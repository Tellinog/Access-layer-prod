#!/usr/bin/env python3
"""Validate the redacted production-continuity evidence bundle.

Exit codes: 0 READY, 2 VALID_BUT_NOT_READY, 1 INVALID/unsafe.
The validator is deliberately read-only and never copies facts to platform manifests.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "operations" / "production-continuity.evidence.yml"
DEFAULT_SCHEMA = ROOT / "schemas" / "production-continuity-evidence.schema.json"

ALLOWED_PRESENCE_KEYS = {
    "APP_BASE_URL", "AUTH_ISSUER", "PUBLIC_BASE_PATH", "POSTGRES_USER",
    "POSTGRES_PASSWORD", "POSTGRES_DB", "DATABASE_URL", "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI", "JWT_PRIVATE_KEY_PEM_PATH",
    "JWT_PRIVATE_KEY_PEM", "JWT_PUBLIC_KEY_ID", "ACCESS_TOKEN_TTL_SECONDS",
    "REFRESH_TOKEN_TTL_SECONDS", "ONE_TIME_CODE_TTL_SECONDS", "ENABLE_REFRESH_TOKENS",
    "SESSION_COOKIE_NAME", "SESSION_SECRET", "TOOL_CLIENT_SECRET_PEPPER",
    "BACKUP_ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "LOG_IP_SALT",
    "SIEM_EXPORT_TOKEN", "BACKUP_API_TOKEN",
}
FORBIDDEN_KEY_PARTS = {
    "access_token", "refresh_token", "authorization_code", "client_secret",
    "database_url", "session_secret", "private_key", "password", "cookie",
    "pepper", "backup_encryption_key", "backup_api_token", "siem_export_token",
}
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s@/]+@", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I),
    re.compile(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_\-]{16,}\b"),
)


@dataclass(frozen=True)
class ValidationReport:
    result: str
    errors: list[str]
    missing_readiness_facts: list[str]

    @property
    def exit_code(self) -> int:
        return 0 if self.result == "READY" else 2 if self.result == "VALID_BUT_NOT_READY" else 1


def _path(parts: tuple[Any, ...]) -> str:
    return ".".join(str(part) for part in parts) or "<root>"


def _find_unsafe(value: Any, parts: tuple[Any, ...] = ()) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized = key_text.lower().replace("-", "_")
            child_path = parts + (key_text,)
            is_presence_key = (
                parts == ("application_continuity", "required_environment_presence")
                and key_text in ALLOWED_PRESENCE_KEYS
            )
            if any(part in normalized for part in FORBIDDEN_KEY_PARTS) and not is_presence_key:
                # Public-key fingerprints are evidence, not private key material.
                if normalized not in {"jwt_public_key_fingerprint_sha256"}:
                    errors.append(f"forbidden secret-bearing field at {_path(child_path)}")
            errors.extend(_find_unsafe(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_find_unsafe(child, parts + (index,)))
    elif isinstance(value, str):
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                errors.append(f"possible secret value at {_path(parts)}")
                break
        parsed = urlsplit(value)
        if parsed.scheme and (parsed.username is not None or parsed.password is not None):
            errors.append(f"URL credentials are forbidden at {_path(parts)}")
    return errors


def _missing_if_false(missing: list[str], condition: bool, path: str) -> None:
    if not condition:
        missing.append(path)


def readiness_gaps(data: dict[str, Any]) -> list[str]:
    """Return facts and approvals needed before the bundle may say READY."""
    missing: list[str] = []
    _missing_if_false(missing, bool(data.get("captured_at")), "captured_at")
    _missing_if_false(missing, bool(data.get("captured_by")), "captured_by")

    coolify = data["coolify"]
    for key in ("server_id", "project_id", "environment_id", "resource_id", "destination_id", "resource_type"):
        _missing_if_false(missing, bool(coolify.get(key)), f"coolify.{key}")
    _missing_if_false(missing, coolify.get("auto_deploy_enabled") is not None, "coolify.auto_deploy_enabled")

    domains = data["domains"]
    for key in ("live_current_origin", "live_current_origin_observed_from", "intended_target_origin"):
        _missing_if_false(missing, bool(domains.get(key)), f"domains.{key}")

    runtime = data["runtime"]
    _missing_if_false(
        missing,
        bool(runtime.get("deployed_revision") or runtime.get("image_digest")),
        "runtime.deployed_revision_or_image_digest",
    )
    for key in ("replica_count", "deployment_strategy", "last_deployed_at"):
        _missing_if_false(missing, runtime.get(key) is not None, f"runtime.{key}")
    expected_services = {
        "app": (8080, "public_via_proxy"),
        "postgres": (5432, "private"),
    }
    for name, (port, exposure) in expected_services.items():
        service = runtime["observed_services"][name]
        _missing_if_false(missing, bool(service.get("service_name")), f"runtime.observed_services.{name}.service_name")
        _missing_if_false(missing, service.get("target_container_port") == port, f"runtime.observed_services.{name}.target_container_port={port}")
        _missing_if_false(missing, service.get("public_host_port_mapping_observed") is True, f"runtime.observed_services.{name}.public_host_port_mapping_observed=true")
        _missing_if_false(missing, service.get("public_host_port") is None, f"runtime.observed_services.{name}.public_host_port=null")
        _missing_if_false(missing, service.get("exposure") == exposure, f"runtime.observed_services.{name}.exposure={exposure}")

    storage = data["storage"]
    for key in ("actual_storage_type", "actual_storage_identifier", "mapping_observed_from", "verified_at", "verified_by"):
        _missing_if_false(missing, bool(storage.get(key)), f"storage.{key}")
    _missing_if_false(missing, storage.get("mapping_verified") is True, "storage.mapping_verified=true")

    backup = data["backup"]
    for key in ("mechanism", "schedule", "retention", "storage_destination_class", "latest_verified_backup_id", "latest_verified_backup_at"):
        _missing_if_false(missing, bool(backup.get(key)), f"backup.{key}")
    restore = backup["restore_test"]
    _missing_if_false(missing, restore.get("status") == "PASSED", "backup.restore_test.status=PASSED")
    _missing_if_false(missing, restore.get("isolated_target") is True, "backup.restore_test.isolated_target=true")
    for key in ("target_identifier", "completed_at", "verified_by", "evidence_reference"):
        _missing_if_false(missing, bool(restore.get(key)), f"backup.restore_test.{key}")

    database = data["database"]
    _missing_if_false(missing, database.get("metadata_collected") is True, "database.metadata_collected=true")
    for key in ("collected_at", "server_version", "database_name", "schema_fingerprint_sha256", "metadata_source"):
        _missing_if_false(missing, bool(database.get(key)), f"database.{key}")
    _missing_if_false(missing, bool(database.get("applied_migration_ids")), "database.applied_migration_ids")

    continuity = data["application_continuity"]
    for key in ("jwks_observed_from", "jwt_public_kid", "jwt_public_key_fingerprint_sha256"):
        _missing_if_false(missing, bool(continuity.get(key)), f"application_continuity.{key}")
    _missing_if_false(missing, continuity.get("environment_presence_verified") is True, "application_continuity.environment_presence_verified=true")
    for key, present in continuity["required_environment_presence"].items():
        _missing_if_false(missing, present is not None, f"application_continuity.required_environment_presence.{key}=observed")

    registry = data["deployment_registry"]
    _missing_if_false(missing, registry.get("record_verified") is True, "deployment_registry.record_verified=true")
    for key in ("registry_identifier", "evidence_reference"):
        _missing_if_false(missing, bool(registry.get(key)), f"deployment_registry.{key}")

    for key, value in data["ownership"].items():
        _missing_if_false(missing, bool(value), f"ownership.{key}")
    for key, value in data["approvals"].items():
        _missing_if_false(missing, value is True, f"approvals.{key}=true")
    return sorted(set(missing))


def validate(evidence_path: Path, schema_path: Path = DEFAULT_SCHEMA) -> ValidationReport:
    try:
        data = yaml.safe_load(evidence_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return ValidationReport("INVALID", [f"unable to load evidence/schema: {type(exc).__name__}"], [])
    if not isinstance(data, dict):
        return ValidationReport("INVALID", ["evidence root must be an object"], [])

    unsafe = sorted(set(_find_unsafe(data)))
    if unsafe:
        return ValidationReport("INVALID", unsafe, [])

    schema_errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(data),
        key=lambda error: list(error.absolute_path),
    )
    if schema_errors:
        # Do not echo values: a malformed operator file could contain a secret.
        errors = [f"schema violation at {_path(tuple(error.absolute_path))} ({error.validator})" for error in schema_errors]
        return ValidationReport("INVALID", errors, [])

    missing = readiness_gaps(data)
    declared_ready = data["status"] == "READY"
    if declared_ready and missing:
        return ValidationReport("INVALID", ["status is READY while required evidence or approvals are missing"], missing)
    if not declared_ready and not missing:
        return ValidationReport("INVALID", ["all readiness facts are present but status is still NOT_READY; operator approval is required"], [])
    if missing:
        return ValidationReport("VALID_BUT_NOT_READY", [], missing)
    return ValidationReport("READY", [], [])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    report = validate(args.evidence.resolve(), args.schema.resolve())
    payload = {
        "result": report.result,
        "evidence": str(args.evidence.resolve()),
        "errors": report.errors,
        "missing_readiness_facts": report.missing_readiness_facts,
        "summary": {"errors": len(report.errors), "missing": len(report.missing_readiness_facts)},
    }
    if args.json_output:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Production continuity evidence: {report.result}")
        for item in report.errors:
            print(f"ERROR: {item}")
        for item in report.missing_readiness_facts:
            print(f"MISSING: {item}")
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

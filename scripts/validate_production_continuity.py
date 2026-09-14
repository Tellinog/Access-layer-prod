#!/usr/bin/env python3
"""Validate redacted production-continuity evidence without changing state.

Exit codes: 0 final READY, 2 valid but not final-ready, 1 invalid/unsafe.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "operations" / "production-continuity.evidence.yml"
DEFAULT_SCHEMA = ROOT / "schemas" / "production-continuity-evidence.schema.json"

SOURCE_ENVIRONMENT_NAMES = (
    "ACCESS_REQUEST_REOPEN_AFTER_DAYS", "ACCESS_TOKEN_TTL_SECONDS", "ADMIN_BOOTSTRAP_EMAILS",
    "APP_BASE_URL", "APP_ENV", "AUDIT_LOG_RAW_IP", "AUDIT_LOG_RETENTION_DAYS", "AUTH_ISSUER",
    "BACKUP_API_TOKEN", "BACKUP_ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "DATABASE_URL",
    "ENABLE_REFRESH_TOKENS", "GOOGLE_ALLOWED_HD", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
    "GOOGLE_OIDC_SCOPE", "GOOGLE_REDIRECT_URI", "JWT_PRIVATE_KEY_PEM", "JWT_PRIVATE_KEY_PEM_PATH",
    "JWT_PUBLIC_KEY_ID", "LEGACY_MICROSOFT_ENABLED", "LEGACY_MICROSOFT_TOOL_SLUGS", "LOG_IP_SALT", "LOG_LEVEL",
    "MICROSOFT_ALLOWED_EMAIL_DOMAINS", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "MICROSOFT_OIDC_SCOPE",
    "MICROSOFT_REDIRECT_URI", "MICROSOFT_TENANT_ID", "OAUTH_CREDENTIAL_SECRET_PEPPER", "OAUTH_P0_ENABLED",
    "OAUTH_SIGNING_KEY_ROOT", "OAUTH_TRANSACTION_PROTECTION_KEY", "ONE_TIME_CODE_TTL_SECONDS", "PORT",
    "POSTGRES_DB", "POSTGRES_PASSWORD", "POSTGRES_USER", "PUBLIC_BASE_PATH",
    "REFRESH_TOKEN_TTL_SECONDS", "RETURN_URL_ALLOWED_SCHEMES", "RUN_MIGRATIONS_ON_START",
    "RUN_SEED_ON_START", "SEED_EXAMPLE_TOOLS", "SESSION_COOKIE_NAME", "SESSION_SECRET",
    "SIEM_EXPORT_ENABLED", "SIEM_EXPORT_ENDPOINT", "SIEM_EXPORT_TOKEN", "TOOL_CLIENT_SECRET_PEPPER",
    "TRUST_PROXY_HOPS",
)
SECRET_CONTINUITY_NAMES = (
    "SESSION_SECRET", "TOOL_CLIENT_SECRET_PEPPER", "OAUTH_CREDENTIAL_SECRET_PEPPER", "BACKUP_ENCRYPTION_KEY",
    "GOOGLE_CLIENT_SECRET", "LOG_IP_SALT", "MICROSOFT_CLIENT_SECRET",
)
REQUIRED_NON_EMPTY_ENVIRONMENT = {
    "APP_ENV", "APP_BASE_URL", "AUTH_ISSUER", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
    "DATABASE_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
    "GOOGLE_ALLOWED_HD", "JWT_PUBLIC_KEY_ID", "SESSION_SECRET", "TOOL_CLIENT_SECRET_PEPPER",
    "BACKUP_ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "LOG_IP_SALT",
}
FORBIDDEN_KEY_PARTS = {
    "access_token", "refresh_token", "authorization_code", "client_secret", "database_url",
    "session_secret", "private_key", "password", "cookie", "pepper", "backup_encryption_key",
    "backup_api_token", "siem_export_token",
}
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s@/]+@", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I),
    re.compile(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_\-]{16,}\b"),
)
HEX_VERIFIER_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$", re.I)


@dataclass(frozen=True)
class ValidationReport:
    result: str
    errors: list[str]
    ready_for_isolated_restore: bool
    missing_for_isolated_restore: list[str]
    ready_for_n_to_n_plus_1: bool
    missing_for_n_to_n_plus_1: list[str]

    @property
    def missing_readiness_facts(self) -> list[str]:
        return self.missing_for_n_to_n_plus_1

    @property
    def exit_code(self) -> int:
        return 0 if self.result == "READY" else 2 if self.result == "VALID_BUT_NOT_READY" else 1


def _invalid(errors: list[str], final_missing: list[str] | None = None) -> ValidationReport:
    missing = final_missing or []
    return ValidationReport("INVALID", errors, False, [], False, missing)


def _path(parts: tuple[Any, ...]) -> str:
    return ".".join(str(part) for part in parts) or "<root>"


def _allowed_sensitive_key(parts: tuple[Any, ...], key: str) -> bool:
    if parts == ("configuration", "environment_state") and key in SOURCE_ENVIRONMENT_NAMES:
        return True
    if parts == ("secret_continuity", "records") and key in SECRET_CONTINUITY_NAMES:
        return True
    # This object has a closed schema containing only reviewed non-secret values.
    if parts == ("configuration", "effective_non_secret_config"):
        return True
    return False


def _find_unsafe(value: Any, parts: tuple[Any, ...] = ()) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized = key_text.lower().replace("-", "_")
            child_path = parts + (key_text,)
            if any(part in normalized for part in FORBIDDEN_KEY_PARTS) and not _allowed_sensitive_key(parts, key_text):
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
        if parts[:2] == ("secret_continuity", "records") and HEX_VERIFIER_RE.fullmatch(value):
            errors.append(f"reusable secret verifier is forbidden at {_path(parts)}")
    return errors


def _require(missing: list[str], condition: bool, path: str) -> None:
    if not condition:
        missing.append(path)


def _common_live_gaps(data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    _require(missing, bool(data.get("captured_at")), "captured_at")
    _require(missing, bool(data.get("captured_by")), "captured_by")

    coolify = data["coolify"]
    for key in ("server_id", "project_id", "environment_id", "resource_id", "destination_id", "resource_type"):
        _require(missing, bool(coolify.get(key)), f"coolify.{key}")
    _require(missing, coolify.get("auto_deploy_enabled") is not None, "coolify.auto_deploy_enabled")

    domains = data["domains"]
    for key in ("live_current_origin", "live_current_origin_observed_from", "intended_target_origin"):
        _require(missing, bool(domains.get(key)), f"domains.{key}")

    runtime = data["runtime"]
    _require(missing, bool(runtime.get("deployed_revision") or runtime.get("image_digest")), "runtime.deployed_revision_or_image_digest")
    for key in ("replica_count", "deployment_strategy", "last_deployed_at"):
        _require(missing, runtime.get(key) is not None, f"runtime.{key}")
    for name, (port, exposure) in {"app": (8080, "public_via_proxy"), "postgres": (5432, "private")}.items():
        service = runtime["observed_services"][name]
        prefix = f"runtime.observed_services.{name}"
        _require(missing, bool(service.get("service_name")), f"{prefix}.service_name")
        _require(missing, service.get("target_container_port") == port, f"{prefix}.target_container_port={port}")
        _require(missing, service.get("public_host_port_mapping_observed") is True, f"{prefix}.public_host_port_mapping_observed=true")
        _require(missing, service.get("public_host_port") is None, f"{prefix}.public_host_port=null")
        _require(missing, service.get("exposure") == exposure, f"{prefix}.exposure={exposure}")

    storage = data["storage"]
    for key in ("actual_storage_type", "actual_storage_identifier", "mapping_observed_from", "verified_at", "verified_by", "evidence_reference"):
        _require(missing, bool(storage.get(key)), f"storage.{key}")
    _require(missing, storage.get("mapping_verified") is True, "storage.mapping_verified=true")

    backup = data["backup"]
    for key in ("mechanism", "schedule", "retention", "storage_destination_class", "latest_verified_backup_id", "latest_verified_backup_at", "evidence_reference"):
        _require(missing, bool(backup.get(key)), f"backup.{key}")

    database = data["database"]
    _require(missing, database.get("metadata_collected") is True, "database.metadata_collected=true")
    for key in ("collected_at", "server_version", "database_name", "schema_fingerprint_sha256", "metadata_source"):
        _require(missing, bool(database.get(key)), f"database.{key}")
    _require(missing, bool(database.get("applied_migration_ids")), "database.applied_migration_ids")

    registry = data["deployment_registry"]
    _require(missing, registry.get("record_verified") is True, "deployment_registry.record_verified=true")
    for key in ("registry_identifier", "evidence_reference"):
        _require(missing, bool(registry.get(key)), f"deployment_registry.{key}")
    for key, value in data["ownership"].items():
        _require(missing, bool(value), f"ownership.{key}")
    return missing


def _jwt_gaps(data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    jwt = data["jwt_signing_material"]
    states = data["configuration"]["environment_state"]
    mode = jwt["source_mode"]
    _require(missing, mode in {"inline_env", "file_path"}, "jwt_signing_material.source_mode")
    public = jwt["public_key"]
    for key in ("jwks_observed_from", "kid", "fingerprint_sha256"):
        _require(missing, bool(public.get(key)), f"jwt_signing_material.public_key.{key}")
    verification = jwt["continuity_verification"]
    _require(missing, verification.get("verified_same_key") is True, "jwt_signing_material.continuity_verification.verified_same_key=true")
    for key in ("verification_method", "verified_by", "verified_at", "evidence_reference"):
        _require(missing, bool(verification.get(key)), f"jwt_signing_material.continuity_verification.{key}")

    if mode == "inline_env":
        _require(missing, states["JWT_PRIVATE_KEY_PEM"] == "PRESENT_NON_EMPTY", "configuration.environment_state.JWT_PRIVATE_KEY_PEM=PRESENT_NON_EMPTY")
    elif mode == "file_path":
        _require(missing, states["JWT_PRIVATE_KEY_PEM"] in {"ABSENT", "PRESENT_EMPTY"}, "configuration.environment_state.JWT_PRIVATE_KEY_PEM=ABSENT_or_PRESENT_EMPTY")
        _require(missing, states["JWT_PRIVATE_KEY_PEM_PATH"] == "PRESENT_NON_EMPTY", "configuration.environment_state.JWT_PRIVATE_KEY_PEM_PATH=PRESENT_NON_EMPTY")
        _require(missing, bool(jwt.get("configured_file_path")), "jwt_signing_material.configured_file_path")
        _require(missing, jwt.get("file_state") == "PRESENT_NON_EMPTY", "jwt_signing_material.file_state=PRESENT_NON_EMPTY")
        persistence = jwt["file_persistence"]
        for key in ("actual_storage_type", "actual_storage_identifier", "mapping_observed_from", "verified_at", "verified_by", "evidence_reference"):
            _require(missing, bool(persistence.get(key)), f"jwt_signing_material.file_persistence.{key}")
        _require(missing, persistence.get("mapping_verified") is True, "jwt_signing_material.file_persistence.mapping_verified=true")
    return missing


def _secret_continuity_gaps(data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for name, record in data["secret_continuity"]["records"].items():
        if name == "MICROSOFT_CLIENT_SECRET" and data["configuration"]["effective_non_secret_config"].get("legacy_microsoft_enabled") is not True:
            continue
        prefix = f"secret_continuity.records.{name}"
        _require(missing, record.get("verified_same_value") is True, f"{prefix}.verified_same_value=true")
        for key in ("verification_method", "verified_by", "verified_at", "evidence_reference"):
            _require(missing, bool(record.get(key)), f"{prefix}.{key}")
    return missing


def _configuration_gaps(data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    configuration = data["configuration"]
    observation = configuration["observation"]
    for key in ("observed_at", "observed_by", "evidence_reference"):
        _require(missing, bool(observation.get(key)), f"configuration.observation.{key}")
    _require(missing, observation.get("runtime_config_validation_observed") is True, "configuration.observation.runtime_config_validation_observed=true")

    states = configuration["environment_state"]
    for name in SOURCE_ENVIRONMENT_NAMES:
        _require(missing, states[name] != "UNOBSERVED", f"configuration.environment_state.{name}=observed")
    for name in REQUIRED_NON_EMPTY_ENVIRONMENT:
        _require(missing, states[name] == "PRESENT_NON_EMPTY", f"configuration.environment_state.{name}=PRESENT_NON_EMPTY")

    effective = configuration["effective_non_secret_config"]
    required_values = (
        "app_env", "public_base_path", "app_base_url", "auth_issuer", "port", "log_level", "postgres_user",
        "postgres_database", "google_client_id", "google_redirect_uri", "jwt_public_key_id",
        "access_token_ttl_seconds", "refresh_token_ttl_seconds", "one_time_code_ttl_seconds",
        "enable_refresh_tokens", "oauth_p0_enabled", "session_cookie_name", "trust_proxy_hops", "audit_log_retention_days",
        "audit_log_raw_ip", "access_request_reopen_after_days", "run_migrations_on_start", "run_seed_on_start",
        "seed_example_tools", "siem_export_enabled", "admin_bootstrap_email_count",
        "legacy_microsoft_enabled",
    )
    for key in required_values:
        _require(missing, effective.get(key) is not None, f"configuration.effective_non_secret_config.{key}")
    for key in ("google_allowed_hd", "google_oidc_scope", "cors_allowed_origins", "return_url_allowed_schemes"):
        _require(missing, bool(effective.get(key)), f"configuration.effective_non_secret_config.{key}")

    if effective.get("legacy_microsoft_enabled") is True:
        for key in ("microsoft_tenant_id", "microsoft_client_id", "microsoft_redirect_uri"):
            _require(missing, bool(effective.get(key)), f"configuration.effective_non_secret_config.{key}")
        for key in ("microsoft_allowed_email_domains", "microsoft_oidc_scope", "legacy_microsoft_tool_slugs"):
            _require(missing, bool(effective.get(key)), f"configuration.effective_non_secret_config.{key}")
        for name in ("MICROSOFT_TENANT_ID", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "MICROSOFT_REDIRECT_URI", "MICROSOFT_ALLOWED_EMAIL_DOMAINS", "LEGACY_MICROSOFT_TOOL_SLUGS"):
            _require(missing, states[name] == "PRESENT_NON_EMPTY", f"configuration.environment_state.{name}=PRESENT_NON_EMPTY")
        _require(missing, {"openid", "email", "profile"}.issubset(set(effective.get("microsoft_oidc_scope", []))), "configuration.effective_non_secret_config.microsoft_oidc_scope includes openid,email,profile")

    _require(missing, effective.get("app_env") == "production", "configuration.effective_non_secret_config.app_env=production")
    _require(missing, effective.get("port") == 8080, "configuration.effective_non_secret_config.port=8080")
    _require(missing, effective.get("access_token_ttl_seconds") == 900, "configuration.effective_non_secret_config.access_token_ttl_seconds=900")
    _require(missing, effective.get("refresh_token_ttl_seconds") == 28800, "configuration.effective_non_secret_config.refresh_token_ttl_seconds=28800")
    _require(missing, effective.get("one_time_code_ttl_seconds") == 60, "configuration.effective_non_secret_config.one_time_code_ttl_seconds=60")
    _require(missing, effective.get("enable_refresh_tokens") is True, "configuration.effective_non_secret_config.enable_refresh_tokens=true")
    _require(missing, effective.get("oauth_p0_enabled") is False, "configuration.effective_non_secret_config.oauth_p0_enabled=false")
    _require(missing, effective.get("session_cookie_name") == "access_layer_admin_session", "configuration.effective_non_secret_config.session_cookie_name=access_layer_admin_session")
    _require(missing, {"openid", "email", "profile"}.issubset(set(effective.get("google_oidc_scope", []))), "configuration.effective_non_secret_config.google_oidc_scope includes openid,email,profile")
    _require(missing, effective.get("jwt_public_key_id") == data["jwt_signing_material"]["public_key"].get("kid"), "configuration.effective_non_secret_config.jwt_public_key_id matches public kid")
    if effective.get("siem_export_enabled") is True:
        _require(missing, bool(effective.get("siem_export_endpoint")), "configuration.effective_non_secret_config.siem_export_endpoint")
        _require(missing, states["SIEM_EXPORT_TOKEN"] == "PRESENT_NON_EMPTY", "configuration.environment_state.SIEM_EXPORT_TOKEN=PRESENT_NON_EMPTY")
    return missing


def isolated_restore_gaps(data: dict[str, Any]) -> list[str]:
    missing = _common_live_gaps(data) + _jwt_gaps(data) + _secret_continuity_gaps(data) + _configuration_gaps(data)
    approvals = data["approvals"]
    for key in (
        "live_topology_verified", "postgres_storage_mapping_verified", "backup_policy_verified",
        "jwt_signing_material_verified", "secret_continuity_verified", "configuration_verified",
        "ready_for_isolated_restore",
    ):
        _require(missing, approvals.get(key) is True, f"approvals.{key}=true")
    return sorted(set(missing))


def n_to_n_plus_one_gaps(data: dict[str, Any]) -> list[str]:
    missing = isolated_restore_gaps(data)
    restore = data["backup"]["restore_test"]
    _require(missing, restore.get("status") == "PASSED", "backup.restore_test.status=PASSED")
    _require(missing, restore.get("isolated_target") is True, "backup.restore_test.isolated_target=true")
    for key in ("target_identifier", "completed_at", "verified_by", "evidence_reference"):
        _require(missing, bool(restore.get(key)), f"backup.restore_test.{key}")
    approvals = data["approvals"]
    _require(missing, approvals.get("restore_test_verified") is True, "approvals.restore_test_verified=true")
    _require(missing, approvals.get("ready_for_n_to_n_plus_1") is True, "approvals.ready_for_n_to_n_plus_1=true")
    return sorted(set(missing))


def readiness_gaps(data: dict[str, Any]) -> list[str]:
    """Backward-compatible alias for the final N→N+1 readiness gaps."""
    return n_to_n_plus_one_gaps(data)


def validate(evidence_path: Path, schema_path: Path = DEFAULT_SCHEMA) -> ValidationReport:
    try:
        data = yaml.safe_load(evidence_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return _invalid([f"unable to load evidence/schema: {type(exc).__name__}"])
    if not isinstance(data, dict):
        return _invalid(["evidence root must be an object"])

    unsafe = sorted(set(_find_unsafe(data)))
    if unsafe:
        return _invalid(unsafe)
    schema_errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(data),
        key=lambda error: list(error.absolute_path),
    )
    if schema_errors:
        errors = [f"schema violation at {_path(tuple(error.absolute_path))} ({error.validator})" for error in schema_errors]
        return _invalid(errors)

    restore_missing = isolated_restore_gaps(data)
    final_missing = n_to_n_plus_one_gaps(data)
    restore_ready = not restore_missing
    final_ready = not final_missing
    declared_ready = data["status"] == "READY"
    if declared_ready and not final_ready:
        return ValidationReport("INVALID", ["status is READY while final N→N+1 evidence or approvals are missing"], restore_ready, restore_missing, False, final_missing)
    if not declared_ready and final_ready:
        return ValidationReport("INVALID", ["final readiness is complete but status is still NOT_READY; explicit operator promotion is required"], True, [], True, [])
    result = "READY" if declared_ready else "VALID_BUT_NOT_READY"
    return ValidationReport(result, [], restore_ready, restore_missing, final_ready, final_missing)


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
        "gates": {
            "ready_for_isolated_restore": report.ready_for_isolated_restore,
            "missing_for_isolated_restore": report.missing_for_isolated_restore,
            "ready_for_n_to_n_plus_1": report.ready_for_n_to_n_plus_1,
            "missing_for_n_to_n_plus_1": report.missing_for_n_to_n_plus_1,
        },
        "missing_readiness_facts": report.missing_readiness_facts,
        "summary": {
            "errors": len(report.errors),
            "missing_for_isolated_restore": len(report.missing_for_isolated_restore),
            "missing_for_n_to_n_plus_1": len(report.missing_for_n_to_n_plus_1),
        },
    }
    if args.json_output:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Production continuity evidence: {report.result}")
        print(f"ready_for_isolated_restore={str(report.ready_for_isolated_restore).lower()}")
        print(f"ready_for_n_to_n_plus_1={str(report.ready_for_n_to_n_plus_1).lower()}")
        for item in report.errors:
            print(f"ERROR: {item}")
        for item in report.missing_for_n_to_n_plus_1:
            print(f"MISSING: {item}")
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

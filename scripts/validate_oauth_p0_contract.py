#!/usr/bin/env python3
"""Validate the frozen OAuth P0 contract without exercising runtime behavior."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATHS = {
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource/v1",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/revoke",
    "/oauth/introspect",
    "/oauth/jwks",
}
FORBIDDEN_P0_MARKERS = {
    "/.well-known/openid-configuration",
    "/oauth/userinfo",
    "client_credentials",
    "private_key_jwt",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "client_id_metadata_document_supported",
}
CAPABILITY_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}$"
)


def load_json(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def load_yaml(path: str) -> Any:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def schema_errors(instance: Any, schema: dict[str, Any], registry: Registry | None = None) -> list[str]:
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
        registry=registry or Registry(),
    )
    return [failure.message for failure in validator.iter_errors(instance)]


def iter_nodes(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_nodes(child)


def resolve_json_pointer(document: Any, reference: str) -> Any:
    current = document
    for segment in reference.removeprefix("#/").split("/"):
        current = current[segment.replace("~1", "/").replace("~0", "~")]
    return current


def validate() -> list[str]:
    errors: list[str] = []
    spec = load_yaml("specs/oauth-p0.v1.yml")
    openapi = load_yaml("schemas/access-layer-oauth-v1.openapi.yaml")
    metadata = load_json("examples/oauth/authorization-server-metadata.expected.json")

    if spec.get("status") != "contract_frozen_not_implemented" or spec.get("runtime_enabled") is not False:
        errors.append("OAuth P0 machine profile must remain frozen and runtime-disabled")
    if spec.get("oauth_2_1_alignment", {}).get("final_rfc_claimed") is not False:
        errors.append("OAuth 2.1 must not be represented as a final RFC")
    if set(openapi.get("paths", {})) != EXPECTED_PATHS:
        errors.append("target OpenAPI path set differs from the frozen P0 surface")

    serialized_openapi = json.dumps(openapi, sort_keys=True)
    serialized_metadata = json.dumps(metadata, sort_keys=True)
    for marker in sorted(FORBIDDEN_P0_MARKERS):
        if marker in serialized_openapi or marker in serialized_metadata:
            errors.append(f"P1 marker is advertised by P0: {marker}")

    metadata_schema = load_json("schemas/oauth-authorization-server-metadata.schema.json")
    errors.extend(f"metadata: {error}" for error in schema_errors(metadata, metadata_schema))

    openapi_schemas = openapi["components"]["schemas"]
    openapi_examples = (
        ("examples/oauth/token.response.json", "TokenResponse"),
        ("examples/oauth/introspection.active.json", "IntrospectionResponse"),
        ("examples/oauth/introspection.inactive.json", "IntrospectionResponse"),
        ("examples/oauth/error.response.json", "OAuthError"),
    )
    for example_path, schema_name in openapi_examples:
        failures = schema_errors(load_json(example_path), openapi_schemas[schema_name])
        errors.extend(f"{example_path}: {failure}" for failure in failures)

    examples_and_schemas = (
        ("examples/oauth/client-registration.confidential.json", "schemas/oauth-client-registration.schema.json"),
        ("examples/oauth/resource-registration.json", "schemas/oauth-resource-registration.schema.json"),
        ("examples/oauth/oauth-protected-resource-metadata.json", "schemas/oauth-protected-resource-metadata.schema.json"),
        ("examples/oauth/access-token.claims.json", "schemas/oauth-access-token-claims.schema.json"),
    )
    for example_path, schema_path in examples_and_schemas:
        failures = schema_errors(load_json(example_path), load_json(schema_path))
        errors.extend(f"{example_path}: {failure}" for failure in failures)

    claims_schema = load_json("schemas/oauth-access-token-claims.schema.json")
    claims_resource = Resource.from_contents(claims_schema)
    registry = Registry().with_resource(claims_schema["$id"], claims_resource)
    token_profile = load_json("examples/oauth/access-token.profile.json")
    token_schema = load_json("schemas/oauth-token-profile.schema.json")
    errors.extend(f"token profile: {error}" for error in schema_errors(token_profile, token_schema, registry))
    if token_profile.get("header", {}).get("typ") != "at+jwt":
        errors.append("RFC 9068 token profile must require typ=at+jwt")

    claims = token_profile.get("claims", {})
    if claims.get("sub") != load_json("examples/oauth/access-token.claims.json").get("sub"):
        errors.append("token fixtures disagree on the stable Google sub")
    for pii_claim in ("email", "hd", "display_name", "picture_url", "role", "permissions", "act"):
        if pii_claim in claims:
            errors.append(f"P0 OAuth access-token fixture contains forbidden/deferred claim: {pii_claim}")
    for scope in str(claims.get("scope", "")).split():
        if not CAPABILITY_PATTERN.fullmatch(scope):
            errors.append(f"OAuth scope is not canonical project:domain:action: {scope}")

    auth_response = load_json("examples/oauth/authorization-response.success.json")
    if set(auth_response) != {"code", "state", "iss"} or auth_response.get("iss") != spec.get("issuer"):
        errors.append("authorization response fixture must contain exactly code, state and RFC 9207 iss")

    client_schema = load_json("schemas/oauth-client-registration.schema.json")
    invalid_client = load_json("examples/oauth/client-registration.confidential.json")
    invalid_client["redirect_uris"] = ["https://*.invalid/callback"]
    if not schema_errors(invalid_client, client_schema):
        errors.append("client schema accepts a wildcard redirect URI")

    operation_ids: list[str] = []
    for node in iter_nodes(openapi):
        reference = node.get("$ref") if isinstance(node, dict) else None
        if isinstance(reference, str) and reference.startswith("#/"):
            try:
                resolve_json_pointer(openapi, reference)
            except (KeyError, TypeError):
                errors.append(f"unresolved OpenAPI component reference: {reference}")
        operation_id = node.get("operationId") if isinstance(node, dict) else None
        if isinstance(operation_id, str):
            operation_ids.append(operation_id)
    if len(operation_ids) != len(set(operation_ids)):
        errors.append("target OpenAPI operationId values are not unique")

    fixture_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "examples/oauth").glob("*.json"))
    )
    unsafe_patterns = {
        "email address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "private key": r"BEGIN (?:RSA |EC |)PRIVATE KEY",
        "serialized JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "legacy tool secret": r"tls_[A-Za-z0-9_-]{8,}",
        "legacy refresh token": r"rt_[A-Za-z0-9_-]{8,}",
    }
    for label, pattern in unsafe_patterns.items():
        if re.search(pattern, fixture_text):
            errors.append(f"OAuth fixtures contain a real-looking {label}")

    runtime_and_migrations = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in ("src/app.ts", "migrations/001_initial.sql", "migrations/002_audit_tool_delete_fk.sql")
    )
    if re.search(r"/oauth/(?:authorize|token|revoke|introspect)|CREATE TABLE(?: IF NOT EXISTS)? oauth_", runtime_and_migrations, re.I):
        errors.append("OAuth runtime handler or migration exists during the contract-only step")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit a JSON result.")
    args = parser.parse_args()
    errors = validate()
    result = {"result": "PASS" if not errors else "FAIL", "errors": errors, "checks": 12}
    if args.json:
        print(json.dumps(result, indent=2))
    elif errors:
        print("OAuth P0 contract validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("OAuth P0 contract validation passed (12 check groups).")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

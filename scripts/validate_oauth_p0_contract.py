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
REQUEST_CONTEXT_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9-]+(?::[a-z][a-z0-9-]+){1,}$"
PKCE_VERIFIER_PATTERN = r"^[A-Za-z0-9._~-]{43,128}$"
PKCE_S256_CHALLENGE_PATTERN = r"^[A-Za-z0-9_-]{43}$"
LEGACY_TOOL_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
LEGACY_PERMISSION_KEY_PATTERN = r"^[a-z0-9-]+(?::[a-z0-9-]+)+$"


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


def resource_scope_mapping_errors(resource: dict[str, Any]) -> list[str]:
    """Validate exact one-to-one declared-scope coverage beyond JSON Schema."""
    declared_scopes = resource.get("scopes", [])
    mappings = resource.get("scope_entitlement_mappings", [])
    mapping_scopes = [mapping.get("scope") for mapping in mappings if isinstance(mapping, dict)]
    errors: list[str] = []
    if len(mapping_scopes) != len(set(mapping_scopes)):
        errors.append("resource scope entitlement mappings contain a duplicate scope")
    missing = sorted(set(declared_scopes) - set(mapping_scopes))
    extra = sorted(set(mapping_scopes) - set(declared_scopes))
    if missing:
        errors.append(f"resource scope entitlement mappings are missing declared scopes: {', '.join(missing)}")
    if extra:
        errors.append(f"resource scope entitlement mappings contain undeclared scopes: {', '.join(extra)}")
    if len(mappings) != len(declared_scopes):
        errors.append("resource scope entitlement mappings must contain exactly one entry per declared scope")
    return errors


def validate() -> list[str]:
    errors: list[str] = []
    spec = load_yaml("specs/oauth-p0.v1.yml")
    openapi = load_yaml("schemas/access-layer-oauth-v1.openapi.yaml")
    metadata = load_json("examples/oauth/authorization-server-metadata.expected.json")

    validation_spec = load_yaml("specs/validation.v1.yml")
    legacy_validation = validation_spec.get("validation", {})
    if legacy_validation.get("tool_slug", {}).get("regex") != LEGACY_TOOL_SLUG_PATTERN:
        errors.append("legacy tool-slug machine grammar differs from the frozen runtime contract")
    if legacy_validation.get("permission_key", {}).get("regex") != LEGACY_PERMISSION_KEY_PATTERN:
        errors.append("legacy permission-key machine grammar differs from the frozen runtime contract")
    runtime_validation = (ROOT / "src/validation.ts").read_text(encoding="utf-8")
    if "TOOL_SLUG_REGEX = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/" not in runtime_validation:
        errors.append("runtime legacy tool-slug grammar no longer matches the frozen machine contract")
    if "PERMISSION_KEY_REGEX = /^[a-z0-9-]+(?::[a-z0-9-]+)+$/" not in runtime_validation:
        errors.append("runtime legacy permission-key grammar no longer matches the frozen machine contract")

    if spec.get("status") != "contract_frozen_not_implemented" or spec.get("runtime_enabled") is not False:
        errors.append("OAuth P0 machine profile must remain frozen and runtime-disabled")
    if spec.get("oauth_2_1_alignment", {}).get("final_rfc_claimed") is not False:
        errors.append("OAuth 2.1 must not be represented as a final RFC")
    if set(openapi.get("paths", {})) != EXPECTED_PATHS:
        errors.append("target OpenAPI path set differs from the frozen P0 surface")

    request_context_schema = load_json("schemas/request-context.schema.json")
    if request_context_schema.get("$id") != "https://platform.unguess-internal.net/schemas/request-context.schema.json":
        errors.append("shared RequestContext v1 schema identity changed")
    request_context_properties = request_context_schema.get("properties", {})
    request_context_patterns = (
        request_context_properties.get("capability_id", {}).get("pattern"),
        request_context_properties.get("scopes", {}).get("items", {}).get("pattern"),
    )
    if request_context_patterns != (REQUEST_CONTEXT_IDENTIFIER_PATTERN, REQUEST_CONTEXT_IDENTIFIER_PATTERN):
        errors.append("shared RequestContext v1 capability/scopes grammar drifted from the canonical hierarchy")
    two_segment_context = {
        "auth_profile": "unguess-oauth-oidc-v1",
        "principal_type": "human",
        "principal_id": "synthetic-subject",
        "project_slug": "alpha",
        "resource_id": "https://resource.invalid/api",
        "capability_id": "alpha:read",
        "permissions": ["alpha:read"],
        "scopes": ["alpha:read"],
        "invocation_channel": "api",
        "correlation_id": "corr-0001",
        "environment": "test",
        "request_started_at": "2026-08-26T00:00:00Z",
    }
    if schema_errors(two_segment_context, request_context_schema):
        errors.append("shared RequestContext v1 rejects a canonical two-segment identifier")

    pkce = spec.get("authorization_code", {}).get("pkce", {})
    if pkce.get("code_verifier_pattern") != PKCE_VERIFIER_PATTERN:
        errors.append("machine profile does not freeze the RFC 7636 code_verifier grammar")
    if pkce.get("s256_code_challenge_pattern") != PKCE_S256_CHALLENGE_PATTERN:
        errors.append("machine profile does not freeze the exact S256 code_challenge grammar")
    if pkce.get("supported_methods") != ["S256"] or pkce.get("plain_forbidden") is not True:
        errors.append("P0 PKCE must advertise only S256 and forbid plain")

    authorize_parameters = {
        parameter.get("name"): parameter
        for parameter in openapi.get("paths", {}).get("/oauth/authorize", {}).get("get", {}).get("parameters", [])
    }
    if authorize_parameters.get("code_challenge", {}).get("schema", {}).get("pattern") != PKCE_S256_CHALLENGE_PATTERN:
        errors.append("target OpenAPI does not enforce the exact S256 code_challenge grammar")
    authorization_request = load_json("examples/oauth/authorization.request.json")
    expected_authorization_parameters = set(spec.get("authorization_code", {}).get("request_parameters_required", []))
    if set(authorization_request) != expected_authorization_parameters:
        errors.append("authorization request fixture differs from the required P0 parameter set")
    for parameter_name, parameter_value in authorization_request.items():
        parameter_schema = authorize_parameters.get(parameter_name, {}).get("schema", {})
        errors.extend(
            f"authorization request {parameter_name}: {error}"
            for error in schema_errors(parameter_value, parameter_schema)
        )
    openapi_schemas = openapi["components"]["schemas"]
    if openapi_schemas.get("AuthorizationCodeTokenRequest", {}).get("properties", {}).get("code_verifier", {}).get("pattern") != PKCE_VERIFIER_PATTERN:
        errors.append("target OpenAPI does not enforce the RFC 7636 code_verifier grammar")

    serialized_openapi = json.dumps(openapi, sort_keys=True)
    serialized_metadata = json.dumps(metadata, sort_keys=True)
    for marker in sorted(FORBIDDEN_P0_MARKERS):
        if marker in serialized_openapi or marker in serialized_metadata:
            errors.append(f"P1 marker is advertised by P0: {marker}")

    metadata_schema = load_json("schemas/oauth-authorization-server-metadata.schema.json")
    errors.extend(f"metadata: {error}" for error in schema_errors(metadata, metadata_schema))

    openapi_examples = (
        ("examples/oauth/authorization-code-token.request.json", "AuthorizationCodeTokenRequest"),
        ("examples/oauth/token.response.json", "TokenResponse"),
        ("examples/oauth/introspection.access-token.request.json", "IntrospectionRequest"),
        ("examples/oauth/introspection.active.json", "IntrospectionResponse"),
        ("examples/oauth/introspection.inactive.json", "IntrospectionResponse"),
        ("examples/oauth/introspection.nondisclosable-refresh.inactive.json", "IntrospectionResponse"),
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

    resource_schema = load_json("schemas/oauth-resource-registration.schema.json")
    resource_properties = resource_schema.get("properties", {})
    resource_slug_pattern = (
        resource_properties.get("entitlement_binding", {})
        .get("properties", {})
        .get("legacy_tool_slug", {})
        .get("pattern")
    )
    mapping_permission_pattern = (
        resource_properties.get("scope_entitlement_mappings", {})
        .get("items", {})
        .get("properties", {})
        .get("legacy_permission_key", {})
        .get("pattern")
    )
    if resource_slug_pattern != LEGACY_TOOL_SLUG_PATTERN:
        errors.append("OAuth resource schema legacy-tool bridge grammar differs from runtime")
    if mapping_permission_pattern != LEGACY_PERMISSION_KEY_PATTERN:
        errors.append("OAuth resource schema legacy-permission mapping grammar differs from runtime")
    resource_registration = load_json("examples/oauth/resource-registration.json")
    errors.extend(resource_scope_mapping_errors(resource_registration))
    resource_without_binding = load_json("examples/oauth/resource-registration.json")
    resource_without_binding.pop("entitlement_binding")
    if not schema_errors(resource_without_binding, resource_schema):
        errors.append("P0 resource schema accepts a resource without its mandatory legacy-tool binding")
    registration = spec.get("registration", {})
    if registration.get("p0_resource_entitlement_binding") != "exactly_one_legacy_tool":
        errors.append("machine profile does not require exactly one P0 legacy-tool entitlement binding")
    if registration.get("client_and_resource_identity_separate") is not True:
        errors.append("machine profile conflates OAuth client and resource identity")
    if registration.get("native_oauth_entitlement_domains") != "deferred_beyond_p0":
        errors.append("native OAuth entitlement domains are not explicitly deferred beyond P0")
    if registration.get("legacy_tool_slug_pattern") != LEGACY_TOOL_SLUG_PATTERN:
        errors.append("OAuth resource binding does not freeze the exact legacy tool-slug grammar")
    if registration.get("scope_entitlement_mappings") != "exactly_one_explicit_legacy_permission_per_resource_scope":
        errors.append("machine profile does not require explicit per-resource-scope entitlement mappings")
    mapping_contract = spec.get("scope", {}).get("entitlement_mapping", {})
    if mapping_contract.get("legacy_permission_pattern") != LEGACY_PERMISSION_KEY_PATTERN:
        errors.append("OAuth entitlement mapping does not freeze the exact legacy permission grammar")
    if mapping_contract.get("exact_declared_scope_coverage") != "required":
        errors.append("OAuth entitlement mapping does not require exact declared-scope coverage")
    if mapping_contract.get("inferred_prefix_segment_or_alias_rewriting") != "forbidden":
        errors.append("OAuth entitlement mapping permits inferred rewriting")
    if mapping_contract.get("mapped_permission_registered_for_bound_legacy_tool") != "required":
        errors.append("OAuth entitlement mapping does not require a permission registered for the bound tool")
    if mapping_contract.get("missing_stale_unknown_or_ungranted_mapping") != "invalid_scope_and_deny":
        errors.append("OAuth entitlement mapping is not fail-closed")

    introspection = spec.get("introspection", {})
    introspection_auth = introspection.get("authentication", {})
    if introspection_auth.get("method") != "client_secret_basic":
        errors.append("P0 introspection does not freeze client_secret_basic")
    if introspection_auth.get("credential_owner") != "oauth_resource" or introspection_auth.get("credential_model") != "oauth_resource_credentials":
        errors.append("P0 introspection credentials are not owned by the OAuth resource model")
    if introspection_auth.get("oauth_client_credential_reused") is not False or introspection_auth.get("legacy_tool_client_reused") is not False:
        errors.append("P0 introspection credential contract conflates client, resource or legacy tool identities")
    required_resource_credential_fields = {
        "resource_id",
        "credential_id",
        "secret_hash",
        "status",
        "created_at",
        "activated_at",
        "rotated_at",
        "expires_at",
        "retired_at",
        "rotation_parent_id",
    }
    if set(introspection.get("credential_lifecycle_fields", [])) != required_resource_credential_fields:
        errors.append("P0 resource credential model lacks the frozen ownership, secret-hash or lifecycle fields")
    if introspection.get("active_disclosure_audience_rule") != "exact_token_aud_equals_authenticated_credential_resource":
        errors.append("P0 introspection active disclosure is not bound to the credential resource's exact audience")
    if introspection.get("audience_mismatch_response") != "active_false_only":
        errors.append("P0 introspection audience mismatch does not return active=false only")
    if introspection.get("token_class_disclosed_active") != "access_token_only":
        errors.append("P0 introspection active disclosure is not limited to access tokens")
    if introspection.get("refresh_token_active_disclosure") != "forbidden_return_active_false":
        errors.append("P0 introspection does not force refresh tokens to active=false")
    introspection_request = openapi_schemas.get("IntrospectionRequest", {})
    if not schema_errors({"token": "synthetic", "token_type_hint": "refresh_token"}, introspection_request):
        errors.append("target OpenAPI accepts a refresh_token introspection hint")
    introspection_response = openapi_schemas.get("IntrospectionResponse", {})
    if schema_errors({"active": False}, introspection_response):
        errors.append("target OpenAPI rejects the exact inactive introspection response")
    if not schema_errors({"active": False, "reason": "hidden"}, introspection_response):
        errors.append("target OpenAPI permits inactive introspection reason leakage")
    introspection_security = openapi.get("components", {}).get("securitySchemes", {}).get("introspectionClientBasic", {})
    if introspection_security.get("x-credential-owner") != "oauth_resource" or introspection_security.get("x-credential-model") != "oauth_resource_credentials":
        errors.append("target OpenAPI introspection credential ownership differs from the machine profile")
    if introspection_security.get("x-active-audience-match") != "exact":
        errors.append("target OpenAPI introspection credential lacks exact-audience disclosure restriction")

    upstream = spec.get("upstream_identity", {})
    if upstream.get("callback_path") != "/oauth/upstream/google/callback":
        errors.append("machine profile does not freeze the separate Google upstream callback")
    if upstream.get("legacy_callback_reused") is not False or upstream.get("advertised_as_oauth_protocol_endpoint") is not False:
        errors.append("Google upstream callback must remain separate and non-advertised")
    if upstream.get("runtime_implemented") is not False:
        errors.append("Google upstream callback is incorrectly marked implemented")
    downstream_state = spec.get("authorization_code", {}).get("downstream_client_state", {})
    if downstream_state.get("response_round_trip") != "exact_original_value":
        errors.append("machine profile does not preserve exact downstream client state")
    if downstream_state.get("storage") != "short_lived_reversible_protected":
        errors.append("downstream client state is not assigned reversible protected storage")
    if downstream_state.get("logging") != "forbidden":
        errors.append("machine profile does not forbid downstream client-state logging")

    gates = spec.get("development_and_release_gates", {})
    if gates.get("step_3_local_dark_development_after_step_2_approval") != "allowed":
        errors.append("machine profile blocks approved generic Step 3 local/dark development")
    if gates.get("oauth_globally_disabled_by_default") is not True:
        errors.append("machine profile does not keep OAuth globally disabled by default")
    if gates.get("pilot_registration_required_before_generic_step_3_implementation") is not False:
        errors.append("machine profile incorrectly requires pilot registration before generic Step 3 implementation")
    if gates.get("pilot_registration_required_before_enable_or_production_registration") is not True:
        errors.append("machine profile does not require pilot registration before enablement/production registration")
    expected_release_gates = {
        "coolify_changes_pending_review",
        "verified_backup_restore",
        "destination_identity",
        "central_registry",
        "named_ownership",
        "deployed_revision_or_image_identity",
        "secret_and_key_continuity",
        "later_n_to_n_plus_1_gates",
    }
    if set(gates.get("production_deploy_or_enable_blocked_until", [])) != expected_release_gates:
        errors.append("machine profile production release gates differ from the frozen Step 2 decision")

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
    if re.search(r"/oauth/|CREATE TABLE(?: IF NOT EXISTS)? oauth_", runtime_and_migrations, re.I):
        errors.append("OAuth runtime handler or migration exists during the contract-only step")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit a JSON result.")
    args = parser.parse_args()
    errors = validate()
    result = {"result": "PASS" if not errors else "FAIL", "errors": errors, "checks": 24}
    if args.json:
        print(json.dumps(result, indent=2))
    elif errors:
        print("OAuth P0 contract validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("OAuth P0 contract validation passed (24 check groups).")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

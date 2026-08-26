from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_oauth_p0_contract", ROOT / "scripts/validate_oauth_p0_contract.py"
)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


class OAuthP0ContractTests(unittest.TestCase):
    def test_contract_is_internally_consistent(self) -> None:
        self.assertEqual([], validator.validate())

    def test_scope_grammar_is_exactly_project_domain_action(self) -> None:
        self.assertIsNotNone(validator.CAPABILITY_PATTERN.fullmatch("project:domain:action"))
        self.assertIsNone(validator.CAPABILITY_PATTERN.fullmatch("project:read"))
        self.assertIsNone(validator.CAPABILITY_PATTERN.fullmatch("project:domain:action:extra"))

    def test_shared_request_context_v1_keeps_hierarchical_identifier_grammar(self) -> None:
        schema = validator.load_json("schemas/request-context.schema.json")
        self.assertEqual(
            "https://platform.unguess-internal.net/schemas/request-context.schema.json",
            schema["$id"],
        )
        self.assertEqual(
            validator.REQUEST_CONTEXT_IDENTIFIER_PATTERN,
            schema["properties"]["capability_id"]["pattern"],
        )
        self.assertEqual(
            validator.REQUEST_CONTEXT_IDENTIFIER_PATTERN,
            schema["properties"]["scopes"]["items"]["pattern"],
        )
        context = {
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
        self.assertEqual([], validator.schema_errors(context, schema))
        context["capability_id"] = "alpha"
        self.assertTrue(validator.schema_errors(context, schema))

    def test_pkce_verifier_and_s256_challenge_grammars(self) -> None:
        openapi = validator.load_yaml("schemas/access-layer-oauth-v1.openapi.yaml")
        verifier_schema = openapi["components"]["schemas"]["AuthorizationCodeTokenRequest"]["properties"]["code_verifier"]
        authorize_parameters = {
            parameter["name"]: parameter["schema"]
            for parameter in openapi["paths"]["/oauth/authorize"]["get"]["parameters"]
        }
        challenge_schema = authorize_parameters["code_challenge"]

        for value in ("A" * 43, "A" * 128, "A._~-" + "b" * 123):
            self.assertEqual([], validator.schema_errors(value, verifier_schema), value)
        for value in ("A" * 42, "A" * 129, " " * 43, "A" * 42 + "=", "A" * 42 + "+"):
            self.assertTrue(validator.schema_errors(value, verifier_schema), repr(value))

        for value in ("A" * 43, "a-_" + "B" * 40):
            self.assertEqual([], validator.schema_errors(value, challenge_schema), value)
        for value in ("A" * 42, "A" * 44, " " * 43, "A" * 42 + "=", "A" * 42 + "."):
            self.assertTrue(validator.schema_errors(value, challenge_schema), repr(value))

        pkce = validator.load_yaml("specs/oauth-p0.v1.yml")["authorization_code"]["pkce"]
        self.assertEqual(["S256"], pkce["supported_methods"])
        self.assertTrue(pkce["plain_forbidden"])

    def test_wildcard_redirect_is_schema_invalid(self) -> None:
        schema = validator.load_json("schemas/oauth-client-registration.schema.json")
        client = copy.deepcopy(validator.load_json("examples/oauth/client-registration.confidential.json"))
        client["redirect_uris"] = ["https://*.invalid/callback"]
        self.assertTrue(validator.schema_errors(client, schema))

    def test_p0_resource_requires_one_legacy_tool_entitlement_binding(self) -> None:
        schema = validator.load_json("schemas/oauth-resource-registration.schema.json")
        resource = validator.load_json("examples/oauth/resource-registration.json")
        self.assertEqual([], validator.schema_errors(resource, schema))
        resource.pop("entitlement_binding")
        self.assertTrue(validator.schema_errors(resource, schema))
        registration = validator.load_yaml("specs/oauth-p0.v1.yml")["registration"]
        self.assertEqual("exactly_one_legacy_tool", registration["p0_resource_entitlement_binding"])
        self.assertTrue(registration["client_and_resource_identity_separate"])
        self.assertEqual("deferred_beyond_p0", registration["native_oauth_entitlement_domains"])

    def test_introspection_discloses_only_access_tokens_as_active(self) -> None:
        openapi = validator.load_yaml("schemas/access-layer-oauth-v1.openapi.yaml")
        request_schema = openapi["components"]["schemas"]["IntrospectionRequest"]
        response_schema = openapi["components"]["schemas"]["IntrospectionResponse"]
        self.assertEqual([], validator.schema_errors({"token": "synthetic", "token_type_hint": "access_token"}, request_schema))
        self.assertTrue(validator.schema_errors({"token": "synthetic", "token_type_hint": "refresh_token"}, request_schema))
        self.assertEqual([], validator.schema_errors({"active": False}, response_schema))
        self.assertTrue(validator.schema_errors({"active": False, "reason": "revoked"}, response_schema))
        self.assertEqual(
            [],
            validator.schema_errors(validator.load_json("examples/oauth/introspection.active.json"), response_schema),
        )
        contract = validator.load_yaml("specs/oauth-p0.v1.yml")["introspection"]
        self.assertEqual("access_token_only", contract["token_class_disclosed_active"])
        self.assertEqual("forbidden_return_active_false", contract["refresh_token_active_disclosure"])

    def test_google_upstream_callback_is_separate_unadvertised_and_not_implemented(self) -> None:
        spec = validator.load_yaml("specs/oauth-p0.v1.yml")
        upstream = spec["upstream_identity"]
        self.assertEqual("/oauth/upstream/google/callback", upstream["callback_path"])
        self.assertFalse(upstream["legacy_callback_reused"])
        self.assertFalse(upstream["advertised_as_oauth_protocol_endpoint"])
        self.assertFalse(upstream["runtime_implemented"])
        openapi = validator.load_yaml("schemas/access-layer-oauth-v1.openapi.yaml")
        self.assertNotIn(upstream["callback_path"], openapi["paths"])
        self.assertNotIn(upstream["callback_path"], (ROOT / "src" / "app.ts").read_text(encoding="utf-8"))

    def test_downstream_client_state_survives_in_reversible_protected_storage(self) -> None:
        state = validator.load_yaml("specs/oauth-p0.v1.yml")["authorization_code"]["downstream_client_state"]
        self.assertEqual("exact_original_value", state["response_round_trip"])
        self.assertEqual("short_lived_reversible_protected", state["storage"])
        self.assertEqual("allowed", state["optional_lookup_hash"])
        self.assertEqual("forbidden", state["logging"])

    def test_metadata_advertises_only_p0(self) -> None:
        metadata = validator.load_json("examples/oauth/authorization-server-metadata.expected.json")
        self.assertEqual(["authorization_code", "refresh_token"], metadata["grant_types_supported"])
        self.assertEqual(["S256"], metadata["code_challenge_methods_supported"])
        self.assertTrue(metadata["authorization_response_iss_parameter_supported"])


if __name__ == "__main__":
    unittest.main()

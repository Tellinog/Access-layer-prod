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

    def test_legacy_tool_slug_bridge_uses_exact_runtime_grammar(self) -> None:
        schema = validator.load_json("schemas/oauth-resource-registration.schema.json")
        base = validator.load_json("examples/oauth/resource-registration.json")
        slug_schema = schema["properties"]["entitlement_binding"]["properties"]["legacy_tool_slug"]
        self.assertEqual(validator.LEGACY_TOOL_SLUG_PATTERN, slug_schema["pattern"])
        for slug in ("1ab", "a" * 64):
            resource = copy.deepcopy(base)
            resource["entitlement_binding"]["legacy_tool_slug"] = slug
            self.assertEqual([], validator.schema_errors(resource, schema), slug)
        for slug in ("ab", "abc-"):
            resource = copy.deepcopy(base)
            resource["entitlement_binding"]["legacy_tool_slug"] = slug
            self.assertTrue(validator.schema_errors(resource, schema), slug)

    def test_legacy_permission_machine_spec_matches_runtime_hierarchy(self) -> None:
        pattern = validator.load_yaml("specs/validation.v1.yml")["validation"]["permission_key"]["regex"]
        self.assertEqual(validator.LEGACY_PERMISSION_KEY_PATTERN, pattern)
        compiled = validator.re.compile(pattern)
        for permission in ("crm:read", "admin:tools:read", "petyr:read:all"):
            self.assertIsNotNone(compiled.fullmatch(permission), permission)
        self.assertIsNone(compiled.fullmatch("read"))

    def test_scope_entitlement_mappings_cover_declared_scopes_exactly(self) -> None:
        schema = validator.load_json("schemas/oauth-resource-registration.schema.json")
        resource = validator.load_json("examples/oauth/resource-registration.json")
        self.assertEqual([], validator.schema_errors(resource, schema))
        self.assertEqual([], validator.resource_scope_mapping_errors(resource))

        missing = copy.deepcopy(resource)
        missing["scope_entitlement_mappings"].pop()
        self.assertTrue(validator.resource_scope_mapping_errors(missing))

        extra = copy.deepcopy(resource)
        extra["scope_entitlement_mappings"].append(
            {"scope": "example-project:records:delete", "legacy_permission_key": "records:delete"}
        )
        self.assertTrue(validator.resource_scope_mapping_errors(extra))

        duplicate = copy.deepcopy(resource)
        duplicate["scope_entitlement_mappings"][1]["scope"] = duplicate["scope_entitlement_mappings"][0]["scope"]
        self.assertTrue(validator.resource_scope_mapping_errors(duplicate))

        invalid_permission = copy.deepcopy(resource)
        invalid_permission["scope_entitlement_mappings"][0]["legacy_permission_key"] = "read"
        self.assertTrue(validator.schema_errors(invalid_permission, schema))

        contract = validator.load_yaml("specs/oauth-p0.v1.yml")["scope"]["entitlement_mapping"]
        self.assertEqual("forbidden", contract["inferred_prefix_segment_or_alias_rewriting"])
        self.assertEqual("required", contract["mapped_permission_registered_for_bound_legacy_tool"])
        self.assertEqual("invalid_scope_and_deny", contract["missing_stale_unknown_or_ungranted_mapping"])

    def test_introspection_discloses_only_access_tokens_as_active(self) -> None:
        openapi = validator.load_yaml("schemas/access-layer-oauth-v1.openapi.yaml")
        revocation_schema = openapi["components"]["schemas"]["RevocationRequest"]
        request_schema = openapi["components"]["schemas"]["IntrospectionRequest"]
        response_schema = openapi["components"]["schemas"]["IntrospectionResponse"]
        self.assertEqual([], validator.schema_errors({"token": "synthetic", "token_type_hint": "access_token"}, request_schema))
        self.assertEqual([], validator.schema_errors({"token": "synthetic", "token_type_hint": "refresh_token"}, request_schema))
        self.assertEqual([], validator.schema_errors({"token": "synthetic", "token_type_hint": "unknown_type"}, request_schema))
        for hint in ["access_token", "refresh_token", "unknown_type"]:
            self.assertEqual([], validator.schema_errors({"token": "synthetic", "token_type_hint": hint}, revocation_schema))
        self.assertEqual([], validator.schema_errors({"active": False}, response_schema))
        self.assertTrue(validator.schema_errors({"active": False, "reason": "revoked"}, response_schema))
        self.assertEqual(
            [],
            validator.schema_errors(validator.load_json("examples/oauth/introspection.active.json"), response_schema),
        )
        contract = validator.load_yaml("specs/oauth-p0.v1.yml")["introspection"]
        self.assertEqual("access_token_only", contract["token_class_disclosed_active"])
        self.assertEqual("forbidden_return_active_false", contract["refresh_token_active_disclosure"])
        self.assertEqual(
            "exact_token_aud_equals_authenticated_credential_resource",
            contract["active_disclosure_audience_rule"],
        )
        self.assertEqual("active_false_only", contract["audience_mismatch_response"])
        self.assertEqual("advisory_ignored_for_active_disclosure", contract["token_type_hint_semantics"])
        revocation = validator.load_yaml("specs/oauth-p0.v1.yml")["revocation"]
        self.assertEqual("advisory_lookup_order_only", revocation["token_type_hint_semantics"])
        self.assertEqual("jwt_exp_plus_verifier_clock_skew", revocation["access_token_jti_retention_deadline"])
        auth = contract["authentication"]
        self.assertEqual("client_secret_basic", auth["method"])
        self.assertEqual("oauth_resource", auth["credential_owner"])
        self.assertEqual("oauth_resource_credentials", auth["credential_model"])
        self.assertFalse(auth["oauth_client_credential_reused"])
        self.assertFalse(auth["legacy_tool_client_reused"])
        self.assertEqual(
            {
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
            },
            set(contract["credential_lifecycle_fields"]),
        )

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

    def test_step_3_dark_development_is_separate_from_production_release(self) -> None:
        gates = validator.load_yaml("specs/oauth-p0.v1.yml")["development_and_release_gates"]
        self.assertEqual("allowed", gates["step_3_local_dark_development_after_step_2_approval"])
        self.assertTrue(gates["oauth_globally_disabled_by_default"])
        self.assertFalse(gates["pilot_registration_required_before_generic_step_3_implementation"])
        self.assertTrue(gates["pilot_registration_required_before_enable_or_production_registration"])
        self.assertIn("coolify_changes_pending_review", gates["production_deploy_or_enable_blocked_until"])
        self.assertIn("later_n_to_n_plus_1_gates", gates["production_deploy_or_enable_blocked_until"])

    def test_metadata_advertises_only_p0(self) -> None:
        metadata = validator.load_json("examples/oauth/authorization-server-metadata.expected.json")
        self.assertEqual(["authorization_code", "refresh_token"], metadata["grant_types_supported"])
        self.assertEqual(["S256"], metadata["code_challenge_methods_supported"])
        self.assertTrue(metadata["authorization_response_iss_parameter_supported"])


if __name__ == "__main__":
    unittest.main()

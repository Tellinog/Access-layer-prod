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

    def test_wildcard_redirect_is_schema_invalid(self) -> None:
        schema = validator.load_json("schemas/oauth-client-registration.schema.json")
        client = copy.deepcopy(validator.load_json("examples/oauth/client-registration.confidential.json"))
        client["redirect_uris"] = ["https://*.invalid/callback"]
        self.assertTrue(validator.schema_errors(client, schema))

    def test_metadata_advertises_only_p0(self) -> None:
        metadata = validator.load_json("examples/oauth/authorization-server-metadata.expected.json")
        self.assertEqual(["authorization_code", "refresh_token"], metadata["grant_types_supported"])
        self.assertEqual(["S256"], metadata["code_challenge_methods_supported"])
        self.assertTrue(metadata["authorization_response_iss_parameter_supported"])


if __name__ == "__main__":
    unittest.main()

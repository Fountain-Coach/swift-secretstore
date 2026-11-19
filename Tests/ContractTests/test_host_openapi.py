"""Positive and negative coverage for the source-owned SecretStore Host contract."""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts" / "validate-host-openapi.py"
SPEC = importlib.util.spec_from_file_location("secretstore_host_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
contract_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract_gate)


class HostContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads((ROOT / "docs" / "openapi-secretstore-host.json").read_text())

    def test_current_contract_is_private_and_complete(self) -> None:
        self.assertEqual([], contract_gate.validate(self.contract))

    def test_anonymous_status_is_refused(self) -> None:
        altered = copy.deepcopy(self.contract)
        altered["paths"]["/custody/v1/status"]["get"]["security"] = []
        self.assertIn("must require exact Host admission", "\n".join(contract_gate.validate(altered)))

    def test_public_host_claim_is_refused(self) -> None:
        altered = copy.deepcopy(self.contract)
        altered["servers"] = [{"url": "https://secretstore.example.invalid"}]
        self.assertIn("cannot announce a public", "\n".join(contract_gate.validate(altered)))

    def test_unapproved_operation_is_refused(self) -> None:
        altered = copy.deepcopy(self.contract)
        req = altered["components"]["schemas"]["BoundOperationRequest"]
        req["required"].remove("approval")
        self.assertIn("must bind owner", "\n".join(contract_gate.validate(altered)))

    def test_plaintext_payload_is_refused(self) -> None:
        altered = copy.deepcopy(self.contract)
        altered["components"]["schemas"]["CustodyReceipt"]["properties"]["secret"] = {"type": "string"}
        self.assertIn("exposes forbidden field secret", "\n".join(contract_gate.validate(altered)))

    def test_response_refuses_unknown_fields(self) -> None:
        altered = copy.deepcopy(self.contract)
        altered["components"]["schemas"]["MigrationReceipt"]["additionalProperties"] = True
        self.assertIn("closed typed object", "\n".join(contract_gate.validate(altered)))

    def test_unresolved_schema_reference_is_refused(self) -> None:
        altered = copy.deepcopy(self.contract)
        op = altered["paths"]["/custody/v1/operations"]["post"]
        op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] = "#/components/schemas/RawSecret"
        self.assertIn("unresolved", "\n".join(contract_gate.validate(altered)))

    def test_missing_expiry_replay_refusal_is_refused(self) -> None:
        altered = copy.deepcopy(self.contract)
        del altered["paths"]["/custody/v1/operations"]["post"]["responses"]["409"]
        self.assertIn("missing typed security refusals", "\n".join(contract_gate.validate(altered)))


if __name__ == "__main__":
    unittest.main()

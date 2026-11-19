#!/usr/bin/env python3
"""Validate SecretStore's source-owned, Host-private OpenAPI contract.

This is a contract/negative-regression gate, not a test of a deployed Host handler.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "openapi-secretstore-host.json"

EXPECTED = {
    ("/custody/v1/status", "get"): ("inspectSecretCustody", "CustodyStatus", None),
    ("/custody/v1/operations", "post"): (
        "executeBoundCustodyOperation", "CustodyReceipt", "BoundOperationRequest"
    ),
    ("/custody/v1/migrations/transfer", "post"): (
        "transferSecretCustodyWithinHost", "MigrationReceipt", "MigrationTransferRequest"
    ),
    ("/custody/v1/migrations/verify", "post"): (
        "verifySecretCustodyContinuity", "MigrationReceipt", "MigrationVerifyRequest"
    ),
}
FORBIDDEN_FIELDS = {
    "secret", "password", "privatekey", "rawsecret", "credentialdata",
    "ciphertext", "plaintext", "secretvalue", "secretdata", "accesstoken",
    "refreshtoken", "keymaterial", "leasehandle", "filepath", "data",
}
REQUIRED_REFUSALS = {"401", "403", "409", "410", "503"}


def _ref(name: str) -> str:
    return "#/components/schemas/" + name


def validate(contract: dict) -> list[str]:
    issues = []
    if contract.get("openapi") != "3.1.0":
        issues.append("OpenAPI 3.1.0 is required")
    if contract.get("x-fcis-private-host-only") is not True:
        issues.append("Host-only boundary missing")
    if contract.get("x-fcis-runtime-state") != "specified-only-not-deployed":
        issues.append("runtime must not be claimed deployed")
    if contract.get("servers"):
        issues.append("cannot announce a public or independently running SecretStore server")
    components = contract.get("components", {})
    schemas = components.get("schemas", {})
    schemes = components.get("securitySchemes", {})
    if set(schemes) != {"hostAdmission"} or schemes["hostAdmission"].get("scheme") != "bearer":
        issues.append("existing protected Host authorization scheme required")
    if contract.get("security") == []:
        issues.append("no anonymous global security override")
    paths = contract.get("paths", {})
    actual = {
        (path, method)
        for path, entry in paths.items() if isinstance(entry, dict)
        for method in entry if method in {"get", "post", "put", "delete", "patch"}
    }
    if actual != set(EXPECTED):
        issues.append("endpoint/method inventory drift")
    ids = []
    for (path, method), (operation_id, response_schema, request_schema) in EXPECTED.items():
        operation = paths.get(path, {}).get(method, {})
        ids.append(operation.get("operationId"))
        if operation.get("operationId") != operation_id:
            issues.append(f"{path} operationId drift")
        if not operation.get("summary") or not operation.get("description"):
            issues.append(f"{path} missing selection guidance")
        if operation.get("x-fcis-implementation-state") != "specified-only-not-deployed":
            issues.append(f"{path} incorrectly claims deployment")
        if operation.get("security") != [{"hostAdmission": []}]:
            issues.append(f"{path} must require exact Host admission")
        responses = operation.get("responses", {})
        body = responses.get("200", {}).get("content", {}).get("application/json", {})
        if body.get("schema", {}).get("$ref") != _ref(response_schema):
            issues.append(f"{path} missing typed redacted response")
        if not REQUIRED_REFUSALS.issubset(responses.keys()):
            issues.append(f"{path} missing typed security refusals")
        for code in REQUIRED_REFUSALS:
            schema = (responses.get(code, {}).get("content", {})
                      .get("application/json", {}).get("schema", {}))
            if schema.get("$ref") != _ref("CustodyError"):
                issues.append(f"{path} missing typed {code} refusal")
        req_body = operation.get("requestBody", {})
        if request_schema:
            schema = req_body.get("content", {}).get("application/json", {}).get("schema", {})
            if not req_body.get("required") or schema.get("$ref") != _ref(request_schema):
                issues.append(f"{path} must use required typed input")
            required = set(schemas.get(request_schema, {}).get("required", []))
            if not {"approval", "hostId", "nonce", "expiresAt", "idempotencyKey"}.issubset(required):
                issues.append(f"{request_schema} must bind owner, Host, nonce, expiry and replay fence")
            approval = schemas.get(request_schema, {}).get("properties", {}).get("approval", {})
            if approval.get("$ref") != _ref("OwnerApproval"):
                issues.append(f"{request_schema} requires independently verified owner approval")
        elif req_body:
            issues.append(f"{path} read-only status must not accept mutation input")
    if len(ids) != len(set(ids)):
        issues.append("duplicate operationId")
    for name, schema in schemas.items():
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            issues.append(f"{name} must be a closed typed object")
        for field in schema.get("properties", {}):
            if field.lower() in FORBIDDEN_FIELDS:
                issues.append(f"{name} exposes forbidden field {field}")
    def refs(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "$ref":
                    if not isinstance(v, str) or not v.startswith("#/components/schemas/") or v.split("/")[-1] not in schemas:
                        issues.append(f"unresolved or external schema reference {v}")
                else:
                    refs(v)
        elif isinstance(value, list):
            for v in value:
                refs(v)
    refs(contract)
    return issues


def main() -> int:
    try:
        document = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"SecretStore contract unreadable: {exc}", file=sys.stderr)
        return 1
    issues = validate(document)
    if issues:
        for issue in issues:
            print("SecretStore contract refusal: " + issue, file=sys.stderr)
        return 1
    print(f"SecretStore private Host OpenAPI passed ({len(EXPECTED)} operations; source contract only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

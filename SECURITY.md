# Security policy

Report vulnerabilities privately to the Fountain Coach maintainers. Do not place vulnerability details, credentials, private keys, bearer tokens, passwords or live keystore material in public issues.

## Boundary

`swift-secretstore` provides secret custody primitives. It does not decide whether a caller is authorized to use a secret.

The following are never public artifacts:

- live secret values;
- keystore passwords;
- private signing keys;
- bearer credentials;
- machine-specific keychain contents;
- production keystore files.

The source code, formats, algorithms, tests and public interfaces are intended to be reviewable.

## MCP warning

`SecretStoreMCP` is a legacy owner-local stdio adapter with full read/write/delete access to the configured store. It has no independent remote authentication or authorization layer and MUST NOT be exposed as a network service or treated as an authorization boundary.

A passing test suite is not an external security review.

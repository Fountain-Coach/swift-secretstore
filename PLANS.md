# Plans and history-first reconstruction

## Public-source alignment — 2026-10-07

Goal: make `swift-secretstore` a publicly consumable Fountain Coach owned kit so public packages such as FountainAuthKit have a publicly resolvable dependency graph.

Observed predecessor:
- repository existed privately before this alignment;
- MIT license already present;
- semantic tags `v0.1.0`, `v0.1.1`, `v0.2.0`, `v0.2.1`;
- FountainAuthKit consumes `0.2.1`;
- 45 package tests pass on the publication-audit checkout;
- tracked-source secret-shape scan found no credential-like material;
- repository history contains no suspicious secret/key filenames.

Authority:
- `SecretStore` protocol and platform backends own custody operations;
- consuming applications own authorization and policy;
- Keychain / Secret Service / encrypted file storage own platform persistence;
- no transport or MCP adapter becomes authority merely by exposing the API.

Publication finding:
The library is suitable for public source publication. Source code, storage algorithms and interfaces are not secrets. Live secret material and deployment-specific configuration remain private.

Open boundary:
`SecretStoreMCP` exposes store/retrieve/delete/configure over local stdio and can receive a file-store password. It is retained for compatibility but explicitly classified as a legacy owner-local full-access adapter. It is not required by FountainAuthKit and must not be exposed as a remote service.

Acceptance:
- tests green;
- secret scan green;
- public security/threat/crypto documentation present;
- CI runs tests and secret scan;
- repository visibility may then be changed to public.

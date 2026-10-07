# Plans and history-first reconstruction

## Public-source alignment — 2026-10-07

Goal: make `swift-secretstore` a publicly consumable Fountain Coach owned kit so public packages such as FountainAuthKit have a publicly resolvable dependency graph.

Observed predecessor:
- the repository predated this alignment and was being treated as a dependency whose public-consumption posture had not been formally audited;
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
- repository is public and its current consumed tag must have complete FCIS release mechanics.

## Completed release reconciliation

The audit discovered that `v0.2.1` was annotated but had no GitHub Release. The tag was preserved exactly and a GitHub Release was added on 2026-10-07. No package source differs between `v0.2.1` and the public-alignment main branch.

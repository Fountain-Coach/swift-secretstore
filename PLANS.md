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

## SecretStore protected Host interface — 2026-11-19

**Owner goal:** Create the missing SecretStore interface for Hetzner-first FCIS old-to-new FountainStore/SecretStore continuity, using the existing Host and Golden Key/owner authority; no Mac or new user UX.

**Observed source:** `SecretStore` is a three-method native custody protocol; its legacy stdio MCP exposes unguarded full CRUD and is explicitly not network-safe. FCIS owns OAuth, owner approval, Host admission and FountainStore receipts. No independent SecretStore HTTP server or remotely callable credential API is demonstrated.

**Scope:** Publish a source-owned OpenAPI 3.1 contract for **private Host-adapter** custody status, exactly approved bounded use, retained/provider-sealed migration, and continuity verification; retain the library’s local protocol. Document security and operational bindings; add contract shape/refusal tests to existing source CI. No new public endpoint, bearer-only authority, raw secret export, remote MCP, or new root key.

**Chapters read:** 07 — smallest existing-source phase; 08 — source, runtime and Store acceptance are distinct; 131 — typed short-lived operation approval and secret-free receipts; 139 — owner trust-root key stays in original SecretStore custody.
**Forbidden:** making `SecretStoreMCP` a network service, allowing arbitrary requester-selected target or raw credential retrieval, treating SSH or browser passkey as root signing authority, replacing the owner or starting a Mac Keychain ceremony.
**Conflicts:** OpenAPI only describes HTTP; this contract is the **Host adapter** projection, not a promise that the `swift-secretstore` library runs a server. The FCIS root OpenAPI remains authority if these operations are mounted onto the issuer; those routes are not yet accepted.
**Excluded:** runtime service deployment, provider secret-copy or Go/FountainStore cutover and migration. These require separately authorized Host runtime execution and observed Store evidence.

**Finite source DoD:** reviewed `docs/openapi-secretstore-host.json`, explicit typed inputs/outputs and non-secret refusals, protected-only security scheme, referenced README/threat model, automated static regression checks, protected PR with green source CI, merged source readback. **Runtime** Host handler, release and live migration remain `NOT_ESTABLISHED` until independently verified.

**State:** contract implementation in progress. No changed runtime authority. First unfinished action: publish, test and review the interface.


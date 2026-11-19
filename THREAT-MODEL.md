# Threat model

## Assets

- secret values;
- keystore encryption password;
- platform keychain / Secret Service records;
- encrypted file-keystore contents and integrity;
- caller intent around retrieval and deletion.

## Trust boundaries

`SecretStore` is a custody boundary, not an authorization server. A caller that can invoke `retrieveSecret` has already crossed the consuming application's authorization boundary.

Backends:

- Apple Keychain delegates persistence and access control to the Security framework.
- Secret Service delegates persistence to the local Secret Service through `secret-tool`.
- FileKeystore derives an encryption key from a caller-supplied password and stores authenticated ciphertext.

## Principal threats

- committing or logging live secrets;
- weak or reused file-keystore passwords;
- exposing the full-access MCP stdio adapter through an untrusted transport;
- path substitution or symbolic-link abuse against file storage;
- ciphertext or metadata tampering;
- confusing custody success with application authorization;
- silent fallback from one backend to another.

## Required mitigations

- no live secrets in source/evidence;
- authenticated encryption for file storage;
- integrity-failure tests;
- explicit backend selection and failures;
- symlink/path failure tests;
- platform custody where available;
- caller-owned authorization before retrieval;
- SecretStoreMCP remains owner-local and non-networked unless a separately governed protected-resource layer is placed in front of it.

## Protected Host OpenAPI boundary (specified, not deployed)

The versioned [Host custody contract](docs/openapi-secretstore-host.json) is **not** a network-exposed implementation of the three-method `SecretStore` protocol. The adapter implementing it must be hosted only under the **already admitted** FCIS Host protected resource. It must independently verify Host identity, per-client and per-instrument permissions, owner-root signed approval for the exact operation/target/scope/reference, expiry and durable replay fences **before** resolving an opaque reference. An issuer bearer or WebAuthn session alone cannot authorize secret use.

Requests and responses must not transport credentials, ciphertext, keystore passwords, raw provider errors, bearer leases, exported keys, arbitrary filesystem paths or unrestricted signing requests. A successful HTTP response cannot stand in for an independently observed FountainStore terminal receipt. Refusal must be typed and redacted so unauthorized callers cannot enumerate whether a credential is present.

For old-to-new FountainStore/SecretStore continuity on Hetzner, custody remains with the original host provider if possible. Any necessary supported provider-to-provider sealed transfer is a bounded, owner-approved Host effect only, with public-fingerprint/challenge and revocation checks; non-exportable or unverifiable credentials remain inactive/quarantined. No Mac, other workstation or new owner root is silently introduced.

OpenAPI publication and CI do **not** constitute deployed remote secret support, production review or the FCIS Go cutover. The unguarded `SecretStoreMCP` stdio adapter remains **strictly owner-local** and must not be proxied to this Host interface.

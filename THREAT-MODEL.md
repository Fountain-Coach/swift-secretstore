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

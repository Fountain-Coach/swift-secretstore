# Agent law

This repository publishes the generic SecretStore custody seam.

- Secret values, passwords, private keys, bearer credentials and live keystore contents MUST NOT enter Git, logs, fixtures, screenshots, receipts or public documentation.
- The library owns storage and retrieval semantics only. It does not grant application authorization.
- Platform backends remain explicit and testable; no backend may silently fall back to a weaker store.
- Cryptographic primitives come from reviewed platform/Apple libraries; do not invent new primitives in this repository.
- Public API or cryptographic changes require focused tests and a recorded plan.
- The `SecretStoreMCP` executable is a legacy owner-local adapter with full secret access. It MUST NOT be treated as a network service, authorization boundary, or remotely exposed capability.
- Keep multi-step work and release intent in `PLANS.md`.
- Do not publish a release from a dirty tree or when tests/security gates fail.

# FCIS audit

## Owned-kit status

`swift-secretstore` is an owned Swift kit providing a generic custody seam. It carries no FountainAuthKit, Reframe, manuscript or application-domain types.

## Publication decision

Public-source publication is compatible with the kit's role. The implementation contains no required private source dependency. Its only package dependency is Apple's public `swift-crypto`.

The publication audit on 2026-10-07 established:

- MIT license present;
- semantic tags through `v0.2.1`;
- 45 tests passing;
- no credential-like tracked source found by the publication scan;
- no suspicious secret/key filenames found in repository history.

## Authority note

The library manages secret storage. Consumers manage authorization.

The bundled `SecretStoreMCP` executable is not an authority and is not part of FountainAuthKit's dependency surface. Its current full-access stdio tool set is classified as a legacy owner-local adapter and must not be remotely exposed without a separately governed protected-resource authorization layer.

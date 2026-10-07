# FCIS audit

## Owned-kit status

`swift-secretstore` is an owned Swift kit providing a generic custody seam. It carries no FountainAuthKit, Reframe, manuscript or application-domain types.

## Publication decision

Public-source publication is compatible with the kit's role. The implementation contains no required private source dependency. Its only package dependency is Apple's public `swift-crypto`.

The publication audit on 2026-10-07 established:

- MIT license present;
- semantic tags through `v0.2.1`;
- `v0.2.1` is now also published as a GitHub Release without moving its existing annotated tag;
- 45 tests passing;
- no credential-like tracked source found by the publication scan;
- no suspicious secret/key filenames found in repository history.

## Authority note

The library manages secret storage. Consumers manage authorization.

The bundled `SecretStoreMCP` executable is not an authority and is not part of FountainAuthKit's dependency surface. Its current full-access stdio tool set is classified as a legacy owner-local adapter and must not be remotely exposed without a separately governed protected-resource authorization layer.

## Release-mechanics reconciliation — 2026-10-07

Audit found that `v0.2.1` was an immutable annotated tag but lacked the GitHub Release required by FCIS-KIT release mechanics. The existing tag was not moved. A GitHub Release was published for that tag with the custody seam and breaking surface stated explicitly. FountainAuthKit can therefore consume the already-tagged `0.2.1` through a publicly resolvable and release-aligned dependency.

Historical note: `v0.1.0` is a legacy lightweight tag. It is not rewritten; current releases must follow the annotated-tag plus GitHub-Release rule.

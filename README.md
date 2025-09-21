# swift-secretstore

An open-source, **Swift-first secrets library** with **100% test coverage enforcement** and **maximal transparency**.  
Targets macOS/iOS (Keychain), Linux desktop (Secret Service), and headless Linux (encrypted file keystore).

> This repository is intentionally minimal at first boot. The design centers on trust-by-default: transparent code, reproducible builds, and signed releases. Add the code skeleton in follow-up commits or generate it via the included scaffolding instructions below.

---

## Goals

- **Single API, multiple backends**: Keychain (Apple), Secret Service/`secret-tool` (Linux desktop), File keystore with AEAD (headless Linux).
- **Provable coverage**: build **fails** if overall coverage \< 100.00%.
- **Auditability**: small, readable components; extensive unit/prop/KAT tests; documented crypto & threat model.
- **Reproducibility & supply chain**: pinned toolchains, SBOM, and signed provenance on releases.

## Package layout (planned)

```
Sources/
  SecretStore/                 # Public protocol + types
    SecretStore.swift
    Backends/
      KeychainStore.swift
      SecretServiceStore.swift
      FileKeystore.swift
    Crypto/
      PBKDF2.swift             # or Argon2id via vetted dep
      AEAD.swift               # thin wrapper over swift-crypto
    Util/
      ProcessRunner.swift      # injectable runner for tests
Tests/
  Unit/
  Property/
  Vectors/                     # Wycheproof/NIST KATs
  Integration/
  Security/
Tools/
  CoverageGate/                # Fails build if coverage < 100%
Docs/
  # DocC bundle & security docs (CRYPTOGRAPHY.md, THREAT-MODEL.md, etc.)
```

> You can initialize the Swift package with `swift package init --type library` and then add the files above incrementally.

## Quick start

```bash
# 1) Create the Swift package skeleton (optional here; repo starts with docs only)
swift package init --type library

# 2) Add swift-crypto dependency to Package.swift when implementing AEAD
#  .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")

# 3) Run tests with coverage
swift test --enable-code-coverage

# 4) Export coverage JSON and enforce 100%
# (CoverageGate is provided as a Swift tool in Tools/ in the roadmap)
llvm-cov export $(find .build -name '*.xctest' | head -n1)   -instr-profile $(find .build -name default.profdata | head -n1) > coverage.json
# swift run CoverageGate --target 100 --file coverage.json
```

## Platform support (planned matrix)

| Backend              | macOS/iOS | Linux (Desktop) | Linux (Headless) |
|----------------------|-----------|------------------|------------------|
| KeychainStore        | ✅        | ❌               | ❌               |
| SecretServiceStore   | ❌        | ✅               | ❌ (no DBus)     |
| FileKeystore (AEAD)  | ✅        | ✅               | ✅               |

## Trust & transparency

- **Coverage gate**: build fails unless 100% line coverage is met.  
- **Vectors**: Known-Answer Tests (Wycheproof/NIST) checked into `Tests/Vectors`.  
- **Threat model & crypto rationale** will be documented in `Docs/` and linked from this README.
- **Supply chain**: SBOM (CycloneDX) and SLSA provenance attached to releases.

## CI (sketch)

- macOS (Keychain integration tests) + Ubuntu (Secret Service via `dbus-run-session` + `gnome-keyring-daemon`).  
- Enforce coverage \(100%\), upload coverage artifacts, generate SBOM, and sign provenance.

## License

Choose a permissive license (e.g., Apache-2.0 or MIT). Create `LICENSE` in the root.

## Contributing

See `AGENTS.md` for the contributor/automation model. Please run the full test suite locally before opening a PR and ensure the coverage gate passes.

## Repository name

**`swift-secretstore`** (suggested).  
If you prefer org branding, use `fountain-swift-secretstore`. Update badges and module names accordingly.

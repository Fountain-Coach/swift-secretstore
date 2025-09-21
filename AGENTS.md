# AGENTS.md

This repository embraces **transparent automation**. All automation is intentional, declared, and reproducible. The following “agents” are logical roles implemented via CI workflows and small, reviewable tools—**not** opaque services.

## Roles

### 1) Build Agent
- **Purpose:** Compile on macOS and Linux, run tests, and generate coverage.
- **Inputs:** Source code, unit/integration tests.
- **Outputs:** `coverage.json`, test logs, build artifacts.
- **Failure Conditions:** Any test fails; coverage JSON missing.

### 2) Coverage Agent
- **Purpose:** Enforce **100.00%** line coverage (and optionally branch coverage).
- **Implementation:** Small Swift tool (`Tools/CoverageGate`) reading `llvm-cov` JSON; exits non‑zero if below threshold.
- **Outputs:** CI status, coverage badge data (optional).

### 3) Security Agent
- **Purpose:** Supply-chain transparency.
- **Tasks:**
  - Generate SBOM (CycloneDX).
  - Sign build provenance (SLSA).
  - Run static checks (lint, spellcheck for docs, optional secret scanners).
- **Outputs:** `sbom.json`, `provenance.intoto.jsonl`, logs.

### 4) Release Agent
- **Purpose:** Create signed, reproducible releases.
- **Checklist (must pass):**
  1. Tests green on macOS & Linux.
  2. CoverageGate == 100%.
  3. SBOM generated & attached.
  4. Provenance signed.
  5. Changelog updated with security notes.
- **Outputs:** Signed tag, release assets, checksums.

### 5) Compliance Agent (optional)
- **Purpose:** Validate repository structure (docs present, DocC builds, security files updated).
- **Outputs:** Report artifact, CI gate on PR.

## Human-in-the-loop

- **Code Owners** review crypto changes and public API changes.
- Security-sensitive PRs require **two approvals**.
- No agent bypass: CI must be green to merge to `main`.

## Deterministic tooling

- Pin the Swift toolchain in CI. Record `swift --version` in artifacts.
- Keep CoverageGate and other agent tools minimal and auditable.

## Extending Agents

If you add new backends or crypto primitives:
- Extend vectors (KATs) and property tests.
- Update **THREAT-MODEL.md** and **CRYPTOGRAPHY.md**.
- Confirm CoverageGate passes with 100% on the new code paths.

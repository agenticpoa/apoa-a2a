# Changelog

All notable changes to `@apoa/a2a` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## 0.1.7 — 2026-05-16

### Changed

- Bump `@apoa/core` dependency range to `^0.2.1`.
- Use `getDelegationAncestorIds()` from `@apoa/core` instead of maintaining a local copy in the A2A guard.

---

## 0.1.6 — 2026-05-16

### Fixed

- Include canonical `definition.parentToken` ancestors in revocation checks, in addition to transport `delegationChain` metadata. This ensures a revoked parent token denies delegated A2A child messages even when the chain is represented using the core SDK's canonical `parentToken` field.

### Added

- Regression coverage for canonical parent-token cascade revocation.

---

## 0.1.5 — 2026-05-10

### Changed

- Bump `@apoa/core` dependency range to `^0.2.0`. New installs now pick up the security fixes in [`@apoa/core` 0.2.0](https://github.com/agenticpoa/apoa/blob/main/CHANGELOG.md): constraint attenuation hardening, `verifyChain` constraint comparison, empty-scope match fix, JWS algorithm pinning, and JWKS https-only resolver. The full 23-test suite passes against 0.2.0 with no source changes.

### Added

- `.github/workflows/ci.yml` — CI matrix over Node 20 and 22 running `pnpm install --frozen-lockfile`, `typecheck`, `test`, and `build` on every push and PR.

### Fixed

- README banner URL simplified now that the repository is public (no auth-token ?token query string needed).

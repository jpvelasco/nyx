# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-06-17

**Patch release.** Fixes a broken install on npm 9+ / Ubuntu 26 where `allow-scripts` blocks the postinstall binary download, plus several engine and backend bug fixes from recent refactors.

### Fixed

- **npm allow-scripts broken install.** On npm 9+ (default on Ubuntu 26+), the postinstall script that downloads the Go binary is silently skipped, leaving `nyx` installed but non-functional. `run.js` now detects the missing binary and runs `install.js` on first invocation. Root-owned global installs (via `sudo npm install -g`) print a clear recovery command instead of crashing with `EACCES`.
- **Engine panic recovery.** Added recover in the engine goroutine so a panicking assertion no longer kills the whole audit run.
- **buildLookup key collision.** Snapshot drift lookup keys now include ports/query as a disambiguator, preventing false "fixed" or "new" drift entries when multiple assertions share the same target.
- **Engine concurrency guard.** Prevents double-invocation of the audit engine in concurrent contexts.
- **seendb error visibility.** Errors from seendb operations are now surfaced rather than silently dropped.
- **Omada version check.** The Omada client now validates the controller API version before making authenticated calls.
- **resolveRuleEndpoint empty string.** Fixed a case where an empty-string endpoint was returned instead of an error.
- **OPNsense resource leak.** Response body was not closed after use in the OPNsense client; fixed.
- **NmapCheck no-op.** NmapCheck was a no-op in certain code paths; wired correctly.
- **gosec G104 in OPNsense client.** `Body.Close()` return values in error paths are now explicitly annotated as unactionable.

### Changed

- **CLI/MCP deduplication.** `check_routes` and `check_vpn` CLI commands now route through `CheckService`; MCP `run_doctor` uses shared helpers from the service package, eliminating duplicated logic.
- **Backend interface.** Engine now uses a `backends.Backend` interface for testability.
- **CIDR matching extracted.** `matchNetworks` helper consolidates duplicated CIDR-matching logic across `localRunnerContext` and `pickBestInterface`.

## [0.2.6] - 2026-06-15

**Patch release.** Removes accidentally committed IDE harness artifacts and tightens gitignore.

### Other

- **Remove Grok MCP artifacts.** Delete `mcps/grok_com_github/` (44 JSON files) that were IDE harness output, not part of nyx.
- **Tighten gitignore.** Ignore `mcps/`, `agent-tools/`, `terminals/`, `.remember/`, `.claude/` to prevent future accidental commits.
- **Genericize test strings.** Remove machine-specific comments and probe username from tests.

## [0.2.5] - 2026-06-14

**Patch release.** Fixes CodeQL parse errors in the npm install/run shims.

### Fixed

- **npm shim shebang order.** Move `#!/usr/bin/env node` to line 1 in `npm/install.js` and `npm/run.js` so CodeQL's JavaScript extractor no longer reports syntax errors.

## [0.2.4] - 2026-06-14

**Patch release.** Publishes the npm package README and expanded registry metadata.

### Added

- **npm README.** Install, quickstart, badges, assertion overview, MCP setup, and vendor integration docs on [npmjs.com](https://www.npmjs.com/package/nyx-audit-cli).

### Changed

- **GitHub README.** npm badge, install link, and npm-first quick start.
- **npm package metadata.** Expanded description and SEO keywords.

## [0.2.3] - 2026-06-14

**Patch release.** First npm publish fully automated via GitHub Actions OIDC (trusted publisher for `nyx-audit-cli`).

## [0.2.2] - 2026-06-14

**Patch release.** Renames the npm package so publishing works under `devrecon` without the `@nyx` org.

### Changed

- **npm package name.** `@nyx/cli` → `nyx-audit-cli` (unscoped; `nyx-cli` is taken on the registry). Install via `npm install -g nyx-audit-cli`.

## [0.2.1] - 2026-06-14

**Patch release.** Fixes the release workflow so the npm shim publishes (package was still `@nyx/cli`, which never succeeded).

### Fixed

- **embed-checksums.js.** Move `#!/usr/bin/env node` to line 1 — a nosemgrep comment above the shebang caused Node to throw `SyntaxError` in CI, blocking npm publish for v0.2.0.

## [0.2.0] - 2026-06-14

**Feature release.** First `@nyx/cli` npm publish, secure-by-default TLS/SSH verification, and engine/provider hardening since v0.1.0.

### Added

- **npm distribution.** GoReleaser builds plus GitHub Actions OIDC publish — install via `npm install -g @nyx/cli`; postinstall downloads the matching binary with embedded SHA-256 verification.
- **Gosec in CI and locally.** `make gosec` and `make check` (gosec → vet → test → build) catch security findings before push.
- **Secure-by-default TLS.** Omada and OPNsense verify TLS certificates by default; opt out with `--skip-tls-verify` or supply a custom CA via `--ca-cert`.
- **Secure-by-default SSH.** Probes verify host keys by default; opt out with `--skip-host-key-verify` or `skip_host_key_verify: true` per probe in the spec.

### Changed

- **Release pipeline.** Replaced hand-rolled release steps with GoReleaser, cross-platform archives (including Windows ARM64), and checksum embedding in the npm shim.
- **Codacy toolchain.** Refreshed rules and tool configs; tuned ignores for the npm shim and build scripts.

### Fixed

- **Audit engine.** Load SeenDB once at `Run()` instead of per-discovery; handle `int` and `float64` host counts in `Observed`; log gateway ACL fetch errors instead of swallowing them.
- **Recommendations engine.** Handle `int` type for `Observed["total"]` after nmap backend change (was silently misclassifying subnet_discovery failures).
- **nmap backend.** Build `Observed` maps directly instead of JSON round-trip.
- **Omada provider.** Integer version comparison instead of string sort (fixes false negatives on values like `5.4.10`).
- **acl_check, probe isolation, port scan.** Critical correctness bugs including partial nmap error status and multi-gateway ACL probing.
- **MCP server.** Context cancellation respected in goroutines; initialization state tracked correctly.
- **embed-checksums.js.** Case-insensitive hex matching for GoReleaser `sha256sum` output on platforms that emit uppercase digests.
- **Codacy/Gosec/CodeQL.** Resolved CRITICAL/HIGH findings, correct suppression syntax per tool chain, and CodeQL config exclusions for intentional homelab TLS/SSH patterns.

### Documentation

- **Codacy guidance.** Resolved documentation findings; clarified personal spec exception path.

## [0.1.0] - 2026-06-02

Initial public release after major stabilization.

### Added
- Full CI pipeline (`.github/workflows/ci.yml`): `go vet → go test → go build` on every push/PR to main, using Go version from go.mod + caching.
- `.golangci.yml` + `make lint` target for consistent linting before push.
- Comprehensive unit test coverage improvements targeting previously untested packages (batfish, system helpers, report, CLI wiring, MCP dispatch, providers, etc.).
- Cross-platform test fixes (e.g., seendb unwritable path test).
- Professional npm distribution wrapper (`@nyx/cli`) fully aligned with current branding, GitHub org, and binary naming.
- Removal of legacy artifacts (`docs/spec.md`, stale npm references, empty directories).
- Review feedback addressed during stabilization PR (workflow permissions, golangci config version declaration).

### Changed
- `Makefile`: Improved `release` target documentation, added `lint` to phony targets, better Windows .exe handling in clean.
- Many packages received gofmt cleanup as part of enforcing higher standards.
- Provider registration and test isolation improvements.

### Fixed
- Several pre-existing test issues exposed by running real CI on Linux (most notably the seendb test).
- Module path inconsistency in Makefile.
- Legacy "netaudit" references throughout distribution artifacts.

### Notes
- This release focuses on making the project ready for external contributors and reliable distribution.
- Core engine, providers (omada + opnsense), snapshot/drift, MCP, and all 8 assertion types were already feature-complete before this release.
- No breaking changes. Version remains 0.1.0 as the first tagged public release.

[Unreleased]: https://github.com/jpvelasco/nyx/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.7
[0.2.6]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.6
[0.2.5]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.5
[0.2.4]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.4
[0.2.3]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.3
[0.2.2]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.2
[0.2.1]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.1
[0.2.0]: https://github.com/jpvelasco/nyx/releases/tag/v0.2.0
[0.1.0]: https://github.com/jpvelasco/nyx/releases/tag/v0.1.0

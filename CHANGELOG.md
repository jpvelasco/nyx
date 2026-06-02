# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/jpvelasco/nyx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jpvelasco/nyx/releases/tag/v0.1.0

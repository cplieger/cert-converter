# Changelog

## 2026.05.18-7b15372 (2026-05-21)

### Added

- Add file-based healthcheck for distroless container
- Add file-based healthcheck for distroless containers
- Improve logging, security hardening, and test coverage

### Fixed

- Refactor health probe to enable unit testing

### Security

- Move healthcheck to Dockerfile and harden security

### Changed

- Introduce ScanResult, CacheChecker interface, distribute tests, and parallelize
- Refactor into internal packages
- Simplify tmpfs comment
- Refactor(cert-convert): replace magic strings with named constants
- Refactor compose (no user-visible change)
- Resilience, pruning, scan summary, and hardening

### Dependencies

- Update gcr.io/distroless/static-debian13:nonroot docker digest to 963fa6c
- Update golang:1.26-alpine docker digest to 91eda97 (#258)
- Update third-party dependencies
- fix(deps): update module github.com/fsnotify/fsnotify to v1.10.0
- fix(deps): update module github.com/fsnotify/fsnotify to v1.10.1 (#239)
- fix(deps): update module pgregory.net/rapid to v1.3.0

## 2026.04.16-8e0d8c0 (2026-04-17)

### Dependencies

- Update golang:1.26-alpine docker digest to 27f8293 (#202)
- Update golang:1.26-alpine docker digest to f853308

## 2026.04.15-7901f5a (2026-04-16)

### Dependencies

- Update golang:1.26-alpine docker digest to 1fb7391 (#192)

## 2026.04.13-98ff0b3 (2026-04-13)

### Changed

- Refactor(cert-convert): simplify logging and improve error handling
- Update Go toolchain configuration

### Dependencies

- Update go to v1.26.2
- Update golang:1.26-alpine docker digest to c2a1f7b
- fix(deps): update module software.sslmate.com/src/go-pkcs12 to v0.7.1

## 2026.04.09-be1da00 (2026-04-10)

### Dependencies

- fix(deps): update module software.sslmate.com/src/go-pkcs12 to v0.7.1

## 2026.04.07-f8709e0 (2026-04-08)

### Changed

- Update Go toolchain configuration

### Dependencies

- Update go to v1.26.2
- Update golang:1.26-alpine docker digest to c2a1f7b

## 2026.04.01-b015ff4 (2026-04-01)

### Added

- Enhance logging with password status and debug traces
- Test(cert-convert): add property-based and edge case tests
- Test(cert-convert): add comprehensive test coverage for file watching and key parsing
- Add security hardening and structured logging
- Add file size validation and resource exhaustion tests
- Test(apps): add comprehensive test coverage for identity loading and cert conversion
- Add CLI health probes for distroless Docker healthchecks
- Ci(validate): Add golangci-lint linting checks for Go apps
- Add specific non-root version
- Pull containers from github vs dockerfile build for all apps. Update jdupes github action to add release versions.
- Added cert convert compose file

### Fixed

- Improve startup health state and retry logic
- App fixes and cleanup
- Fix build images
- Fix go module caching with go.sum, fix linting.
- Fix whitespace in all files
- Fix versions and exclude [deploy-tool] from auto updates
- Fix post build version
- Fix env file name for cert-convert

### Changed

- Test(cert-convert): use bytes.Equal for slice comparison
- Refactor(cert-convert): reorganize code structure and improve file handling
- Migrate to structured logging and enhance validation
- Refactor(cert-convert): extract certificate processing and health check logic
- Test(cert-convert): improve certificate chain building and modernize type hints
- Test(cert-convert): improve code quality and readability in test helpers
- Consolidate age encryption hooks and re-encrypt all env files
- Test(apps): refactor test structure and improve helper functions
- Update health checks and standardize environment variable quoting
- Update encrypted environment files across all services
- Ci(validate,renovate): Consolidate golangci-lint to dynamic loop and expand critical infra coverage
- Ci(workflows,dockerfiles): Refactor build and validation pipelines
- Improve health check dependencies
- New approach to env file management for sops
- New approach to sops .env file naming
- Trigger rebuilds for broken images
- Update to new versioning scheme
- Upload encoded env files
- Revert to rolling image
- Remove QEMU
- Upgrade debian version
- Update golang Docker tag
- Pin dependencies
- Update build versions
- Pin dependencies
- Revert [deploy-tool] secrets
- Replace .env files with [deploy-tool] secrets
- Update repo to [private-repo] from snippetspace/homelab
- Removed space
- Change cert-convert log output to stdout

### Dependencies

- Update gcr.io/distroless/static-debian13:nonroot Docker digest to 01e550f
- Update gcr.io/distroless/static-debian13:nonroot Docker digest to f512d81
- Update gcr.io/distroless/static-debian13:nonroot docker digest to 0376b51
- Update gcr.io/distroless/static-debian13:nonroot docker digest to e3f9456
- Update go to v1.26.0
- Update go to v1.26.1
- Update golang.org/x/crypto to v0.45.0 [security]
- Update golang:1.25-alpine Docker digest to 660f0b8
- Update golang:1.25-alpine Docker digest to 98e6cff
- Update golang:1.25-alpine Docker digest to d9b2e14
- Update golang:1.25-alpine Docker digest to e689855
- Update golang:1.25-alpine Docker digest to f4622e3
- Update golang:1.25-alpine Docker digest to f6751d8
- Update golang:1.26-alpine docker digest to 2389ebf
- Update software.sslmate.com/src/go-pkcs12 to v0.7.0

## 2026.03.21-0aabfbc (2026-03-22)

### Added

- Enhance logging with password status and debug traces

## 2026.03.15-784bd79 (2026-03-16)

### Dependencies

- Update gcr.io/distroless/static-debian13:nonroot docker digest to e3f9456

## 2026.03.13-0b2cad0 (2026-03-14)

### Added

- Test(cert-convert): add property-based and edge case tests
- Test(cert-convert): add comprehensive test coverage for file watching and key parsing

### Changed

- Test(cert-convert): use bytes.Equal for slice comparison

## 2026.03.12-0137780 (2026-03-12)

### Fixed

- Improve startup health state and retry logic

## 2026.03.11-b633060 (2026-03-11)

### Added

- Add security hardening and structured logging

### Changed

- Refactor(cert-convert): reorganize code structure and improve file handling
- Migrate to structured logging and enhance validation

## 2026.03.07-3c60ea9 (2026-03-08)

### Added

- Add file size validation and resource exhaustion tests

### Changed

- Refactor certificate processing and health check logic

## 2026.03.07-9112d85 (2026-03-07)

### Added

- Minor healthcheck code improvements and optimizations

## 2026.03.06-694b90b (2026-03-06)

### Dependencies

- Update golang:1.26-alpine docker digest to 2389ebf
- Update dependency go to v1.26.1

## 2026.03.03-cdb462e (2026-03-04)

- Initial release

# Changelog

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

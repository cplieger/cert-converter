# docker-cert-converter

![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)
[![GitHub release](https://img.shields.io/github/v/release/cplieger/docker-cert-converter)](https://github.com/cplieger/docker-cert-converter/releases)
[![Image Size](https://ghcr-badge.egpl.dev/cplieger/cert-convert/size)](https://github.com/cplieger/docker-cert-converter/pkgs/container/cert-convert)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)
![base: Distroless](https://img.shields.io/badge/base-Distroless_nonroot-4285F4?logo=google)

Automated PEM-to-PFX certificate converter with file watching

## Overview

Watches a certificate directory using fsnotify (with polling fallback) for
new or changed PEM certificate files. When a change is detected, it reads
the certificate chain and private key, then produces a PKCS#12 (.pfx) file.
SHA-256 change detection skips unchanged certificates. Supports modern2023,
modern2026, and legacy PFX encoding profiles. Includes a CLI health probe
for distroless Docker healthchecks (file-based, no HTTP server or open port).

**Example use case:** Caddy generates PEM certificates natively. If you have
apps that only accept PFX/PKCS#12 files (e.g. some Synology services, .NET
apps, or Windows-based tools), point the input directory to Caddy's
certificate folder and this container will automatically produce PFX files
whenever Caddy renews certificates.

This is a distroless, rootless container — it runs as `nonroot` on
`gcr.io/distroless/static` with no shell or package manager.


## Container Registries

This image is published to both GHCR and Docker Hub:

| Registry | Image |
|----------|-------|
| GHCR | `ghcr.io/cplieger/cert-convert` |
| Docker Hub | `docker.io/cplieger/cert-convert` |

```bash
# Pull from GHCR
docker pull ghcr.io/cplieger/cert-convert:latest

# Pull from Docker Hub
docker pull cplieger/cert-convert:latest
```

Both registries receive identical images and tags. Use whichever you prefer.

## Quick Start

```yaml
services:
  cert-convert:
    image: ghcr.io/cplieger/cert-convert:latest
    container_name: cert-convert
    restart: unless-stopped
    user: "1000:1000"  # match your host user
    mem_limit: 64m

    environment:
      TZ: "Europe/Paris"
      PFX_PASSWORD: "your-pfx-password"
      FALLBACK_SCAN_HOURS: "6"  # fsnotify fallback interval
      PFX_ENCODER: "modern2023"  # modern2023, modern2026, or legacy

    volumes:
      - "\\/path/to/pem/certificates:/input:ro"
      - "\\/path/to/pfx/output:/output:rw"

    healthcheck:
      test:
        - CMD
        - /cert-watcher
        - health
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
```

## Deployment

1. Set `PFX_PASSWORD` to the password you want embedded in the generated PFX files.
2. Mount your PEM certificate directory to `/input` (read-only) and an output directory to `/output`.
3. The container watches `/input` for changes using fsnotify. When a
   new or modified `.crt`/`.key` file pair is detected, it generates a
   corresponding `.pfx` file in `/output`.
4. If fsnotify misses events (common with network mounts), the
   container falls back to periodic full scans every
   `FALLBACK_SCAN_HOURS` hours.
5. Choose `PFX_ENCODER` — see the
   [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables)
   for details on each profile:
   - `modern2023` (default): AES-256-CBC + SHA-256 MAC. Compatible with OpenSSL 1.1.1+, Java 12+, Windows Server 2019+.
   - `modern2026`: AES-256-CBC + PBMAC1 MAC. Requires OpenSSL 3.4.0+ or Java 26+.
   - `legacy`: 3DES + SHA-1. For older devices like some Synology firmware versions.


## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `TZ` | Container timezone | `Europe/Paris` | No |
| `PFX_PASSWORD` | Password embedded in generated PFX files | - | Yes |
| `FALLBACK_SCAN_HOURS` | Hours between full directory re-scans (fallback when fsnotify misses events) | `6` | No |
| `PFX_ENCODER` | PFX encoding profile — modern2023 (AES-256-CBC + SHA-256, default), modern2026 (AES-256-CBC + PBMAC1, requires OpenSSL 3.4.0+), or legacy (3DES + SHA-1 for older devices). See [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables). | `modern2023` | No |


## Volumes

| Mount | Description |
|-------|-------------|
| `/input` | PEM certificate directory (read-only) |
| `/output` | PFX output directory |


## Docker Healthcheck

The container includes a built-in Docker healthcheck. On startup and after
each certificate processing cycle, the main process creates a marker file
at `/tmp/.healthy`. The `health` subcommand checks for this file's existence.

**When it becomes unhealthy:**
- Input directory is unreadable or missing
- PEM parsing fails (malformed certificate or key)
- PFX write fails (output directory full or read-only)
- Any error during the `processAll` cycle

**When it recovers:**
- The next successful processing cycle (triggered by fsnotify event or fallback timer) recreates the marker file and the container reports healthy again. No restart required.

**On shutdown:** The marker file is removed, so a stopped container
always reports unhealthy on the next start until the first successful
processing cycle completes.

To check health manually:
```bash
docker inspect --format='{{json .State.Health.Log}}' cert-convert | python3 -m json.tool
```

| Type | Command | Meaning |
|------|---------|---------|
| Docker | `/cert-watcher health` | Exit 0 = last processing cycle succeeded |


## Code Quality

| Metric | Value |
|--------|-------|
| [Test Coverage](https://go.dev/blog/cover) | 64.7% |
| Tests | 106 |
| [Cyclomatic Complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) (avg) | 5.7 |
| [Cognitive Complexity](https://www.sonarsource.com/docs/CognitiveComplexity.pdf) (avg) | 8.2 |
| [Mutation Efficacy](https://en.wikipedia.org/wiki/Mutation_testing) | 90.5% (59 runs) |
| Test Framework | Property-based ([rapid](https://github.com/flyingmutant/rapid)) + table-driven |

The test suite validates all user-facing functionality: PEM certificate
parsing (RSA, ECDSA, Ed25519, chain handling, corrupt input), PFX
encoding round-trips across all encoder profiles, SHA-256 change
detection with file size guards, fsnotify event handling with debounce
logic, and the full processing pipeline (skip unchanged, reconvert on
change, nested directories, error recovery). Property-based tests
verify that parsing functions never panic on arbitrary input and that
round-trips preserve certificate data.

Not tested: the filesystem watcher loop and polling fallback — these
are event-driven I/O paths that can't be unit tested meaningfully.
Validated by Docker healthchecks in production (the health probe
confirms the last processing cycle succeeded).

## Security Review

**No vulnerabilities found.** All scans clean across 10 tools.

| Tool | Result |
|------|--------|
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | No vulnerabilities in call graph |
| [golangci-lint](https://golangci-lint.run/) (gosec, gocritic) | 0 issues |
| [trivy](https://trivy.dev/) | 0 vulnerabilities |
| [grype](https://github.com/anchore/grype) | 0 vulnerabilities |
| [gitleaks](https://github.com/gitleaks/gitleaks) | No secrets detected |
| [semgrep](https://semgrep.dev/) | 1 info (false positive) |
| [hadolint](https://github.com/hadolint/hadolint) | Clean |

This app has a minimal attack surface: no network listener, no
HTTP server, no exposed ports. It reads PEM files from a mounted
directory and writes PFX files to another. Runs as `nonroot` on
a distroless base image with no shell or package manager.

**Details for advanced users:** File paths are hardcoded
(`/input`, `/output`), not configurable via env vars. File reads
are TOCTOU-safe (stat + read from same handle) with a 10 MB cap.
PFX writes use atomic temp-file + rename. The semgrep finding is
the `/tmp/.healthy` health marker, a fixed-path zero-byte file
in a single-process container.

## Dependencies

All dependencies are updated automatically via [Renovate](https://github.com/renovatebot/renovate) and pinned by digest or version for reproducibility.

| Dependency | Version | Source |
|------------|---------|--------|
| golang | `1.26-alpine` | [Go](https://hub.docker.com/_/golang) |
| gcr.io/distroless/static-debian13 | `nonroot` | [Distroless](https://github.com/GoogleContainerTools/distroless) |
| github.com/fsnotify/fsnotify | `v1.9.0` | [GitHub](https://github.com/fsnotify/fsnotify) |
| pgregory.net/rapid | `v1.2.0` | [pkg.go.dev](https://pkg.go.dev/pgregory.net/rapid) |
| software.sslmate.com/src/go-pkcs12 | `v0.7.0` | [SSLMate](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) |

## Design Principles

- **Always up to date**: Base images, packages, and libraries are updated automatically via Renovate. Unlike many community Docker images that ship outdated or abandoned dependencies, these images receive continuous updates.
- **Minimal attack surface**: When possible, pure Go apps use `gcr.io/distroless/static:nonroot` (no shell, no package manager, runs as non-root). Apps requiring system packages use Alpine with the minimum necessary privileges.
- **Digest-pinned**: Every `FROM` instruction pins a SHA256 digest. All GitHub Actions are digest-pinned.
- **Multi-platform**: Built for `linux/amd64` and `linux/arm64`.
- **Healthchecks**: Every container includes a Docker healthcheck.
- **Provenance**: Build provenance is attested via GitHub Actions, verifiable with `gh attestation verify`.

## Credits

This is an original tool that builds upon [Go crypto/x509 + go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12).

## Disclaimer

These images are built with care and follow security best practices, but they are intended for **homelab use**. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude Opus](https://www.anthropic.com/claude) and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

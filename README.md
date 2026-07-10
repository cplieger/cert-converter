# cert-converter

[![Image Size](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/size.json)](https://github.com/cplieger/cert-converter/pkgs/container/cert-converter)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)
![base: Distroless](https://img.shields.io/badge/base-Distroless_nonroot-4285F4?logo=google)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/coverage.json)](https://github.com/cplieger/cert-converter/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/mutation.json)](https://github.com/cplieger/cert-converter/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13200/badge)](https://www.bestpractices.dev/projects/13200)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/cert-converter/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/cert-converter)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/cert-converter/releases)

Automatically converts PEM certificates to PFX format whenever they renew — set it and forget it.

## What it does

Watches a certificate directory using fsnotify (with polling fallback) for
new or changed PEM certificate files. When a change is detected, it reads
the certificate chain and private key, then produces a PKCS#12 (.pfx) file —
for example, if Caddy generates PEM certificates and you have apps that only
accept PFX/PKCS#12 files (e.g. some Synology services, .NET apps, or
Windows-based tools), point the input directory to Caddy's certificate folder
and this container will automatically produce PFX files whenever certificates
are renewed. SHA-256 change detection skips unchanged certificates. Supports
modern2023, modern2026, and legacy PFX encoding profiles. Includes a CLI
health probe for distroless Docker healthchecks (file-based, no HTTP server
or open port).

### Why this design

- **Distroless and rootless** — runs on `gcr.io/distroless/static:nonroot` with no shell or package manager, minimizing attack surface and eliminating entire classes of container escapes.
- **fsnotify with polling fallback** — reacts to certificate changes in real time, but falls back to periodic full scans so network mounts and edge cases never cause missed renewals.
- **SHA-256 skip-unchanged** — avoids unnecessary PFX regeneration by fingerprinting input files, reducing disk writes and keeping output timestamps meaningful.
- **No HTTP server, no open ports** — the container has zero network listeners; health is reported via a file-based probe, leaving nothing exposed to the network.

## Quick start

The image is published to both GHCR (`ghcr.io/cplieger/cert-converter`) and Docker Hub (`cplieger/cert-converter`) — identical contents, use whichever you prefer.

```yaml
services:
  cert-converter:
    image: ghcr.io/cplieger/cert-converter:latest
    container_name: cert-converter
    restart: unless-stopped
    user: "1000:1000"  # match your host user

    environment:
      PFX_PASSWORD: "your-pfx-password"
      FALLBACK_SCAN_HOURS: "6"  # fsnotify fallback interval
      PFX_ENCODER: "modern2023"  # modern2023, modern2026, legacy, or legacyrc2

    volumes:
      - "/path/to/pem/certificates:/input:ro"
      - "/path/to/pfx/output:/output:rw"
```

## Configuration reference

### Environment variables

| Variable                   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                        | Default        | Required |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | -------- |
| `PFX_PASSWORD`             | Password embedded in generated PFX files. Required: the container refuses to start when this is empty unless `PFX_ALLOW_EMPTY_PASSWORD=true` is set.                                                                                                                                                                                                                                                                                               | -              | Yes      |
| `PFX_ALLOW_EMPTY_PASSWORD` | Opt out of the empty-password guard. When `PFX_PASSWORD` is empty the container refuses to start; set this to `true` to allow startup anyway. Generated PFX files then protect the embedded private key with an empty password (effectively no protection) — not recommended.                                                                                                                                                                      | `false`        | No       |
| `FALLBACK_SCAN_HOURS`      | Hours between full directory re-scans (fallback when fsnotify misses events). Only an explicit `0` or `false` disables the periodic fallback; with it off, a missed fsnotify event (common on network mounts) is not recovered until the next change, so a renewal can be skipped. A set-but-empty (`FALLBACK_SCAN_HOURS=""`), whitespace, or invalid value uses the 6h default (like omitting the key), so a blank never silently disables it.    | `6`            | No       |
| `PFX_ENCODER`              | PFX encoding profile — modern2023 (AES-256-CBC + SHA-256, default), modern2026 (AES-256-CBC + PBMAC1, requires OpenSSL 3.4.0+), legacy (3DES + SHA-1 for older devices), or legacyrc2 (RC2-40 + SHA-1, only for very old devices). `modern` is accepted as an alias for `modern2023`, and `legacy` is recorded as `legacydes` in startup logs. See [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables). | `modern2023`   | No       |
| `LOG_LEVEL`                | Minimum log level — `debug`, `info` (default), `warn`, or `error` (case-insensitive; accepts slog offsets such as `info+2`). Set to `debug` to surface per-certificate skip reasons (orphan, unchanged, unreadable subdir) and filesystem-event detail that are otherwise suppressed. An unrecognized value falls back to `info`.                                                                                                                  | `info`         | No       |

> **`FALLBACK_SCAN_HOURS` ceiling:** a value above `87600` (10 years) is clamped to that ceiling and logs a WARN.

### Volumes

| Mount     | Description                           |
| --------- | ------------------------------------- |
| `/input`  | PEM certificate directory (read-only) |
| `/output` | PFX output directory                  |

## Alerting

cert-converter has no metrics endpoint; its operational state is in its logs.
Ship the container's logs to Loki (Grafana Alloy's Docker log discovery does
this with no configuration) and evaluate these with
[Loki's ruler](https://grafana.com/docs/loki/latest/alert/); firing alerts
deliver through your Alertmanager exactly like Prometheus metric alerts.

```yaml
groups:
  - name: cert-converter
    rules:
      - alert: CertConverterConversionFailed
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"} |= `scan complete`
            |~ ` (failed|unreadable)=[1-9]` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter failed to convert a certificate"
          description: >
            A scan logged failed>0 or unreadable>0 (PEM parse, PFX write, or
            input read failure); the affected .pfx is stale or missing. Check
            /input permissions and the certificate chain.
      - alert: CertConverterScanStalled
        expr: |
          absent_over_time({container="cert-converter"} |= `scan complete` [8h])
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter has not completed a scan in 8h"
          description: >
            cert-converter emits a `scan complete` line at least every
            FALLBACK_SCAN_HOURS (default 6h). None in 8h while the container is
            up means the fsnotify watch and the fallback timer are both wedged;
            certificates silently stop converting. Restart the container.
```

Thresholds and the `severity` label are starting points; adjust the stall
window to your `FALLBACK_SCAN_HOURS` and the `container` selector to your
deployment, and route by whatever labels your Alertmanager uses.

## Healthcheck

The container includes a built-in health probe: after each processing cycle with no conversion failures, the main process creates a marker file at `/tmp/.healthy`; the `health` subcommand (`/cert-watcher health`) checks for this file and exits 0 if it exists.

Health answers a single operational question — _should an orchestrator restart this container?_ — so it tracks only failures a restart could plausibly clear. The container becomes **unhealthy** when the `/input` root itself cannot be read, or when a certificate fails to convert (PEM or key parse error, cert/key mismatch, or PFX write failure). It **auto-recovers** on the next clean cycle (triggered by an fsnotify event or the fallback timer) without requiring a restart.

An unreadable _sub-path_ under `/input` (e.g. one certificate directory with the wrong permissions or owner) is a steady-state misconfiguration a restart would not fix, so it is logged as a warning and its certificates are skipped — it does **not** flip the container unhealthy. Fix the directory permissions or run the container as a UID that can read it.

## Security

**No vulnerabilities found.** All scans clean across the full scanner suite.

| Tool                                                                | Result                           |
| ------------------------------------------------------------------- | -------------------------------- |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | No vulnerabilities in call graph |
| [golangci-lint](https://golangci-lint.run/) (gosec, gocritic)       | 0 issues                         |
| [trivy](https://trivy.dev/)                                         | 0 vulnerabilities                |
| [grype](https://github.com/anchore/grype)                           | 0 vulnerabilities                |
| [gitleaks](https://github.com/gitleaks/gitleaks)                    | No secrets detected              |
| [semgrep](https://semgrep.dev/)                                     | 1 info (false positive)          |
| [hadolint](https://github.com/hadolint/hadolint)                    | Clean                            |

This app has a minimal attack surface: it reads PEM files from a
mounted directory and writes PFX files to another, with no network
listener or open port (see [Why this design](#why-this-design)).

**Details for advanced users:** File paths are hardcoded
(`/input`, `/output`), not configurable via env vars. Input reads
are confined to `/input` through an `os.Root`, so a symlink planted
in the input tree cannot redirect a read outside it; reads are
TOCTOU-safe (stat + read from the same handle) with a 10 MB cap.
PFX writes use atomic temp-file + rename.

## Dependencies

Updated automatically via [Renovate](https://github.com/renovatebot/renovate) and pinned by digest. Builds carry signed SBOMs and provenance attestations verifiable with `gh attestation verify`.

| Dependency                         | Source                                                           |
| ---------------------------------- | ---------------------------------------------------------------- |
| golang                             | [Go](https://hub.docker.com/_/golang)                            |
| gcr.io/distroless/static           | [Distroless](https://github.com/GoogleContainerTools/distroless) |
| github.com/fsnotify/fsnotify       | [GitHub](https://github.com/fsnotify/fsnotify)                   |
| pgregory.net/rapid                 | [pkg.go.dev](https://pkg.go.dev/pgregory.net/rapid)              |
| software.sslmate.com/src/go-pkcs12 | [SSLMate](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) |

## Credits

This is an original tool that builds upon [Go crypto/x509 + go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12).

## Contributing

Issues and pull requests are welcome. Please open an issue first for
larger changes so the approach can be discussed before implementation.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude Opus](https://www.anthropic.com/claude) and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

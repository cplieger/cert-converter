# cert-converter

[![Image Size](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/size.json)](https://github.com/cplieger/cert-converter/pkgs/container/cert-converter)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)
![base: Distroless](https://img.shields.io/badge/base-Distroless_nonroot-4285F4?logo=google)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/coverage.json)](https://github.com/cplieger/cert-converter/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/mutation.json)](https://github.com/cplieger/cert-converter/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13200/badge)](https://www.bestpractices.dev/projects/13200)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/cert-converter/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/cert-converter)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/cert-converter/releases)

Automatically converts PEM certificates to PFX format whenever they renew. Set it and forget it.

## What it does

Watches a certificate directory for new or changed PEM certificate files and
converts each one, chain plus private key, into a PKCS#12 (.pfx) file. The
typical use: Caddy renews PEM certificates, but some of your apps only accept
PFX (some Synology services, .NET apps, Windows-based tools). Point `/input`
at Caddy's certificate folder and fresh PFX files appear on every renewal.
SHA-256 change detection skips unchanged certificates; modern2023,
modern2026, and legacy encoding profiles cover both current and older
consumers.

### Why this design

- **Distroless and rootless**: runs on `gcr.io/distroless/static-debian13:nonroot` with no shell or package manager, minimizing the attack surface.
- **fsnotify with polling fallback**: reacts to certificate changes in real time, and periodic full scans catch anything fsnotify misses (network mounts, edge cases), so renewals are never skipped.
- **SHA-256 skip-unchanged**: fingerprints input files to skip pointless PFX regeneration, reducing disk writes and keeping output timestamps meaningful.
- **No HTTP server, no open ports**: the container has zero network listeners; health is a file-based probe, so nothing is exposed to the network.

## Quick start

The image is published to both GHCR (`ghcr.io/cplieger/cert-converter`) and Docker Hub (`cplieger/cert-converter`); the contents are identical, use whichever you prefer.

```yaml
services:
  cert-converter:
    image: ghcr.io/cplieger/cert-converter:latest
    container_name: cert-converter
    restart: unless-stopped
    user: "1000:1000"  # match your host user

    environment:
      PFX_PASSWORD: "${PFX_PASSWORD:-}"  # set this or configure PFX_PASSWORD_FILE; empty is rejected
      PFX_ENCODER: "modern2023"  # modern2023, modern2026, legacy, or legacyrc2

    volumes:
      - "/path/to/pem/certificates:/input:ro"
      - "/path/to/pfx/output:/output"
```

## Configuration reference

### Environment variables

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `PFX_PASSWORD` | Password embedded in generated PFX files. The container refuses to start when this is empty unless `PFX_ALLOW_EMPTY_PASSWORD=true` is set. | - | Yes |
| `PFX_PASSWORD_FILE` | Path to a file holding the PFX password (Docker/Podman secret). When set it takes precedence over `PFX_PASSWORD`, keeping the secret out of the container environment and out of `docker inspect`. The file is read once, bounded at 1 MB, and trimmed of surrounding whitespace; an unreadable or empty file is a startup failure. | - | No |
| `PFX_ALLOW_EMPTY_PASSWORD` | Set to `true` to let the container start with an empty `PFX_PASSWORD`. Generated PFX files then protect the embedded private key with an empty password (effectively no protection); not recommended. | `false` | No |
| `FALLBACK_SCAN_HOURS` | Hours between full directory re-scans, the fallback for fsnotify events missed on network mounts and similar edge cases. Only an explicit `0` or `false` disables it, leaving a missed event unrecovered until the next change. An empty, whitespace, or invalid value uses the 6h default, so a blank never silently disables the safety net; a value above `87600` (10 years) is clamped to that ceiling and logs a WARN. | `6` | No |
| `PFX_ENCODER` | PFX encoding profile: modern2023 (AES-256-CBC + SHA-256, default), modern2026 (AES-256-CBC + PBMAC1, requires OpenSSL 3.4.0+), legacy (3DES + SHA-1 for older devices), or legacyrc2 (RC2-40 + SHA-1, only for very old devices). `modern` is an alias for `modern2023`, and `legacy` is recorded as `legacydes` in startup logs. See the [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables). | `modern2023` | No |
| `LOG_LEVEL` | Minimum log level: `debug`, `info`, `warn`, or `error` (case-insensitive; slog offsets such as `info+2` work). `debug` surfaces per-certificate skip reasons (orphan, unchanged, unreadable subdir) and filesystem-event detail. An unrecognized value falls back to `info`. | `info` | No |

### Volumes

| Mount | Description |
| --- | --- |
| `/input` | PEM certificate directory (read-only). Must be readable by the UID in `user:`; Caddy's certificate directory is often root-owned and mode `0700`, so either `chgrp`/`chmod` it for that UID or run the container as a UID that can read it. |
| `/output` | PFX output directory; must be writable by the UID in `user:` |

Create the host output directory owned by the UID you set in `user:`
(`mkdir -p /path/to/pfx/output && chown 1000:1000 /path/to/pfx/output`) before
the first start. Unlike an unreadable `/input` sub-path, which is only warned
about and skipped, an unwritable `/output` fails every conversion and keeps the
container unhealthy. Generated `.pfx` files are mode `0600` and their
directories `0750`, both owned by that UID, so whatever consumes them must run
as the same UID (or as a privileged process); group membership alone is
insufficient because mode `0600` grants no group read access.

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

The image bakes in a health probe. After each processing cycle with no conversion failures, the main process writes a marker file at `/tmp/.healthy`. The `health` subcommand (`/cert-watcher health`) exits 0 when the marker exists and, while the fallback rescan is enabled, is fresher than three `FALLBACK_SCAN_HOURS` intervals. A staler marker means the watch loop is wedged, so the probe fails and the container is reported `unhealthy`. Docker Engine does not act on health status by itself: an orchestrator that does (Swarm, Kubernetes) restarts the container, while under plain Docker Compose the `unhealthy` state is a signal to monitor — see the `CertConverterScanStalled` rule under [Alerting](#alerting) — and the restart is yours to perform. Setting `FALLBACK_SCAN_HOURS` to `0`/`false` disables both the fallback and this staleness deadline.

Health answers one question: should an orchestrator restart this container? It therefore tracks only failures a restart could plausibly clear. The container becomes **unhealthy** when the `/input` root itself cannot be read or a certificate fails to convert (PEM or key parse error, cert/key mismatch, or PFX write failure). It **auto-recovers** on the next clean cycle (fsnotify event or fallback timer) without a restart.

An unreadable _sub-path_ under `/input` (e.g. one certificate directory with the wrong permissions or owner) is a steady-state misconfiguration a restart would not fix. It is logged as a warning and its certificates are skipped; it does **not** flip the container unhealthy. Fix the directory permissions or run the container as a UID that can read it.

## Security

The attack surface is small: the container reads PEM files from one mounted directory and writes PFX files to another, with no network listener or open port. It runs as a non-root user on a distroless base with no shell or package manager (see [Why this design](#why-this-design)), so there is nothing to expose or firewall; keep the `/input` mount read-only as in the quick start.

File paths are hardcoded (`/input`, `/output`), not configurable via env vars. Input reads are confined to `/input` through an `os.Root`, so a symlink planted in the input tree cannot redirect a read outside it. Reads are TOCTOU-safe (stat and read from the same handle) with a 10 MB cap, and malformed PEM or key input is rejected and logged rather than converted. PFX writes use an atomic temp-file + rename.

`PFX_PASSWORD` is the only protection on the private key inside every generated `.pfx`. A literal compose value, `${...}` interpolation, and `env_file:` all become container environment and are visible to anyone who can query the Docker daemon (`docker inspect`). To avoid that exposure, mount a Docker/Podman secret and set `PFX_PASSWORD_FILE` to its in-container path; the file value takes precedence over `PFX_PASSWORD`. If an environment value is acceptable, `PFX_PASSWORD: "${PFX_PASSWORD:?}"` plus a mode-`0600`, gitignored `.env` keeps the value out of the committed compose file, but not out of container inspection.

One accepted scanner finding: semgrep flags the fixed `/tmp/.healthy` health-marker path as a predictable temp file. The path is a deliberate contract between the main process and the `health` probe inside the container's own filesystem, not shared state an attacker can pre-create. Live scan results are on the repository's Security tab.

### Hardened deployment

To lock the container down further, layer these directives onto the Quick start service:

```yaml
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - "/tmp:size=1m,mode=1777,noexec,nosuid,nodev"
```

`read_only: true` requires the file-marker health probe to have a writable `/tmp`; the tmpfs supplies it. `size=1m` is ample: the marker is the only thing cert-converter writes outside `/output`.

## Dependencies

Updated automatically via [Renovate](https://github.com/renovatebot/renovate) and pinned by digest. Builds carry signed SBOMs and provenance attestations verifiable with `gh attestation verify`.

| Dependency                         | Source                                                           |
| ---------------------------------- | ---------------------------------------------------------------- |
| golang                             | [Go](https://hub.docker.com/_/golang)                            |
| gcr.io/distroless/static-debian13  | [Distroless](https://github.com/GoogleContainerTools/distroless) |
| github.com/fsnotify/fsnotify       | [GitHub](https://github.com/fsnotify/fsnotify)                   |
| pgregory.net/rapid                 | [pkg.go.dev](https://pkg.go.dev/pgregory.net/rapid)              |
| software.sslmate.com/src/go-pkcs12 | [SSLMate](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) |
| github.com/cplieger/health         | [GitHub](https://github.com/cplieger/health)                     |
| github.com/cplieger/slogx          | [GitHub](https://github.com/cplieger/slogx)                      |
| github.com/cplieger/atomicfile/v2  | [GitHub](https://github.com/cplieger/atomicfile)                 |
| github.com/cplieger/envx           | [GitHub](https://github.com/cplieger/envx)                       |

## Credits

This is an original tool that builds upon [Go crypto/x509 + go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12).

## Contributing

Issues and pull requests are welcome. Please open an issue first for
larger changes so the approach can be discussed before implementation.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0. See [LICENSE](LICENSE).

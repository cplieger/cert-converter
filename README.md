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
converts each one, chain plus private key, into a PKCS#12 (.pfx) file. RSA,
ECDSA, Ed25519 and ML-DSA keys are all supported. The
typical use: Caddy renews PEM certificates, but some of your apps only accept
PFX (some Synology services, .NET apps, Windows-based tools). Point `/input`
at Caddy's certificate folder and fresh PFX files appear on every renewal.
Each scan compares the bundle already on disk against the one the current
inputs produce, so unchanged certificates are skipped; modern2023,
modern2026, and legacy encoding profiles cover both current and older
consumers.

### Why this design

- **Distroless and rootless**: runs on `gcr.io/distroless/static-debian13:nonroot` with no shell or package manager, minimizing the attack surface.
- **fsnotify with polling fallback**: reacts to certificate changes in real time, and periodic full scans catch anything fsnotify misses (network mounts, edge cases), so renewals are never skipped.
- **Skip-unchanged read from the output itself**: currency is decided by reading the bundle on disk rather than from a state file, so a rotated password or a changed encoder profile is picked up on the next scan while unchanged certificates cause no rewrite, keeping disk writes and output timestamps meaningful.
- **No HTTP server, no open ports**: the container has zero network listeners; health is a file-based probe, so nothing is exposed to the network.

## Quick start

The image is published to both GHCR (`ghcr.io/cplieger/cert-converter`) and Docker Hub (`cplieger/cert-converter`); the contents are identical, use whichever you prefer.

```yaml
services:
  cert-converter:
    image: ghcr.io/cplieger/cert-converter:latest
    container_name: cert-converter
    restart: unless-stopped
    # Override with PUID/PGID in .env; defaults to 1000:1000.
    user: "${PUID:-1000}:${PGID:-1000}"  # must own the /output host dir

    environment:
      PFX_PASSWORD: "${PFX_PASSWORD:-}"  # set this or configure PFX_PASSWORD_FILE; empty is rejected
      # Orphaned output: warn (default, keeps it) | sync (deletes) | keep (silent).
      # Use sync only once /input is your single source of truth.
      OUTPUT_LIFECYCLE: "${OUTPUT_LIFECYCLE:-warn}"
      PFX_ENCODER: "modern2023"  # modern2023, modern2026, legacy, or legacyrc2

    volumes:
      - "/path/to/pem/certificates:/input:ro"  # must be readable by the UID above; see README "Healthcheck"
      - "/path/to/pfx/output:/output"
```

## Configuration reference

### Environment variables

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `PFX_PASSWORD` | Password embedded in generated PFX files. The container refuses to start when it is empty or blank (whitespace-only, or invisible characters only such as a byte-order mark) unless `PFX_ALLOW_EMPTY_PASSWORD=true` is set. It also refuses a value PKCS#12 cannot encode: a character outside the Basic Multilingual Plane, a byte sequence that is not valid UTF-8, or an embedded NUL, each of which produces bundles no consumer can open with the configured secret. | - | Yes |
| `PFX_PASSWORD_FILE` | Path to a file holding the PFX password (a Docker/Podman secret). When set it takes precedence over `PFX_PASSWORD` and keeps the secret out of `docker inspect`; setting both logs a WARN naming which one is ignored. The file is read once, bounded at 1 MB, and used verbatim apart from at most one trailing line ending, so whitespace inside or around the password stays part of it, and leading or trailing whitespace draws a WARN on either channel because every consumer must reproduce it. The path must already be in cleaned form and must not traverse, so `/run/secrets/../secrets/pfx`, a redundant `//`, a `./` prefix and a trailing `/` are all refused. An **unusable** file (unreadable, oversized, or a rejected path) is a startup failure that `PFX_ALLOW_EMPTY_PASSWORD=true` does not rescue; a **blank** file is refused exactly like a blank `PFX_PASSWORD`, so the opt-out means one thing however the secret arrives. A configured file never falls back to `PFX_PASSWORD`. | - | No |
| `PFX_ALLOW_EMPTY_PASSWORD` | Set to `true` to let the container start with a blank password, from either delivery channel. Generated PFX files then protect the embedded private key with an empty password (effectively no protection); not recommended. | `false` | No |
| `FALLBACK_SCAN_HOURS` | Hours between full directory re-scans, the fallback for fsnotify events missed on network mounts and similar edge cases. Only an explicit `0` or `false` disables it, which stops re-scans **on your cadence** but not the app's own convergence: the watcher still reconciles the whole tree, and still refreshes the health marker, at least once every 24 hours, so a missed renewal is converted late rather than never (see [Healthcheck](#healthcheck)). Startup logs a WARN naming that latency tradeoff. An empty, whitespace, or invalid value uses the 6h default, so a blank never silently disables the safety net; a value above `87600` (10 years) is clamped to that ceiling, and any cadence above 24h is capped at the 24h reconciliation floor. An invalid or clamped value is reported by a WARN at startup only, never by the `health` subcommand, which reads the same setting on every probe. | `6` | No |
| `PFX_ENCODER` | PFX encoding profile: modern2023 (AES-256-CBC + SHA-256, default), modern2026 (AES-256-CBC + PBMAC1, requires OpenSSL 3.4.0+), legacy (3DES + SHA-1 for older devices), or legacyrc2 (RC2-40 + SHA-1, a last-resort interop escape: a 40-bit RC2 key is brute-forceable, so the private key in such a bundle is protected only nominally; use it when a device accepts nothing else and treat the output as sensitive). `modern` is an alias for `modern2023`, and `legacy` is recorded as `legacydes` in startup logs. See the [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables). | `modern2023` | No |
| `OUTPUT_LIFECYCLE` | What happens to a `.pfx` whose certificate **and** private key have both left `/input`. `warn` (default) logs the orphan and leaves the file in place; `sync` deletes it so `/output` tracks `/input`, once a re-check 30 seconds later confirms both are still gone; `keep` is silent and never deletes. A bundle whose `<name>.key` is still there is kept and reported by its own WARN, because a half-written or half-deleted pair is not proof the bundle is orphaned: finish the change under `/input` (add the matching `<name>.crt`, or remove the leftover `<name>.key`) and the next scan reaps it. `sync` removes only files matching this app's own output shape, and it deletes nothing unless the scan proves it enumerated `/input` completely: at least one certificate found, the walk finished within `MAX_SCAN_ENTRIES`, and no unreadable path, unresolvable symlink, or conversion failure. A scan without that proof logs `orphan removal is disabled for this scan` and reaps nothing, so a broken or empty mount is never read as "every certificate was deleted". Every scan that deletes something logs a WARN naming the count and a sample of the paths. An unrecognized value logs a WARN and uses `warn`. | `warn` | No |
| `MAX_SCAN_ENTRIES` | How many `/input` paths one scan enumerates before it stops, converting and removing nothing further. The stop is a WARN naming the path it reached, and it leaves health alone, because no restart shrinks the tree; orphan cleanup is skipped for that scan. If your certificate tree is legitimately larger than the default, raise this **and** the container's memory limit together: one scan's memory grows with the total length of the paths it enumerates and not only with their number, so raising this alone can push the scan past a fixed memory limit, where it is killed and converts nothing at all. Where the memory limit cannot move, lower this ceiling or set `OUTPUT_LIFECYCLE=keep`, which returns before the output walk and so never builds the `/output` list. An empty, whitespace, invalid, zero, or negative value uses the `10000` default, and a value above `200000` is clamped to that ceiling; either repair is reported by a WARN at startup naming the value you set. There is deliberately no value that disables the budget. | `10000` | No |
| `LOG_LEVEL` | Minimum log level: `debug`, `info`, `warn`, or `error` (case-insensitive; slog offsets such as `info+2` work). `debug` surfaces per-certificate skip reasons (orphan, unchanged, unreadable subdir), each orphan deletion's own path, and filesystem-event detail. An unrecognized value falls back to `info`. | `info` | No |

### Volumes

| Mount | Description |
| --- | --- |
| `/input` | PEM certificate directory (read-only). Each certificate must be named `<name>.crt` with its private key as the sibling `<name>.key` in the same directory (Caddy's layout); files with any other extension are ignored, so a certbot-style directory of `fullchain.pem`/`privkey.pem` produces no output and logs `no certificate pairs found under the input root`. Sub-directories are scanned recursively and mirrored under `/output` as `<name>.pfx`. Must be readable by the UID in `user:`; Caddy's certificate directory is often root-owned and mode `0700`, so `chgrp`/`chmod` it for that UID or run the container as a UID that can read it. |
| `/output` | PFX output directory; must be writable by the UID in `user:` |

Create the host output directory owned by the UID you set in `user:` before
the first start. Export `PUID` and `PGID` with the same values Compose uses,
then run `mkdir -p /path/to/pfx/output && chown "${PUID:-1000}:${PGID:-1000}" /path/to/pfx/output`
(both default to `1000`, matching `compose.yaml`). An unwritable `/output` fails
every conversion and keeps the container unhealthy.

Generated `.pfx` files are mode `0600` and the directories this app creates are
`0750`, both owned by that UID, so whatever consumes them must run as the same
UID or as a privileged process; group membership alone is not enough, because
mode `0600` grants no group read access. This app never `chmod`s what it finds
under `/output`: an output directory more permissive than `0750`, or a `.pfx`
more permissive than `0600`, draws a WARN naming the mode found and is then left
exactly as found. Tightening it is yours to do, and worth doing: a group- or
world-writable output directory lets any other process on that mount replace a
bundle. A bundle this app writes again for its own reasons, such as a renewal,
lands at `0600`.

### Commands

The image supplies `watch` as its default command, so a plain
`docker run`/`docker compose up` needs nothing extra. Both subcommands are
listed here because the binary takes one and refuses to run without it.

| Command | Description |
| --- | --- |
| `cert-watcher watch` | Start the watcher. The image's default command, so Compose never has to state it |
| `cert-watcher health` | Probe the health marker and exit 0 or 1. What the baked-in `HEALTHCHECK` runs |

Any other argv, including no argv at all, prints usage and exits 2. That is
deliberate: `docker exec <container> /cert-watcher` would otherwise start a
second watcher over the same `/input` and `/output` while the container's own
watcher was running, and the second process clears the first one's health marker
on the way in. Use `docker exec <container> /cert-watcher health` to read the
marker, and leave the running watcher alone.

## Alerting

cert-converter has no metrics endpoint; its operational state is in its logs.
Ship the container's logs to Loki (Grafana Alloy's Docker log discovery does
this with no configuration) and evaluate the rules in
[`alerts.yaml`](alerts.yaml) with
[Loki's ruler](https://grafana.com/docs/loki/latest/alert/); firing alerts
deliver through your Alertmanager exactly like Prometheus metric alerts. They
cover:

| Alert | Fires when | Severity |
| --- | --- | --- |
| `CertConverterConversionFailed` | a parse error, a cert/key mismatch, or a failed PFX write left a `.pfx` stale or missing | warning |
| `CertConverterOutputWriteRefused` | an `/output` condition no restart clears refused a write, so a stale `.pfx` is left as found | warning |
| `CertConverterScanAborted` | the `/input` root itself could not be walked, so the scan returned early | warning |
| `CertConverterInputTreeTooLarge` | a scan stopped at `MAX_SCAN_ENTRIES`, so every certificate past that point is unconverted | warning |
| `CertConverterChangeDetectionDegraded` | no fsnotify watch could be established, so a renewal waits for the next full re-scan | warning |
| `CertConverterChangeDetectionDead` | the watch loop ended for a reason other than shutdown, and the process exited for a restart | critical |
| `CertConverterInputPathUnreachable` | an `/input` path could not be read or resolved, so its certificates were skipped | warning |
| `CertConverterNoCertificatePairs` | a scan found no `<name>.crt` with a sibling `<name>.key`, so no PFX is produced at all | warning |
| `CertConverterOutputCleanupDegraded` | stale temp files under `/output`, each holding a private key, cannot be removed | warning |
| `CertConverterOrphanRemovalDisabled` | a scan could not prove a bundle is orphaned, so `OUTPUT_LIFECYCLE=sync` reaped nothing | warning |
| `CertConverterScanStalled` | no `scan complete` heartbeat in 8h, so the watch loop is wedged, silent, or shipping no logs | warning |

Every rule keys on a WARN or ERROR record and works at `LOG_LEVEL=warn` as well
as at the `info` default, with one deliberate exception.
`CertConverterScanStalled` reports a wedged watch loop, and it can only do that
by keying on the `scan complete` heartbeat, which is an **`info`** record
because a healthy scan has nothing to report at `warn`. So that one rule
requires the `info` default and fires permanently at `LOG_LEVEL=warn`; drop it
if you run at `warn`. The container healthcheck covers the same failure without
needing the `info` level, through the health marker's freshness deadline (see
[Healthcheck](#healthcheck)), but only where something acts on an unhealthy
container.

Thresholds and the `severity` labels are starting points; adjust the
`container` selector to your deployment, match the degradation window to your
`FALLBACK_SCAN_HOURS`, and route by whatever labels your Alertmanager uses.

## Healthcheck

The image bakes in a health probe. After each cycle with no conversion failures, the main process writes a marker file at `/tmp/.healthy`, and the `health` subcommand (`/cert-watcher health`) exits 0 while that marker exists and is fresher than three times the app's guaranteed re-scan cadence: 18h on the 6h default, and 72h when `FALLBACK_SCAN_HOURS` is `0`/`false` or above 24h, because the app reconciles the whole tree at least every 24 hours whatever that setting says. A staler marker means the watch loop is wedged. The startup line reports both numbers, `fallback_scan` (your cadence, or `disabled`) beside `scan_floor` (the guaranteed one the deadline comes from).

The container is `unhealthy` when the `/input` root cannot be read or a certificate fails to convert (PEM or key parse error, cert/key mismatch, or PFX write failure), and it recovers on the next clean cycle without a restart. Docker Engine does not act on health status itself: an orchestrator that does (Swarm, Kubernetes) restarts the container, and under plain Docker Compose the restart is yours to perform.

Health tracks only failures a restart can clear, so five conditions are logged at WARN with the action to take and leave health alone: an unreadable `/input` sub-path, an `/input` tree over `MAX_SCAN_ENTRIES`, an `/output` directory more permissive than `0750`, a `.pfx` more permissive than `0600`, and a refused replacement of a bundle this app could not read or verify.

## Security

The attack surface is small: the container reads PEM files from one mounted directory and writes PFX files to another, with no network listener or open port. It runs as a non-root user on a distroless base with no shell or package manager (see [Why this design](#why-this-design)), so there is nothing to expose or firewall; keep the `/input` mount read-only as in the quick start.

File paths are hardcoded (`/input`, `/output`), not configurable via env vars. Input reads are confined to `/input` through an `os.Root`, so a symlink planted in the input tree cannot redirect a read outside it. Reads are TOCTOU-safe (stat and read from the same handle) with a 10 MB cap, and malformed PEM or key input is rejected and logged rather than converted. A private key is refused before Go's parser sees it when its structure declares more than 64 RSA prime factors or an RSA integer above 16384 bits, so a small crafted file cannot stall the scan on key precomputation. PFX writes use an atomic temp-file + rename.

`PFX_PASSWORD` is the only protection on the private key inside every generated `.pfx`. A literal compose value, `${...}` interpolation, and `env_file:` all become container environment and are visible to anyone who can query the Docker daemon (`docker inspect`). To avoid that exposure, mount a Docker/Podman secret and set `PFX_PASSWORD_FILE` to its in-container path; the file value takes precedence over `PFX_PASSWORD`. If an environment value is acceptable, `PFX_PASSWORD: "${PFX_PASSWORD:?}"` plus a mode-`0600`, gitignored `.env` keeps the value out of the committed compose file, but not out of container inspection.

One accepted scanner finding: semgrep flags the fixed `/tmp/.healthy` marker path as a predictable temp file, but it is a contract between the main process and the `health` probe inside the container's own filesystem, not shared state an attacker can pre-create. Live scan results are on the repository's Security tab.

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
| github.com/cplieger/atomicfile/v3  | [GitHub](https://github.com/cplieger/atomicfile)                 |
| github.com/cplieger/envx           | [GitHub](https://github.com/cplieger/envx)                       |
| github.com/cplieger/runesafe       | [GitHub](https://github.com/cplieger/runesafe)                   |

## Credits

This is an original tool that builds upon [Go crypto/x509 + go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12).

## Contributing

Issues and pull requests are welcome. Please open an issue first for
larger changes so the approach can be discussed before implementation.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

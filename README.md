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
| `PFX_PASSWORD` | Password embedded in generated PFX files. The container refuses to start when this is empty **or blank** (whitespace-only, e.g. a quoting slip in compose) unless `PFX_ALLOW_EMPTY_PASSWORD=true` is set, and refuses to start when the value cannot survive PKCS#12 encoding: a character outside the Basic Multilingual Plane (every conversion would fail), a byte sequence that is not valid UTF-8, or an embedded NUL (both would silently produce bundles no consumer can open with the configured secret). | - | Yes |
| `PFX_PASSWORD_FILE` | Path to a file holding the PFX password (Docker/Podman secret). When set it takes precedence over `PFX_PASSWORD`, keeping the secret out of the container environment and out of `docker inspect`; setting both logs a WARN naming which one is ignored. The file is read once, bounded at 1 MB, and trimmed of surrounding whitespace. The path must already be in cleaned form and contain no `..` anywhere in it, so `/run/secrets/../secrets/pfx` is refused even when it is readable, as are a redundant `//`, a `./` prefix, a trailing `/`, and a filename that merely holds two consecutive dots such as `pfx..v2`. An **unusable** file — unreadable, oversized, or a rejected path — is a startup failure that `PFX_ALLOW_EMPTY_PASSWORD=true` does not rescue. A **blank** file (empty or whitespace-only) is treated exactly like a blank `PFX_PASSWORD`: refused unless `PFX_ALLOW_EMPTY_PASSWORD=true`, so the opt-out means one thing however the secret is delivered. A configured file never falls back to `PFX_PASSWORD` in either case. | - | No |
| `PFX_ALLOW_EMPTY_PASSWORD` | Set to `true` to let the container start with an empty `PFX_PASSWORD`. Generated PFX files then protect the embedded private key with an empty password (effectively no protection); not recommended. | `false` | No |
| `FALLBACK_SCAN_HOURS` | Hours between full directory re-scans, the fallback for fsnotify events missed on network mounts and similar edge cases. Only an explicit `0` or `false` disables it, and that runs the watcher unsupervised: a missed event stays unrecovered until the next change, the health marker's freshness deadline is off, and an `/input` watch dropped by an unmount or remount cannot be detected at all, so the container keeps reporting healthy while converting nothing. Startup logs a WARN naming those three losses. Leave the fallback enabled unless you accept a watcher nothing supervises. An empty, whitespace, or invalid value uses the 6h default, so a blank never silently disables the safety net; a value above `87600` (10 years) is clamped to that ceiling. An invalid or clamped value is reported by a WARN at startup only — never by the `health` subcommand, which reads the same setting on every healthcheck. | `6` | No |
| `PFX_ENCODER` | PFX encoding profile: modern2023 (AES-256-CBC + SHA-256, default), modern2026 (AES-256-CBC + PBMAC1, requires OpenSSL 3.4.0+), legacy (3DES + SHA-1 for older devices), or legacyrc2 (RC2-40 + SHA-1, a last-resort interop escape: a 40-bit RC2 key is brute-forceable, so the private key in such a bundle is protected only nominally — use it when a device accepts nothing else, and treat the output as sensitive). `modern` is an alias for `modern2023`, and `legacy` is recorded as `legacydes` in startup logs. See the [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables). | `modern2023` | No |
| `OUTPUT_LIFECYCLE` | What happens to a `.pfx` whose certificate has been removed from `/input`. `warn` (default) logs the orphan and leaves the file in place; `sync` deletes it so `/output` tracks `/input`; `keep` is silent and never deletes. `sync` only ever removes files matching this app's own output shape, and it refuses to delete anything at all unless the scan proves it enumerated `/input` completely: at least one certificate found, the walk finished, and no unreadable path, unresolvable symlink, or conversion failure. A scan that cannot make that proof logs `orphan removal is disabled for this scan` and reaps nothing, so a broken or empty mount can never be read as "every certificate was deleted". An unrecognized value logs a WARN and uses `warn`. | `warn` | No |
| `LOG_LEVEL` | Minimum log level: `debug`, `info`, `warn`, or `error` (case-insensitive; slog offsets such as `info+2` work). `debug` surfaces per-certificate skip reasons (orphan, unchanged, unreadable subdir) and filesystem-event detail. An unrecognized value falls back to `info`. | `info` | No |

### Volumes

| Mount | Description |
| --- | --- |
| `/input` | PEM certificate directory (read-only). Each certificate must be named `<name>.crt` with its private key as the sibling `<name>.key` in the same directory (Caddy's layout); files with any other extension are ignored, so a certbot-style directory of `fullchain.pem`/`privkey.pem` produces no output and logs `no certificate pairs found under the input root`. Sub-directories are scanned recursively and mirrored under `/output` as `<name>.pfx`. Must be readable by the UID in `user:`; Caddy's certificate directory is often root-owned and mode `0700`, so either `chgrp`/`chmod` it for that UID or run the container as a UID that can read it. |
| `/output` | PFX output directory; must be writable by the UID in `user:` |

Create the host output directory owned by the UID you set in `user:`
(`mkdir -p /path/to/pfx/output && chown 1000:1000 /path/to/pfx/output`) before
the first start. Unlike anything under `/input` the scan cannot read, which is
only warned about and skipped, an unwritable `/output` fails every conversion and
keeps the container unhealthy. Generated `.pfx` files are mode `0600` and their
directories `0750`, both owned by that UID, so whatever consumes them must run
as the same UID (or as a privileged process); group membership alone is
insufficient because mode `0600` grants no group read access.

## Alerting

cert-converter has no metrics endpoint; its operational state is in its logs.
Ship the container's logs to Loki (Grafana Alloy's Docker log discovery does
this with no configuration) and evaluate these with
[Loki's ruler](https://grafana.com/docs/loki/latest/alert/); firing alerts
deliver through your Alertmanager exactly like Prometheus metric alerts.

**Prerequisite: these exact rules require `LOG_LEVEL=info` (the default) or
`debug`.** The `scan complete` line they key on is logged at INFO even when
`failed`/`unreadable` are non-zero, so `LOG_LEVEL=warn` or `error` suppresses
it: `CertConverterConversionFailed` then never fires and
`CertConverterScanStalled` fires permanently despite healthy fallback scans
(`error` additionally suppresses the WARN-level `scan aborted before
completion` line behind `CertConverterScanAborted`). If you run at `warn` or
`error`, do not deploy the `CertConverterConversionFailed` or
`CertConverterScanStalled` expressions unchanged. Container health covers
conversion failures and aborted scans (and, with the fallback rescan enabled, a
stalled watch loop through the marker's freshness deadline), but it deliberately
ignores `unreadable>0` — nothing the scan merely could not READ under `/input`
flips health, because none of it is clearable by a restart — so at `warn` also
alert on the WARN lines `some /input paths were unreadable and were skipped` and
`skipping cert: cannot read` to keep that coverage. At `error` that WARN is
suppressed too, so use a
lower log level if you need equivalent unreadable-path alerting. Otherwise write
replacement rules over the messages your level still emits.

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
            A scan logged failed>0 (PEM parse, cert/key mismatch, or PFX write)
            or unreadable>0 (an /input path the scan could not read); the
            affected .pfx is stale or missing. Only the failed>0 half flips
            container health — an unreadable path is a layout or permissions
            condition a restart cannot clear — so this rule deliberately covers
            more than the healthcheck does. Check /input permissions, that each
            cert and its sibling key are regular files inside the mount rather
            than symlinks out of it, and the certificate chain.
      - alert: CertConverterScanAborted
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"} |= `scan aborted before completion` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter aborted a scan before completion"
          description: >
            The /input root itself could not be walked (unreadable mount, wrong
            permissions, or a mid-scan unmount), so the scan returned early and
            the container is unhealthy. The conversion-failure rule does not
            cover this outcome, and the stall rule identifies it only after its
            eight-hour window. Check the /input mount and its permissions.
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
            up means either the fsnotify watch and the fallback timer are both
            wedged, or every scan is aborting early — check for a
            CertConverterScanAborted alert first, since that one names the
            /input problem and fires within 15m. If no scan aborted, the loop is
            wedged: restart the container.
      - alert: CertConverterChangeDetectionDead
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |= `change detection is dead` [15m]
          )) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "cert-converter lost change detection and is exiting for a restart"
          description: >
            The watch loop ended for a reason other than shutdown, so the process
            exited non-zero to be restarted. The announcement is emitted once,
            by the process that exits, and its `error` field names which loss
            occurred. Two causes: fsnotify's channels closed under a live
            container, or fsnotify was unavailable AND
            FALLBACK_SCAN_HOURS is 0/false, leaving no mechanism to notice
            a renewal at all. Exiting is deliberate — the alternative was a
            container that sat healthy forever while converting nothing, because
            the startup scan had already written the health marker and disabling
            the fallback also disables the marker's freshness deadline. Critical
            rather than warning: with no restart policy the container stays down
            and every renewal is silently missed. Ensure the deployment restarts
            it (`restart: unless-stopped`), and if the record carries a
            `remediation` field naming FALLBACK_SCAN_HOURS, unset it or set it
            above 0 so the periodic rescan covers the missing watch. Exhausted
            inotify instances on the host are the usual root cause and are often
            transient.
      - alert: CertConverterInputPathUnreachable
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |~ `(skipping symlink that could not be resolved through the input root|skipping cert: cannot stat sibling key)` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter skipped an unreachable /input path"
          description: >
            An /input path could not be reached, so what it holds was not
            converted. Either a symlink could not be resolved through the input
            root, or a certificate's sibling `<name>.key` could not be stat'ed —
            which covers a path escaping the input root, a permission denial, and
            any other IO error, not only a symlink. Whatever was skipped — every
            certificate under a linked directory, or that one certificate — was
            not converted. This outcome is health-neutral: the scan still
            logs `scan complete` with failed=0 and unreadable=0, so none of the
            other rules fire and the affected .pfx stays stale or absent
            indefinitely. Mount the certificate path directly instead of linking
            to it, or repair the permissions of the link target and of the
            sibling key.
      - alert: CertConverterNoCertificatePairs
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |~ `(no certificate pairs found under the input root|every certificate under the input root is missing its sibling \.key)` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter found no convertible certificate pairs under /input"
          description: >
            A scan completed without converting a single `<name>.crt` with a
            sibling `<name>.key` — either it visited no pair at all, or every
            `.crt` it visited was an orphan with no sibling key — so no PFX is
            produced at all. This is the signature of a wrong or vanished
            /input mount, of a certbot-style
            directory of fullchain.pem/privkey.pem this app does not read, or
            of a key-naming layout that does not match the `<name>.key`
            contract. The
            outcome is health-neutral — the scan still logs `scan complete` with
            failed=0 and unreadable=0 — so none of the other rules fire. Check
            the /input mount and the .crt/.key filename contract. A fresh
            deployment legitimately reports this until the first issuance; raise
            `for:` if that is noisy.
      - alert: CertConverterOutputCleanupDegraded
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |~ `(stale temp cleanup failed|some stale output temps could not be inspected or removed|some output paths could not be inspected during stale temp cleanup)` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter cannot clean up stale /output temp files"
          description: >
            The stale-temp sweep aborted at the /output root, could not inspect
            or unlink temp files left
            behind by an interrupted atomic write, or could not enter an /output
            sub-path. Conversions may still succeed, so this is health-neutral
            and no other rule fires, while `.atomicfile-*.tmp` files — each
            holding a private key — accumulate under /output indefinitely. Check
            /output ownership and permissions for the UID in `user:`.
      - alert: CertConverterOrphanRemovalDisabled
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |~ `orphan removal is disabled for this scan` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter cannot reap orphaned /output bundles"
          description: >
            The orphan walk could not enumerate /output completely, so this scan
            refused to delete anything: either a sub-path could not be read, or
            the tree contains a symlink (writes resolve through the output root
            and follow it, while the orphan walk does not, so the two disagree
            about where a bundle lives and a freshly written one would read as an
            orphan). Only relevant with `OUTPUT_LIFECYCLE=sync`, where it is the
            difference between "nothing to reap" and "reaping is off" — the two
            are otherwise indistinguishable, since refusing to delete is
            health-neutral and no other rule fires. A `.pfx` whose certificate
            was removed from /input therefore stays served indefinitely. Check
            /output ownership and permissions for the UID in `user:`, and mount
            the real output directory instead of linking to it.
```

Thresholds and the `severity` label are starting points; adjust the stall
window to your `FALLBACK_SCAN_HOURS` and the `container` selector to your
deployment, and route by whatever labels your Alertmanager uses.
`CertConverterScanStalled` assumes the fallback rescan is enabled: with
`FALLBACK_SCAN_HOURS` set to `0`/`false` there is no guaranteed `scan
complete` cadence at all (a scan then runs only on a filesystem event, and
certificates renew every few weeks), so that rule fires permanently instead
of reporting a wedged loop — drop it, exactly as the `health` probe drops its
staleness deadline in that configuration. Dropping it leaves no rule that can
report a wedged loop, and the probe has no deadline to fail either, so a
dropped `/input` watch goes undetected and the container stays healthy while
converting nothing (see [Healthcheck](#healthcheck)). Keep the fallback enabled
if you want either signal. The same applies at
`LOG_LEVEL=warn`/`error`, where the `scan complete` heartbeat is filtered out
of the logs entirely (see the prerequisite above): both conditions invalidate
the heartbeat rule. `CertConverterInputPathUnreachable`,
`CertConverterNoCertificatePairs`, `CertConverterOutputCleanupDegraded`, and
`CertConverterOrphanRemovalDisabled` are
the exceptions to the prerequisite: they key on WARN lines, so they work at
`debug`, `info`, or `warn` and are suppressed only at `error`.

## Healthcheck

The image bakes in a health probe. After each processing cycle with no conversion failures, the main process writes a marker file at `/tmp/.healthy`. The `health` subcommand (`/cert-watcher health`) exits 0 when the marker exists and, while the fallback rescan is enabled, is fresher than three `FALLBACK_SCAN_HOURS` intervals. A staler marker means the watch loop is wedged, so the probe fails and the container is reported `unhealthy`. Docker Engine does not act on health status by itself: an orchestrator that does (Swarm, Kubernetes) restarts the container, while under plain Docker Compose the `unhealthy` state is a signal to monitor — see the `CertConverterScanStalled` rule under [Alerting](#alerting) — and the restart is yours to perform.

Setting `FALLBACK_SCAN_HOURS` to `0`/`false` disables both the fallback and this staleness deadline, which leaves the watcher unsupervised. Nothing re-scans, and a dropped `/input` watch is invisible: unmounting or remounting that directory makes the kernel discard the watch without any filesystem event reaching the process, so the watcher can sit holding no watches while the last clean scan's marker keeps the container healthy indefinitely. It logs nothing in that state, so no alert rule can catch it either. Startup logs a WARN naming that tradeoff. The supervised choice is to leave the fallback enabled; turn it off only if you accept having no signal at all when conversion stops.

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

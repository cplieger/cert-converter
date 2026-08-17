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
| `PFX_PASSWORD` | Password embedded in generated PFX files. The container refuses to start when this is empty **or blank** unless `PFX_ALLOW_EMPTY_PASSWORD=true` is set. Blank means nothing an operator can read or retype: whitespace-only (a quoting slip in compose), or invisible characters only, such as a byte-order mark or a pasted zero-width space. It also refuses to start when the value cannot survive PKCS#12 encoding: a character outside the Basic Multilingual Plane (every conversion would fail), a byte sequence that is not valid UTF-8, or an embedded NUL (both would silently produce bundles no consumer can open with the configured secret). | - | Yes |
| `PFX_PASSWORD_FILE` | Path to a file holding the PFX password (Docker/Podman secret). When set it takes precedence over `PFX_PASSWORD`, keeping the secret out of the container environment and out of `docker inspect`; setting both logs a WARN naming which one is ignored. The file is read once, bounded at 1 MB, and delivered verbatim apart from at most one trailing line ending (the newline an editor or `kubectl create secret --from-file` appends), so whitespace you put inside or around the password stays part of it — exactly as it does for `PFX_PASSWORD`. A password with leading or trailing whitespace logs a WARN on either channel, because it is part of the password every consumer must reproduce. The path must already be in cleaned form and must not traverse, so `/run/secrets/../secrets/pfx` is refused even when it is readable, as are a redundant `//`, a `./` prefix and a trailing `/`. An **unusable** file (unreadable, oversized, or a rejected path) is a startup failure that `PFX_ALLOW_EMPTY_PASSWORD=true` does not rescue. A **blank** file (empty, whitespace-only, or holding only invisible characters such as a byte-order mark an editor added) is treated exactly like a blank `PFX_PASSWORD`: refused unless `PFX_ALLOW_EMPTY_PASSWORD=true`, so the opt-out means one thing however the secret is delivered. A configured file never falls back to `PFX_PASSWORD` in either case. | - | No |
| `PFX_ALLOW_EMPTY_PASSWORD` | Set to `true` to let the container start with a blank password, from either delivery channel. Generated PFX files then protect the embedded private key with an empty password (effectively no protection); not recommended. | `false` | No |
| `FALLBACK_SCAN_HOURS` | Hours between full directory re-scans, the fallback for fsnotify events missed on network mounts and similar edge cases. Only an explicit `0` or `false` disables it, which turns off re-scans **on your cadence** but not the app's own convergence: the watcher still reconciles the whole tree, and still refreshes the health marker, at least once every 24 hours, so a missed renewal is converted late rather than never and a wedged watcher is now reported unhealthy instead of staying up ([Healthcheck](#healthcheck) has the detail and the one behaviour change this brings to existing `0`/`false` deployments). Startup logs a WARN naming that latency tradeoff. An empty, whitespace, or invalid value uses the 6h default, so a blank never silently disables the safety net; a value above `87600` (10 years) is clamped to that ceiling, and any cadence above 24h is capped at the reconciliation floor in practice. An invalid or clamped value is reported by a WARN at startup only, never by the `health` subcommand, which reads the same setting on every healthcheck. | `6` | No |
| `PFX_ENCODER` | PFX encoding profile: modern2023 (AES-256-CBC + SHA-256, default), modern2026 (AES-256-CBC + PBMAC1, requires OpenSSL 3.4.0+), legacy (3DES + SHA-1 for older devices), or legacyrc2 (RC2-40 + SHA-1, a last-resort interop escape: a 40-bit RC2 key is brute-forceable, so the private key in such a bundle is protected only nominally; use it when a device accepts nothing else and treat the output as sensitive). `modern` is an alias for `modern2023`, and `legacy` is recorded as `legacydes` in startup logs. See the [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables). | `modern2023` | No |
| `OUTPUT_LIFECYCLE` | What happens to a `.pfx` whose certificate **and** private key have both been removed from `/input`. `warn` (default) logs the orphan and leaves the file in place; `sync` deletes it so `/output` tracks `/input`, after a short re-check (30 seconds later, once per scan) confirms both are still gone; `keep` is silent and never deletes. A bundle whose `<name>.key` is still there is kept and reported by its own WARN: a half-written or half-deleted pair is not proof the bundle is orphaned. Finish the change under `/input` (add the matching `<name>.crt`, or remove the leftover `<name>.key`) and the next scan reaps it. `sync` only ever removes files matching this app's own output shape, and it refuses to delete anything at all unless the scan proves it enumerated `/input` completely: at least one certificate found, the walk finished within `MAX_SCAN_ENTRIES`, and no unreadable path, unresolvable symlink, or conversion failure. A scan that cannot make that proof logs `orphan removal is disabled for this scan` and reaps nothing, so a broken or empty mount can never be read as "every certificate was deleted". Every scan that does delete something logs a WARN naming the count and a sample of the paths. An unrecognized value logs a WARN and uses `warn`. | `warn` | No |
| `MAX_SCAN_ENTRIES` | How many `/input` paths one scan enumerates before it stops without converting or removing anything further. The stop is a WARN naming the path it reached, and it leaves health alone, because no restart shrinks the tree; orphan cleanup is skipped for that scan. If your certificate tree is legitimately larger than the default, raise this **and** the container's memory limit together: one scan's memory grows with the total length of the paths it enumerates and not only with their number, so raising this alone can push the scan past a fixed memory limit, where it is killed and converts nothing at all. Where the memory limit cannot move, the two mitigations that do work are lowering this ceiling and `OUTPUT_LIFECYCLE=keep`, which returns before the output walk and so never builds the `/output` list. An empty, whitespace, invalid, zero, or negative value uses the `10000` default; a value above `200000` is clamped to that ceiling. Either repair is reported by a WARN at startup naming the value you set. There is deliberately no value that disables the budget. | `10000` | No |
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
every conversion and keeps the container unhealthy. The one exception is a bundle
this app could not read or verify at all, whose replacing write is then refused:
the refusal leaves the existing file in place, warns with the matching
remediation, and leaves health alone, since no restart grants the UID ownership
of the volume or frees a full one.

Generated `.pfx` files are mode `0600` and the directories this app creates are
`0750`, both owned by that UID, so whatever consumes them must run as the same
UID (or as a privileged process); group membership alone is insufficient because
mode `0600` grants no group read access. An output directory that is already more
permissive than `0750` is reported by a WARN naming its mode and then left exactly
as found: the bundle is still published and health is unaffected (a forced-mode
mount such as CIFS, NFS, or vfat cannot be chmod'ed at all). Tightening it is
yours to do, and worth doing: a group- or world-writable directory lets any other
process on that mount replace a bundle.

This app never `chmod`s anything it finds under `/output`, and never rewrites a
bundle in order to correct one either. A `.pfx` left more permissive than `0600`
— by an earlier deployment, or by whatever wrote it — is reported by a WARN
naming the mode found and the mode this app installs on files it writes, and is
then left exactly as found. The WARN repeats once per scan for as long as the
mode does, because nothing this app does will clear it: tightening the mode is
yours to do. The mode is corrected only when the bundle is next written for its
own reasons — the certificate renewed, or the app could not verify what was on
disk — where the atomic replacement lands a fresh file at `0600` for free. So a
bundle whose certificate keeps renewing settles at `0600` on its next renewal,
and one whose certificate never renews keeps the mode you left it with. A mode
you made _stricter_ than `0600` carries no extra bit and is left alone.

This is what comparable tools do: OpenSSH refuses an over-permissive private key
and never `chmod`s it, certbot warns about an over-permissive credentials file
and makes you fix it, and certbot's own key renewal applies its restrictive mode
to the new file it was writing anyway rather than rewriting an unchanged
certificate. Rewriting a bundle purely to correct its mode also cannot converge
on a mount that forces or ignores permission bits (CIFS/SMB forced mode, NFS
squash, vfat `fmask`): the replacement would land with the same lax mode and
every scan would rewrite the bundle the previous scan wrote, churning a fresh
mtime — and any downstream replication of `/output` — every cycle.

## Alerting

cert-converter has no metrics endpoint; its operational state is in its logs.
Ship the container's logs to Loki (Grafana Alloy's Docker log discovery does
this with no configuration) and evaluate these with
[Loki's ruler](https://grafana.com/docs/loki/latest/alert/); firing alerts
deliver through your Alertmanager exactly like Prometheus metric alerts.

Every rule below keys on a WARN or ERROR record, so they all work at
`LOG_LEVEL=warn` as well as at the `info` default (`error` suppresses all but
the two ERROR rules). No rule reports a wedged watch loop, because a healthy
scan is deliberately silent at `warn`: the container healthcheck covers that
case through the health marker's freshness deadline (see
[Healthcheck](#healthcheck)).

```yaml
groups:
  - name: cert-converter
    rules:
      - alert: CertConverterConversionFailed
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |~ `(conversion failed|failed to inspect existing pfx)`
            != `(shutdown)` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter failed to convert a certificate"
          description: >
            A PEM or key parse error, a cert/key mismatch, or a failed PFX write
            left the affected .pfx stale or missing, and the container is
            unhealthy until a scan converts everything cleanly. The
            `!= (shutdown)` filter drops the same messages when they were caused
            by the container stopping, which are logged at DEBUG. Check /output
            ownership and permissions for the UID in `user:`, that no symlink is
            planted at the output path, and the certificate chain.
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
            the container is unhealthy. Check the /input mount and its
            permissions.
      - alert: CertConverterInputTreeTooLarge
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |= `holds more entries than one scan will enumerate` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter stopped a scan at the /input entry budget"
          description: >
            The scan reached MAX_SCAN_ENTRIES (default 10000) and stopped, so
            every certificate past that point is unconverted and orphan cleanup
            was skipped for that scan. Health is unaffected, because no restart
            shrinks the tree, which makes this rule the only signal. Check that
            /input is mounted at the certificate directory and holds nothing
            else; if the tree is legitimately this large, raise
            MAX_SCAN_ENTRIES and the container's memory limit together,
            because one scan's memory grows with the total length of the paths
            it enumerates and not only with their number.
      - alert: CertConverterChangeDetectionDegraded
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |= `change detection scan` |= `mode=poll` [8h]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter is polling instead of watching for changes"
          description: >
            No fsnotify watch could be established, so change detection has
            fallen back to a full rescan every FALLBACK_SCAN_HOURS (default 6h,
            capped at the 24h reconciliation floor) and a renewal now waits that
            long to convert. Every poll-mode scan
            repeats this record, so the alert stands for as long as the
            degradation does; recovery is logged as `fsnotify recovered,
            upgrading from poll to watch`. Health is unaffected: a poll scan
            refreshes the marker exactly like a watch scan. Exhausted inotify
            instances on the host are the usual cause. Match the window to your
            FALLBACK_SCAN_HOURS.
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
            exited non-zero to be restarted, and its `error` field names which
            loss occurred: fsnotify's channels closed under a live container, or
            the root watch was removed, or fsnotify was unavailable at all, the
            last two only while FALLBACK_SCAN_HOURS is 0/false, where a restart
            re-attaches a watch in seconds and the alternative is an entirely
            unwatched tree until the next reconciliation. Critical rather than
            warning: with no restart
            policy the container stays down and every renewal is silently
            missed. Ensure the deployment restarts it
            (`restart: unless-stopped`), and if the record carries a
            `remediation` field naming FALLBACK_SCAN_HOURS, unset it or set it
            above 0 so the periodic rescan covers or re-attaches the missing
            watch. Exhausted inotify instances on the host are the usual root
            cause and are often transient.
      - alert: CertConverterInputPathUnreachable
        expr: |
          sum by (container) (count_over_time(
            {container="cert-converter"}
            |~ `(some /input paths were unreadable and were skipped|skipping symlink that could not be resolved through the input root|skipping cert: cannot stat sibling key|skipping cert: cannot read)` [15m]
          )) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "cert-converter skipped an unreachable /input path"
          description: >
            An /input path could not be read, stat'ed, or resolved, so the
            certificates it holds were not converted and their .pfx files stay
            stale or absent. Health is unaffected, because no restart clears a
            permissions or layout condition, which makes this rule the only
            signal. Repair the permissions for the UID in `user:`, and mount the
            certificate directory directly instead of linking to it.
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
            sibling `<name>.key`, so no PFX is produced at all. This is the
            signature of a wrong or vanished /input mount, of a certbot-style
            directory of fullchain.pem/privkey.pem this app does not read, or of
            a key-naming layout that does not match the `<name>.key` contract.
            Health is unaffected, so this rule is the only signal. Check the
            /input mount and the .crt/.key filename contract. A fresh deployment
            legitimately reports this until the first issuance; raise `for:` if
            that is noisy.
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
            or unlink temp files left behind by an interrupted atomic write, or
            could not enter an /output sub-path. Conversions may still succeed,
            so health is unaffected, while `.atomicfile-*.tmp` files, each
            holding a private key, accumulate under /output indefinitely. Check
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
            This scan could not prove an output bundle is orphaned, so it deleted
            nothing: /input was not fully enumerated, or an /output sub-path could
            not be read, or the output tree contains a symlink, so the orphan walk
            could not enumerate all of it, or either tree holds more entries than
            MAX_SCAN_ENTRIES lets one walk enumerate. Only relevant with
            `OUTPUT_LIFECYCLE=sync`, where it is the difference between "nothing
            to reap" and "reaping is off", otherwise indistinguishable because
            health is unaffected: a `.pfx` whose certificate was removed from
            /input stays served indefinitely. The record's own `remediation`
            field names the action for the case that fired.
```

Thresholds and the `severity` label are starting points; adjust the
`container` selector to your deployment, match the degradation window to your
`FALLBACK_SCAN_HOURS`, and route by whatever labels your Alertmanager uses.

Two `OUTPUT_LIFECYCLE=sync` conditions are worth querying without a rule of
their own: `removed output bundles whose input certificates are gone` audits
each scan's deletions with a count and a sample of the paths, and `keeping an
output bundle whose certificate is gone but whose private key is still in
/input` names a half-deleted pair whose bundle is kept until you finish the
change. Nothing keys on `cert input observation`: an ACME `fullchain.pem` from
Caddy or certbot deliberately omits the root certificate, so that normal shape
is reported at INFO (`kind=chain-trust-anchor-absent`), and only the WARN-level
observations name input a consumer is likely to reject.

## Healthcheck

The image bakes in a health probe. After each processing cycle with no conversion failures, the main process writes a marker file at `/tmp/.healthy`. The `health` subcommand (`/cert-watcher health`) exits 0 when the marker exists and is fresher than three times the app's guaranteed re-scan cadence — three `FALLBACK_SCAN_HOURS` intervals on the default, and three 24h reconciliation intervals when that setting is `0`/`false` or above 24h. A staler marker means the watch loop is wedged, so the probe fails and the container is reported `unhealthy`. Docker Engine does not act on health status by itself: an orchestrator that does (Swarm, Kubernetes) restarts the container, while under plain Docker Compose the `unhealthy` state is a signal to monitor and the restart is yours to perform. The startup line reports both numbers: `fallback_scan` is your cadence (or `disabled`), `scan_floor` is the guaranteed one the deadline is derived from.

Setting `FALLBACK_SCAN_HOURS` to `0`/`false` turns off re-scans on **your** cadence, not the app's convergence. fsnotify events are a latency optimisation here, not the liveness mechanism: one watch-set walk enumerates at most `MAX_SCAN_ENTRIES` paths, so a tree larger than that is watched only in part; the kernel refuses a watch outright once the host's `fs.inotify.max_user_watches` quota is spent (that directory is logged with the remediation and skipped); and the kernel can discard an `/input` watch without any filesystem event reaching the process — unmounting or remounting that directory does exactly that. So the watcher keeps two schedules that this setting cannot switch off. Watch-set repair runs on its own bounded schedule, at most once a minute, so a registration dropped silently is restored without a certificate scan. And a full reconciliation — re-assert the whole watch set, then scan the whole tree — runs whenever nothing else has scanned for 24 hours, which is also what keeps the health marker fresh. A renewal whose event was lost is therefore converted late rather than never: 24 hours is well inside the ~30-day margin an ACME issuer leaves before expiry, and the cadence is deliberately four times slower than the 6h default because an operator who disables the fallback is usually escaping expensive walks on a network mount. Any scan re-arms the timer, so an active deployment never pays for a reconciliation walk at all.

**This changes behaviour for existing `0`/`false` deployments in one way:** the marker now has a freshness deadline in this mode (72 hours), so a wedged watcher that used to keep reporting healthy indefinitely is now reported `unhealthy` and can be restarted by an orchestrator that acts on health. Turn the fallback off if you want renewals recovered on the reconciliation floor rather than on your own cadence; the tradeoff is latency on a missed event, not silence.

Health answers one question: should an orchestrator restart this container? It therefore tracks only failures a restart could plausibly clear. The container becomes **unhealthy** when the `/input` root itself cannot be read or a certificate fails to convert (PEM or key parse error, cert/key mismatch, or PFX write failure). It **auto-recovers** on the next clean cycle (an fsnotify event, or the next periodic re-scan) without a restart.

An unreadable _sub-path_ under `/input` (e.g. one certificate directory with the wrong permissions or owner) is a steady-state misconfiguration a restart would not fix, so it is logged as a warning, its certificates are skipped, and health is left alone. Four other conditions are reported the same way, each naming what to act on in the record — an explicit `remediation` for three of them, and for a lax `.pfx` the mode found beside the mode this app installs: an `/input` tree holding more entries than `MAX_SCAN_ENTRIES` (that scan stops early and skips orphan cleanup), an `/output` directory more permissive than `0750`, a `.pfx` more permissive than `0600`, and a refused replacement of a bundle this app could not read or verify at all.

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
| github.com/cplieger/atomicfile/v2  | [GitHub](https://github.com/cplieger/atomicfile)                 |
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

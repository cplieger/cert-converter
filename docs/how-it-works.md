# How cert-converter works

This page describes how cert-converter finds certificates, notices renewals, names its output and reports health. It is for readers who want to know why it behaves as it does, or who are tracing a problem.

## Finding certificates

A scan walks the whole `/input` tree. It pairs each `<name>.crt` with the `<name>.key` beside it, and once an input password is set it also picks up `<name>.pfx` and `<name>.p12` bundles. A `.crt` with no matching `.key` is skipped and reported, not treated as an error. Each input file is read once, and the same bytes feed both the conversion and the change check.

Each PFX output holds the private key, the certificate and the chain of issuing certificates from its source, whether that source is a PEM pair or a bundle. RSA, ECDSA, Ed25519 and ML-DSA keys are all supported.

## Noticing renewals

cert-converter watches `/input` for file changes and starts a scan about two seconds after the last change it sees. A full recheck also runs every `FALLBACK_SCAN_HOURS`, 6 hours by default, to catch any change the watcher missed on a network mount or after a remount. Whatever that setting says, a full recheck runs at least once every 24 hours.

When no file watch can be set up, cert-converter falls back to polling with a full recheck on that cadence, and it keeps trying to return to watching. The usual cause is the host running out of inotify instances.

## Deciding what to rewrite

Each scan reads the file already at the output path and checks whether it is the one the current inputs produce. Unchanged certificates cause no write, so output timestamps change only when the content does. Because the check reads the output itself rather than a state file, a changed `PFX_PASSWORD` or `PFX_ENCODER` is picked up on the next scan. Every write goes to a temporary file first and is then renamed into place, so an app never reads a half-written file.

## Output names

By default an output is named after the certificate's own folder, not after the issuing CA's folder above it. Caddy, for example, keeps `<issuer>/<site>/<site>.crt`, and cert-converter writes `<site>/<site>.pfx`. Apps keep working when the issuer changes. `OUTPUT_LAYOUT=mirror` keeps the full path instead.

When two inputs would produce the same output name, cert-converter converts neither and turns the container unhealthy. Picking one would publish one certificate under another's name, so it leaves the choice to you. [Configuration](configuration.md#output-formats-and-layout) has the details.

## Health

After each scan with no conversion failure and no output-name collision, the main process writes a marker file at `/tmp/.healthy`. The `health` subcommand passes while that marker exists and is fresher than three times the guaranteed recheck cadence. That is 18 hours on the 6-hour default, and 72 hours when `FALLBACK_SCAN_HOURS` is `0`, `false` or above 24, because the 24-hour floor applies then. A staler marker means the watch loop is stuck. The startup line reports both numbers, `fallback_scan` for your cadence or `disabled`, and `scan_floor` for the guaranteed one the deadline comes from.

A restart clears the marker until the first scan completes. That scan reads every output back and rewrites only the ones that no longer match their source, so a restart costs one read pass and no writes.

The container is unhealthy when any of these holds:

- The `/input` root cannot be read. That includes `/input` and `/output` being the same folder, or one being inside the other.
- A certificate fails to convert. The causes are a PEM or key parse error, a PFX decode failure, a certificate that does not match its key, and a failed write.
- Two inputs collide on one output name under the flat layout.

It recovers on the next clean scan without a restart. Docker Engine does not act on health status itself. An orchestrator that does, such as Swarm or Kubernetes, restarts the container, and under plain Docker Compose the restart is yours to do. A collision is the one unhealthy state a restart never clears. It is deliberate, because nothing else tells an orchestrator that an app is reading a file cert-converter refuses to update.

Health tracks only failures a restart can clear, plus that one exception. These conditions are logged at WARN with the action to take and leave health unchanged:

- An unreadable path below `/input`, or a symlink that points outside the mount.
- An `/input` tree larger than `MAX_SCAN_ENTRIES`.
- An `/output` folder more permissive than `0750`, or a file more permissive than `0600`.
- A refused replacement of an output cert-converter could not read or verify.
- Files kept from a previous `OUTPUT_LAYOUT`.
- An `INPUT_EXCLUDE_PATHS` value that covers every source found.

[Monitoring and alerts](monitoring.md) has an alert rule for each of them except the two permission warnings, which appear only in the log.

## Design choices

- The image has no shell or package manager and runs as a non-root user.
- It opens no port. Health is a file the probe reads, so nothing listens on the network.
- The file watcher reacts within seconds, and the periodic recheck covers network mounts and missed events, so a renewal is never skipped.
- Output names follow the certificate's folder rather than the issuer's storage layout, so apps keep working across an issuer change.
- An ambiguous output name converts nothing and turns the container unhealthy, rather than cert-converter guessing which certificate you meant.
- The change check reads the output on disk instead of a state file, so writes happen only when the content changes and file timestamps stay meaningful.

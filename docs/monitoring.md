# Monitoring and alerts

This page describes what cert-converter logs and the alert rules that ship with it. It is for readers who collect container logs and want to be told when a certificate stops converting.

## Logs

cert-converter has no metrics endpoint, and its state is in its logs. It writes plain-text `log/slog` records to standard error, with every timestamp in UTC.

- `starting cert watcher` opens each start and lists the settings in use, the user the container runs as, and both scan cadences as `fallback_scan` and `scan_floor`.
- `wrote pfx` and `wrote pem` name each file written.
- `scan complete` closes every scan, including one that found nothing to convert. It carries the counts `total`, `converted`, `unchanged`, `orphan`, `unreadable`, `unresolved`, `vanished`, `unwritable`, `collided`, `excluded`, `ignored`, `removed` and `failed`.
- Look for a `remediation` field on warnings and errors. When present, it names the action to take.

## Alerting

Ship the container's logs to Loki and load the rules in [`alerts/logql.yaml`](../alerts/logql.yaml) into [Loki's ruler](https://grafana.com/docs/loki/latest/alert/). Grafana Alloy's Docker log discovery ships the logs with no extra configuration, and firing alerts go through your Alertmanager like any Prometheus alert. They cover:

| Alert | Fires when | Severity |
| --- | --- | --- |
| `CertConverterConversionFailed` | a parse error, a failed PFX decode, a cert/key mismatch or a failed write left a requested file stale or missing | warning |
| `CertConverterOutputNameCollision` | two inputs claim the same flat output name, so none of them converts and the container stays unhealthy until you resolve it | warning |
| `CertConverterOutputWriteRefused` | an `/output` condition no restart clears refused a write, so a stale file is left as found | warning |
| `CertConverterScanAborted` | the `/input` root itself could not be walked, so the scan returned early | warning |
| `CertConverterInputTreeTooLarge` | a scan stopped at `MAX_SCAN_ENTRIES`, so every certificate past that point is unconverted | warning |
| `CertConverterChangeDetectionDegraded` | no file watch could be set up, so a renewal waits for the next full recheck | warning |
| `CertConverterChangeDetectionDead` | the watch loop ended for a reason other than shutdown, and the process exited for a restart | critical |
| `CertConverterInputPathUnreachable` | an `/input` path could not be read or resolved, so its certificates were skipped | warning |
| `CertConverterNoCertificateSources` | a scan found neither a complete PEM pair nor a PFX or P12 bundle, so no output is produced at all | warning |
| `CertConverterEverySourceExcluded` | `INPUT_EXCLUDE_PATHS` covers every source found, so the scan converted nothing | warning |
| `CertConverterOutputCleanupDegraded` | leftover temporary files under `/output`, each holding a private key, cannot be removed | warning |
| `CertConverterOrphanRemovalDisabled` | a scan could not prove a file is orphaned, so `OUTPUT_LIFECYCLE=sync` removed nothing | warning |
| `CertConverterPreviousLayoutRetained` | `sync` found files from a previous `OUTPUT_LAYOUT` and kept them, because the layout is not set explicitly | warning |
| `CertConverterScanStalled` | no `scan complete` record in 8 hours, so the watch loop is stuck, silent or shipping no logs | warning |

Every rule but one keys on a WARN or ERROR record, so it works at `LOG_LEVEL=warn` as well as at the `info` default. `CertConverterScanStalled` reports a stuck watch loop, and it can only do that by keying on the `scan complete` record. That record is logged at `info`, because a healthy scan has nothing to report at `warn`. So that one rule needs the `info` default and fires permanently at `LOG_LEVEL=warn`. Drop it if you run at `warn`.

The container healthcheck covers the same failure without needing the `info` level, through the health marker's freshness deadline, but only where something acts on an unhealthy container.

Size the `CertConverterScanStalled` window above the guaranteed recheck cadence. An 8-hour window fits the 6-hour default. When `FALLBACK_SCAN_HOURS` is `0`, `false` or above 24, the guarantee is the 24-hour floor. An 8-hour window then fires for most of every day, so use 30 hours there.

Thresholds and the `severity` labels are starting points. Adjust the `container` selector to your deployment, and match the degradation window to your `FALLBACK_SCAN_HOURS`. Route by whatever labels your Alertmanager uses.

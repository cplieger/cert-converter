# Monitoring and alerts

This page lists what cert-converter reports, the alert rules that ship with it, and how to know the container is alive. It is for readers who want to be told when a certificate stops converting. cert-converter writes one `scan complete` record to its log after every scan. Set `METRICS_LISTEN_ADDR` and it also serves a metrics page, with metric alert rules in `alerts/promql.yaml`. If you run Loki and no Prometheus, `alerts/logql.yaml` gives you the same alerts from the log.

## What you get

| You run | You get | You set up |
| --- | --- | --- |
| Prometheus, Mimir or VictoriaMetrics, with Alertmanager (the monitoring guide's starting stack adds Loki) | 14 alerts, including `CertConverterDown`, plus `up` and graphs | `METRICS_LISTEN_ADDR`, a scrape job named `cert-converter`, and [`alerts/promql.yaml`](../alerts/promql.yaml) |
| Loki and Alertmanager, no metric store | 15 alerts, including one for a refused start | [`alerts/logql.yaml`](../alerts/logql.yaml) on Loki's ruler, with `LOG_LEVEL` at `info` |
| Grafana-managed alerting only | The same rules, imported into Grafana | A Prometheus or Loki data source, and one of the two rule files |
| Docker or Unraid only | Docker health, and the log | An uptime prober on `/healthz` with `METRICS_LISTEN_ADDR` set, or something that watches Docker health |

## Metrics

The metrics page is off by default, and the container then opens no port. Set `METRICS_LISTEN_ADDR` to a listen address, for example `:9468`, and cert-converter serves `GET /metrics` on it. [Reaching an app's metrics page](https://github.com/cplieger/docs/blob/main/docs/monitoring.md#reaching-an-apps-metrics-page) shows how to let your scraper reach it. The page has no login, so keep the port on your network. Name the scrape job `cert-converter`, because `CertConverterDown` reads `up{job="cert-converter"}`.

Each scan sets the scan series from the same verdict it writes to the `scan complete` record. The labels carry only the values listed below, never a path.

| Series | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `cert_converter_last_scan_sources` | gauge | `outcome`: `converted`, `unchanged`, `orphan`, `unreadable`, `unresolved`, `vanished`, `unwritable`, `collided`, `excluded`, `ignored`, `failed` | Sources at each outcome in the last scan |
| `cert_converter_last_scan_sources_found` | gauge | none | Sources the last scan found under `/input` |
| `cert_converter_last_scan_timestamp_seconds` | gauge | none | Unix time the last scan ended, `0` before the first one |
| `cert_converter_last_scan_outcome` | gauge | `outcome`: `complete`, `aborted`, `budget_stopped` | `1` for how the last scan ended, `0` for the others |
| `cert_converter_change_detection_mode` | gauge | `mode`: `watch`, `poll` | `1` for the mode the last scan ran in, `0` for the other |
| `cert_converter_condition` | gauge | `condition`: `no_sources`, `all_excluded`, `orphan_removal_disabled`, `previous_layout_retained`, `cleanup_degraded` | `1` while the last scan reported the condition |
| `cert_converter_removed_artifacts_total` | counter | none | Outputs removed because their source is gone |
| `cert_converter_scan_deadline_timestamp_seconds` | gauge | none | Unix time by which the next healthy scan is due: the end of the last healthy scan, or the start, plus three guaranteed recheck cadences, 18 hours at the default. A scan that leaves the container unhealthy leaves it where it was. This version never sets it to `0` |
| `cert_converter_build_info` | gauge | `version` | Always `1`. `version` is the release the image was built from |

Every labelled scan series starts at `0`, so each rule sees its series from the first scrape. The page also carries the Go runtime and process families (`go_*`, `process_*`) under the names Go's official Prometheus client uses, so stock Go dashboards work.

Three queries to start with in Grafana's Metrics Drilldown:

- `time() - cert_converter_last_scan_timestamp_seconds` is how long ago the last scan ended.
- `cert_converter_last_scan_sources{outcome=~"converted|unchanged"}` is how many certificates are current.
- `increase(cert_converter_removed_artifacts_total[1d])` is how many outputs `OUTPUT_LIFECYCLE=sync` removed in a day.

## Logs

cert-converter writes logfmt records to standard error, with every timestamp in UTC. Go renders the level in capitals, such as `level=WARN`.

- `starting cert watcher` opens each start and lists the settings in use, the user the container runs as, and both scan cadences as `fallback_scan` and `scan_floor`.
- `wrote pfx` and `wrote pem` name each file written.
- A standing problem, such as an unreadable path, is logged once when it appears, again when its count changes, once when it clears and once after each restart. The clearing record is `standing condition cleared`, with the `condition` and how long it `lasted`.
- Three records follow the same rule for each path they name, and carry a `condition` field. `conversion failed` is `conversion_failed`, an ERROR for each source, logged again when its cause changes. The permission WARNs are `permissive_output_dir` for an `/output` folder and `permissive_output_file` for an output file, logged again when the mode changes. While one holds, later scans log it at Debug. It clears when a scan of the whole tree no longer finds it, or, for an output file, when cert-converter writes the file again.
- With `METRICS_LISTEN_ADDR` set, each request to the listener writes an `http` record: at Debug for `/metrics` and `/healthz`, and at `INFO` for any other path.
- Look for a `remediation` field on warnings and errors. When present, it names the action to take.

`scan complete` closes every scan that is not cut short by a shutdown. It is `INFO` when the scan covered the whole tree, and `WARN` when the scan aborted or stopped at `MAX_SCAN_ENTRIES`, with an `error` field on an abort. The log rules read this record at either level, so keep `LOG_LEVEL` at `info` if you use them. Every field except `error` is a number.

| Field | Meaning |
| --- | --- |
| `total` | PEM pairs, bundles and orphan `.crt` files the scan classified, whatever their outcome, except those listed below the table |
| `converted`, `unchanged` | Sources written this scan, and sources whose output already matched |
| `orphan` | `.crt` files with no `.key` beside them |
| `unreadable`, `unresolved` | Paths that could not be read, and symlinks that could not be resolved |
| `vanished` | Paths that disappeared during the scan |
| `unwritable` | Outputs left as found because a write was refused |
| `collided` | Sources that share a flat output name with another source |
| `excluded`, `ignored` | Sources under `INPUT_EXCLUDE_PATHS`, and bundles skipped while bundle input is off |
| `removed` | Outputs removed this scan because their source is gone |
| `failed` | Sources that failed to convert |
| `aborted`, `budget_stopped` | `1` when the scan ended early, or stopped at `MAX_SCAN_ENTRIES` |
| `polling` | `1` when the scan ran in poll mode instead of watching for changes |
| `no_sources`, `all_excluded` | `1` when the scan found no source at all, or found sources and excluded every one |
| `orphan_removal_disabled` | `1` when `OUTPUT_LIFECYCLE=sync` could not prove an output orphaned, so it removed nothing |
| `previous_layout_retained` | `1` when `sync` kept files from a previous `OUTPUT_LAYOUT` |
| `cleanup_degraded` | `1` when leftover temporary files under `/output` could not be removed |

`total` leaves out a bundle skipped while bundle input is off and a bundle a higher-precedence sibling shadows. It also leaves out paths the walk could not enter: an unreadable entry, a vanished entry and an unresolved symlink. A directory standing where a source file should be is not in `total` either, though the scan still counts the sources inside it.

A scan that did not see the whole tree cannot prove a problem gone, so its record keeps what the previous scan reported.

- When the scan aborted or stopped at `MAX_SCAN_ENTRIES`, the counts `orphan`, `unreadable`, `unresolved`, `unwritable`, `collided` and `failed` stay at least at the previous scan's values. So do `orphan_removal_disabled` and `previous_layout_retained`.
- When the scan aborted, stopped at `MAX_SCAN_ENTRIES`, or finished its walk but left an unreadable path, an unresolved symlink or a vanished path, two values carry over from the previous scan. `no_sources` keeps the previous value unless this scan's `total` is greater than its `orphan` count. `all_excluded` keeps the previous value unless this scan's `excluded` count is below its `total`.
- The next scan that covers the whole tree resets every value.

An aborted scan turns the container unhealthy. So does a failed conversion or a name collision, including a `failed` or `collided` count carried through a stop at `MAX_SCAN_ENTRIES`. The other carried values leave health unchanged.

## Alerting

Load [`alerts/promql.yaml`](../alerts/promql.yaml) or [`alerts/logql.yaml`](../alerts/logql.yaml), not both. They hold the same alerts under the same names. Loading both sends each alert twice, under different labels. [Loading metric alert rules](https://github.com/cplieger/docs/blob/main/docs/monitoring.md#loading-metric-alert-rules) and [Loading an app's alert rules](https://github.com/cplieger/docs/blob/main/docs/monitoring.md#loading-an-apps-alert-rules) show how.

Three alerts exist in one file only. `CertConverterStartupRefused` and `CertConverterChangeDetectionDead` are log rules only, because the process exits and leaves no series to read. In `alerts/promql.yaml`, `CertConverterDown` covers both. `CertConverterDown` is a metric rule only, and in `alerts/logql.yaml` `CertConverterScanStalled` covers it.

Every state alert reads the last scan. It fires at the first scan that sees the problem and holds while the problem lasts. It resolves at the next scan that does not see it.

| Alert | Fires when | Severity |
| --- | --- | --- |
| `CertConverterDown` | nothing has scraped the metrics page for 5 minutes, because the container is down or the scrape cannot reach it | critical |
| `CertConverterStartupRefused` | a setting is invalid or a mount is missing or unreadable, so the process exited before its first scan | critical |
| `CertConverterConversionFailed` | the last scan could not convert a source, so its output is stale or missing and the container is unhealthy | warning |
| `CertConverterOutputNameCollision` | two inputs claim the same flat output name, so none of them converts and the container is unhealthy | warning |
| `CertConverterOutputWriteRefused` | an `/output` condition no restart clears refused a write, so a stale file is left as found | warning |
| `CertConverterScanAborted` | the last scan ended early, usually because `/input` or `/output` could not be opened or walked | warning |
| `CertConverterInputTreeTooLarge` | the last scan stopped at `MAX_SCAN_ENTRIES`, so every certificate past that point is unconverted | warning |
| `CertConverterChangeDetectionDegraded` | the last scan ran in poll mode. It clears on the first scan with a working file watch | warning |
| `CertConverterChangeDetectionDead` | the watch loop ended for a reason other than shutdown, and the process exited for a restart | critical |
| `CertConverterInputPathUnreachable` | the last scan could not read an `/input` path or resolve a symlink, so its certificates were skipped | warning |
| `CertConverterNoCertificateSources` | the last scan found neither a complete PEM pair nor a PFX or P12 bundle, so no output is produced | warning |
| `CertConverterEverySourceExcluded` | `INPUT_EXCLUDE_PATHS` covers every source found, so the scan converted nothing | warning |
| `CertConverterOutputCleanupDegraded` | leftover temporary files under `/output`, each holding a private key, cannot be removed | warning |
| `CertConverterOrphanRemovalDisabled` | the last scan could not prove a file is orphaned, so `OUTPUT_LIFECYCLE=sync` removed nothing | warning |
| `CertConverterPreviousLayoutRetained` | `sync` found files from a previous `OUTPUT_LAYOUT` and kept them, because the layout is not set explicitly | warning |
| `CertConverterScanStalled` | in `alerts/promql.yaml`, no scan has left the container healthy by `cert_converter_scan_deadline_timestamp_seconds` plus 15 minutes, so the watch loop is stuck or scans keep failing. In `alerts/logql.yaml`, no scan has finished in 13 hours, so the watch loop is stuck or the log stopped arriving | warning |

Thresholds and the `severity` labels are starting points. Every state alert in `alerts/logql.yaml`, and `CertConverterScanStalled` there, reads a 13-hour window, which fits the 6-hour default of `FALLBACK_SCAN_HOURS`. Size it to twice your effective cadence plus an hour. The effective cadence is `FALLBACK_SCAN_HOURS` capped at 24 hours, or 24 hours when it is `0` or `false`, so the window is 49 hours at most. `CertConverterStartupRefused` and `CertConverterChangeDetectionDead` count their exit line over 15 minutes, which does not depend on the cadence. Change the `container` selector to the label your log collector sets, such as `job` or `service`, and keep the scrape job name `CertConverterDown` reads.

`CertConverterScanStalled` in `alerts/promql.yaml` has two arms, and `cert_converter_scan_deadline_timestamp_seconds` picks one. While the deadline is above `0`, the alert fires 15 minutes after it passes. That covers a stuck watch loop, a first scan that never ends, and scans that keep failing, which also fire their own alerts. cert-converter works the deadline out from `FALLBACK_SCAN_HOURS`, so this arm has no window to change. While the deadline reads `0`, the alert fires when no scan has ended for 13 hours. This version never writes `0`, so the deadline arm always decides. Load the rule file of the release you run, since an older image serves no deadline and neither arm can fire.

Notes on individual alerts:

- `CertConverterOutputNameCollision` fires under `OUTPUT_LAYOUT=flat`, the default, when two inputs share their last directory and file name. cert-converter does not pick a winner. The `output name collision` record carries the shared output name, the number of claimants and a sample of them. `OUTPUT_LAYOUT=mirror` keeps each source's full path, so names cannot collide.
- `CertConverterOutputWriteRefused` covers a write that cert-converter refused because it could not read the file already at that path. The cause is ownership, the output layout, a volume that will not take the bytes, or a volume that will not keep the new file at mode 0600. Health stays unaffected on purpose, because no restart changes an `/output` layout or its permissions. `CertConverterConversionFailed` covers a refused write only where the file on disk was proven wrong.
- `CertConverterInputTreeTooLarge` also means orphan cleanup was skipped for that scan. `MAX_SCAN_ENTRIES` defaults to 10000. Raise the memory limit with it, because one scan's memory grows with the total length of the paths it lists, as well as with their number.
- `CertConverterChangeDetectionDegraded` holds while polling lasts. Leaving poll mode is logged as `fsnotify recovered, upgrading from poll to watch`, with how long polling lasted. A poll scan refreshes the health marker like a watch scan, so health is unaffected. Exhausted inotify instances on the host are the usual cause.
- `CertConverterChangeDetectionDead` records one of three losses in its `error` field. The fsnotify channels closed under a live container, the root watch was removed, or fsnotify was unavailable. The last two end the process only while `FALLBACK_SCAN_HOURS` is `0` or `false`, where a restart attaches a new watch in seconds. Otherwise the periodic recheck covers the tree. It is critical because, without a restart policy, the container stays down and every renewal is missed. If its `remediation` field names `FALLBACK_SCAN_HOURS`, unset it or set it above 0.
- `CertConverterScanStalled` is the deadman. A wedged watch loop logs nothing and moves no series, so it trips no other rule. The log rule cannot tell a stuck loop from a stopped container or a stopped log pipeline, so rule those out first. The metric rule also fires when the first scan after a start never ends.
- `CertConverterInputPathUnreachable` fires when a path could not be read, checked with stat or resolved. Health is unaffected because no restart clears a permissions or layout condition.
- `CertConverterNoCertificateSources` usually means a wrong or missing `/input` mount, an unsupported naming layout, or `.crt` files without a sibling `.key`. A fresh deployment reports it until the first certificate is issued. Raise `for:` if that is noisy.
- `CertConverterEverySourceExcluded` has no other signal, because the scan counts look like a healthy steady state. The exclusion removes nothing from `/output`.
- `CertConverterOutputCleanupDegraded` fires when the temporary-file sweep stopped at the `/output` root, could not inspect or remove a file left by an interrupted write, or could not enter an `/output` sub-path.
- `CertConverterOrphanRemovalDisabled` tells "nothing to remove" apart from "removal is off" under `OUTPUT_LIFECYCLE=sync`. A scan cannot prove a file is orphaned when `/input` was not fully listed, at scan time or at the check just before deletion. The same holds when an `/output` sub-path could not be read, the output tree holds a symlink, either tree exceeds `MAX_SCAN_ENTRIES`, or an output name collision left the tree ambiguous.
- `CertConverterPreviousLayoutRetained` fires because the unset `OUTPUT_LAYOUT` default never deletes a tree an earlier configuration wrote, since a consumer may still mount those paths. Setting `OUTPUT_LAYOUT` explicitly lets `sync` remove the old tree.

## Knowing the app is alive

| Route | Method | Port | Login | Answers |
| --- | --- | --- | --- | --- |
| `/healthz` | `GET`, `HEAD` | `METRICS_LISTEN_ADDR`, only when it is set | none | `200 {"status":"ok"}`, or `503 {"status":"unhealthy","reasons":[...]}` |
| `/metrics` | `GET` | the same port | none. Keep the port on your network | Prometheus text format |

**What healthy means.** The last scan read `/input`, converted every source and found no output name collision, and it finished within three guaranteed recheck cadences. That is 18 hours at the 6-hour default, and 72 hours when the 24-hour floor applies. Until the first scan after a start finishes, the answer is `503`. Each failing check adds one sentence to `reasons`. Problems a restart cannot fix, such as an unreadable path below `/input`, leave health unchanged and show on `/metrics` and in the log. [How cert-converter works](how-it-works.md#health) lists them.

**Docker health.** The image checks itself every 30 seconds with `/cert-watcher health`, which reads the health file the app refreshes after each clean scan at `/dev/shm/cert-converter.healthy`. If that file cannot be written, the check passes and the log says so once, while `/healthz` on the metrics listener still gives the true answer. Docker marks the container unhealthy after 3 failures, and allows 15 seconds after a start. Docker's health status notifies nobody on its own, and Docker does not restart an unhealthy container.

**Who is told.**

| You run | A dead app | A wedged app |
| --- | --- | --- |
| Prometheus with these rules | `CertConverterDown` | `CertConverterScanStalled`, and `/healthz` turns `503` |
| Loki only | `CertConverterStartupRefused` or `CertConverterChangeDetectionDead` when it exits with an error, then `CertConverterScanStalled` | `CertConverterScanStalled` |
| Docker or Unraid only | an uptime prober on `/healthz`, or something that watches Docker health | the same |

**Probing from outside.** With `METRICS_LISTEN_ADDR` set, check `GET http://<host>:<port>/healthz` on its port and pass on status 200 only. Do not match the body. Use a 5-second timeout, check every 60 seconds, alert after 3 failures, and wait 15 seconds after a first start. A Kubernetes liveness probe that must ignore readiness uses a `tcpSocket` probe on the port. With `METRICS_LISTEN_ADDR` unset, the app opens no port, so nothing outside the container can probe it. Watch Docker health, or set `METRICS_LISTEN_ADDR` and probe its `/healthz`.

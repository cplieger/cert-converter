# Contributing to cert-converter

Notes on the layout, local workflow, and conventions specific to this
repo. Most of it is standard Go, but a few things are easy to trip over.

## What this is

A watcher daemon that converts PEM certificate/key pairs to PFX/PKCS#12
whenever they change on disk. There is no HTTP server and no open port;
the only runtime surfaces are the `/input` (read-only) and `/output`
volumes plus a file-based health marker.

Note the name split: the repo and image are `cert-converter`, but the Go
module and built binary are `cert-watcher` (`module
github.com/cplieger/cert-converter` in `go.mod`). Build output and the
`health` subcommand both use the `cert-watcher` name.

## Package layout

`main.go` is wiring only: load config, build the scanner, run an initial
scan, then hand off to the watcher. The real work lives under
`internal/`:

- `internal/config`: parses `PFX_PASSWORD` (or `PFX_PASSWORD_FILE`, via
  `envx.Secret`), `PFX_ALLOW_EMPTY_PASSWORD`, `PFX_ENCODER`,
  `FALLBACK_SCAN_HOURS`, `MAX_SCAN_ENTRIES`, and `LOG_LEVEL` (via
  `config.LogLevel`, exported
  separately from `Load` so `main` can install the logger before the
  config load emits its own WARN lines) from the environment, then
  delegates encoder selection to `convert.EncoderName` (an unknown
  `PFX_ENCODER` value warns here and falls back to `modern2023`).
  Every configuration WARN except the invalid-`LOG_LEVEL` one is emitted
  during `Load` (directly or through its helpers), once per process start;
  that one belongs to `main`, which must install the logger before `Load`
  runs. The reusable readers `config.FallbackInterval`, `config.MaxScanEntries`
  and `config.LogLevel`
  keep their parsing silent because they are called outside `Load` (the first
  by the `health` subcommand, where a WARN would repeat on every healthcheck).
- `internal/convert`: PEM parsing (package-internal; reached through
  `PairInRoot`, which is the package's only production conversion edge —
  the parsers are exposed to the package's own tests via
  `export_test.go`), cert/key matching and confined PFX encoding
  (`PairInRoot`, the only PFX-writing entry point; its encoder helper is
  package-internal), the encoder-profile mapping (`EncoderName` /
  `PickEncoder` in `encoder.go`; `EncoderName` normalizes the value and
  reports whether it was recognized).
- `internal/outputpolicy`: the `OUTPUT_LIFECYCLE` value domain — the
  `Lifecycle` type, its `warn`/`sync`/`keep` modes and `ParseLifecycle`.
  A standard-library-only leaf both `config` (which parses the operator's
  raw value) and `process` (which acts on the parsed mode) import, so the
  configuration layer does not sit above the orchestrator.
- `internal/process`: orchestration, plus `types.go` holding the
  package-private `conversionStatus` outcome enum (`ScanResult` is the
  package's only exported outcome surface), and the package-private
  observation log that de-duplicates per-input warnings across scans.
  `Scanner.Run` walks `/input`,
  pairs each `*.crt` with its sibling `*.key`, asks `store.isCurrent` whether
  the bundle already on disk is the one those inputs produce, and
  writes PFX files to `/output`, returning a `ScanResult` count summary.
  `reap.go` owns the `OUTPUT_LIFECYCLE` reconciliation, including the vetoes
  that must hold before anything is deleted.
- `internal/watch`: fsnotify watch loop with a debounce window, a periodic
  full-scan safety net (the `FALLBACK_SCAN_HOURS` cadence, or the 24h
  reconciliation floor that stands in for it) and a deferred watch-set repair on
  its own bounded schedule. Falls back to polling (with periodic
  upgrade attempts) when fsnotify is unavailable.
- `internal/testcerts`: test-only helpers that generate certificates;
  imported only from `_test.go`.

Data flow: `watch` detects a change and invokes the `onChange` callback
wired in `main.go`, which calls `Scanner.Run`. The scan result drives the
health marker through `healthyAfterScan`: a conversion failure, or a scan that
could not walk `/input` at all, clears it, and a cycle with neither sets it.
Read-side conditions (an unreadable sub-path, an unresolvable symlink, an
`/input` tree over `MAX_SCAN_ENTRIES`, a refused output permission repair) are
warned about and deliberately leave the marker alone, because no restart clears
them.

## Conventions and gotchas

- **Cert/key pairing is by filename.** The scanner only acts on a
  `*.crt` file when a sibling `*.key` with the same stem exists in the
  same directory. A `.crt` with no matching `.key` is recorded as an
  orphan and skipped, not an error.
- **Paths are hardcoded on purpose.** `/input` and `/output` are
  constants in `main.go`, not env vars. Don't add env knobs for them;
  the container contract relies on the fixed mounts.
- **Reads are bounded and confined.** Cert/key reads go through
  `convert.ReadBoundedFromRoot`, which opens each file through the `/input`
  `*os.Root` and reads it under the 10 MB cap (`MaxFileSize`), so a symlink
  planted in the watched tree cannot redirect the read outside it. The scanner
  reads each input once and derives the pair's fingerprint from those bytes
  (`pairFingerprint`), so nothing re-reads a file just to hash it. PFX writes are
  atomic (temp + rename) via `cplieger/atomicfile`. Keep new file I/O on these helpers.
- **The watch loop and its polling fallback are unit-tested.** `newFSWatcher` is
  the construction seam the tests swap to make fsnotify "unavailable", so the
  poll mode, its periodic upgrade attempt, and the handback to watch mode are all
  covered along with `Run` end to end (`watch_run_test.go`), `watchLoop`'s
  `select` over a real cert write and a dead watcher (`watch_loop_test.go`), the
  poll tick and its upgrade handoff (`watch_poll_test.go`), event classification
  (`handleFsEvent`), watch-set construction (`addWatchDirs`),
  the per-arm receive helpers (`handleEventRecv`, `handleErrorRecv`,
  `handleSafetyNetTick`), the channel-closed-vs-shutdown translation
  (`lostOrShutdown`), the mode records (`watch_mode_record_test.go`), the
  deferred watch-set repair (`watch_repair_test.go`) and the
  debounce/safety-net/repair timer accounting
  (`watchState`, under `testing/synctest`). New logic in this package follows
  the same shape: put it in a helper the loop calls, and test the helper.
- **Health is a file marker, not a probe endpoint.** A successful cycle
  writes the marker; `/cert-watcher health` exits 0 if it exists. There
  is no port to bind.
- **Logs are UTC.** The `slogx` library forces every
  record's timestamp to UTC (its `UTCTime` `ReplaceAttr`), so the container
  needs no `TZ` and the binary embeds no `time/tzdata`.

## Running checks locally

From the repo root:

```sh
go build ./...
go test ./...
golangci-lint run
```

The lint config (`.golangci.yaml`) is golangci-lint v2 with `gofumpt`
(extra rules) and `gci` as formatters, so `golangci-lint run` reports
unformatted files as failures. Apply formatting with:

```sh
golangci-lint fmt
```

Tests are property-based ([rapid](https://github.com/flyingmutant/rapid))
plus table-driven, and there are fuzz targets in `internal/convert`
(PEM and key parsing, bundle analysis, password-encoding classification, and
log-text bounding), `internal/config`, and `internal/outputpolicy`. Run a fuzz
target directly when touching a parser or a value domain:

```sh
go test ./internal/convert -run '^$' -fuzz FuzzParseCertChain -fuzztime 30s
```

Benchmarks live beside the code they measure
(`*_bench_test.go`); run them with `go test -bench . ./...`.

## Commits and PRs

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
and are parsed by git-cliff to build the release changelog, so the
subject becomes a public changelog line. Use `feat:`, `fix:`, `sec:` for
release-worthy changes; `docs:`/`chore:`/`refactor:`/`test:` for the
rest. Branch from `main` and open a PR.

## Conduct & security

By participating you agree to the
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report security issues through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md),
never in a public issue.

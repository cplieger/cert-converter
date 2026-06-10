# Contributing to cert-converter

Notes on the layout, local workflow, and conventions specific to this
repo. Most of it is standard Go, but a few things are easy to trip over.

## What this is

A watcher daemon that converts PEM certificate/key pairs to PFX/PKCS#12
whenever they change on disk. There is no HTTP server and no open port —
the only runtime surfaces are the `/input` (read-only) and `/output`
volumes plus a file-based health marker.

Note the name split: the repo and image are `cert-converter`, but the Go
module and built binary are `cert-watcher` (`module
github.com/cplieger/cert-watcher` in `go.mod`). Build output and the
`health` subcommand both use the `cert-watcher` name.

## Package layout

`main.go` is wiring only: load config, build the scanner, run an initial
scan, then hand off to the watcher. The real work lives under
`internal/`:

- `internal/config` — parses `PFX_PASSWORD`, `PFX_ENCODER`, and
  `FALLBACK_SCAN_HOURS` from the environment. `PickEncoder` maps the
  encoder name to a `go-pkcs12` encoder; unknown values warn and fall
  back to `modern2023`.
- `internal/convert` — PEM parsing (`ParseCertChain`, `ParsePrivateKey`),
  PFX encoding (`ToPFX`), and the SHA-256 `HashCache` for
  skip-unchanged detection. `types.go` holds the `CertPair` /
  `ConversionResult` value types.
- `internal/process` — orchestration. `Scanner.Run` walks `/input`,
  pairs each `*.crt` with its sibling `*.key`, consults the cache, and
  writes PFX files to `/output`, returning a `ScanResult` count summary.
- `internal/watch` — fsnotify watch loop with a debounce window and a
  periodic full-scan fallback. Falls back to polling (with periodic
  upgrade attempts) when fsnotify is unavailable.
- `internal/testcerts` — test-only helpers that generate certificates;
  imported only from `_test.go`.

Data flow: `watch` detects a change and invokes the `onChange` callback
wired in `main.go`, which calls `Scanner.Run`. The scan result drives the
health marker (any failure clears it; a clean cycle sets it).

## Conventions and gotchas

- **Cert/key pairing is by filename.** The scanner only acts on a
  `*.crt` file when a sibling `*.key` with the same stem exists in the
  same directory. A `.crt` with no matching `.key` is recorded as an
  orphan and skipped, not an error.
- **Paths are hardcoded on purpose.** `/input` and `/output` are
  constants in `main.go`, not env vars. Don't add env knobs for them —
  the container contract relies on the fixed mounts.
- **Reads are bounded.** Cert/key reads go through
  `convert.ReadFileWithLimit` / the cache hasher with a 10 MB cap
  (`MaxFileSize`). PFX writes are atomic (temp + rename) via
  `cplieger/atomicfile`. Keep new file I/O on these helpers.
- **The watcher loop and poll fallback are not unit-tested.** They are
  event-driven I/O paths validated by the Docker healthcheck in
  production. Logic worth testing belongs in `config`, `convert`, or
  `process`, not in `watch`.
- **Health is a file marker, not a probe endpoint.** A successful cycle
  writes the marker; `/cert-watcher health` exits 0 if it exists. There
  is no port to bind.

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
(`fuzz_parse_test.go`). Run a fuzz target directly when touching the
parsers:

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

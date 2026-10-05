# Contributing to cert-converter

The [shared rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) for commits, releases, synced files and checks apply here.

## Rules

- Only `internal/convert` imports `crypto/x509`, `encoding/pem`, `encoding/asn1` or `go-pkcs12` outside tests. Certificate or key bytes parsed anywhere else skip the limits it checks before parsing, such as the chain-length cap and the RSA prime-factor ceiling.
- Only `internal/layout` spells the file extensions. `internal/process` and `internal/watch` call its functions instead of matching suffixes. A suffix matched elsewhere lets the watcher and the scan disagree, for example by ignoring a `.p12` change the scan converts.
- Pass every log attribute that holds a file path or an error's text through `logtext.Path` at the log call, because a file name with a newline otherwise splits a log record. File operations keep using the raw path.
- `config.FallbackInterval` stays silent on a bad `FALLBACK_SCAN_HOURS` and leaves the warning to `config.Load`. The `health` subcommand calls it on every healthcheck, so a warning there would print every 30 seconds.

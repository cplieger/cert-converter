# Security assurance case — cert-converter

This extends the fleet-wide
[default assurance case](https://github.com/cplieger/.github/blob/main/assurance-case.md)
with the threat model specific to `cert-converter`. Read that first.

## What this is

A distroless Go service that watches a directory of PEM certificates/keys and
emits PKCS#12 (`.pfx`) bundles when they change (fsnotify + polling fallback,
SHA-256 skip-unchanged). It handles key material, so confidentiality and input
robustness matter.

## Top-level claim

cert-converter converts certificate material robustly and without leaking or
corrupting it, even when fed malformed input, on a least-privilege runtime.

## Threats and mitigations

| Threat | Mitigation | Evidence |
|---|---|---|
| Malformed/hostile PEM or key input crashing or exploiting the parser | parsing via Go `crypto/x509` + `encoding/pem` stdlib; hardened under fuzz | `internal/convert/fuzz_parse_test.go`, `convert_test.go` |
| Partial/corrupt output on crash or concurrent write | atomic write (temp → fsync → rename) via the `atomicfile` library | `internal/process`, atomicfile |
| Unnecessary re-emission / churn | SHA-256 content comparison, skip-unchanged | `process.go` |
| Privilege/escape at runtime | distroless, non-root, no shell; CLI `health` probe (no network listener) | Dockerfile, healthcheck |
| Key material exposure in logs | no secret values logged | source review |

## Cryptography

Uses Go stdlib `crypto/x509`, `crypto/tls`, and `software.sslmate.com`/stdlib
PKCS#12 handling — no home-grown crypto. Operates on key material but never
transmits it; output stays on the local filesystem.

## Residual risks

- The output `.pfx` is only as protected as the directory it is written to and
  the passphrase the operator supplies; filesystem permissions are a deployment
  concern.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).

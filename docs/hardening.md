# Security

This page covers what cert-converter exposes, how it treats the files it reads, how to protect the passwords and private keys, and a hardened compose profile. It is for readers who run it next to private keys they care about.

## What it exposes

cert-converter reads certificate sources from one mounted folder and writes converted files to another. It has no network listener and no open port, so there is nothing to expose or firewall. It runs as a non-root user on a distroless base with no shell or package manager. Keep the `/input` mount read-only, as the quick start does.

## How it reads input

- The paths are fixed at `/input` and `/output` and cannot be changed with an environment variable.
- Every read is confined to `/input` through an `os.Root`, so a symlink planted in the input tree cannot redirect a read outside it.
- Each file is checked and read through the same handle, so it cannot be swapped between the check and the read. PEM inputs are capped at 10 MB.
- Malformed PEM or key input is rejected and logged, never converted.
- A private key is refused before Go's parser sees it when its structure declares more than 64 RSA prime factors or an RSA integer above 16384 bits. A small crafted file therefore cannot stall the scan on key precomputation.
- Every write goes to a temporary file that is then renamed into place.
- The two mounts must be separate trees. Identical or nested `/input` and `/output` roots are refused at scan time, compared by their underlying mount and path rather than by name. With PEM output on, an aliased tree would let cert-converter consume and overwrite its own files.

## Bundle input

PFX input is off until `INPUT_PFX_PASSWORD` is set, and that password must not be blank. A bundle's authenticity is checked against it before any certificate or key parsing happens. The password is therefore what stands between untrusted bytes and the parser. Decoding is budgeted per bundle and per scan, weighted by each bundle's declared key-derivation cost. A bundle that declares more work than the budget covers, or more than 64 embedded objects, is refused as a conversion failure. It cannot stall the scan.

## Passwords and private keys

`PFX_PASSWORD` is the only protection on the private key inside every generated `.pfx`. A literal compose value, `${...}` interpolation and `env_file:` all become container environment, which anyone who can query the Docker daemon sees with `docker inspect`.

To avoid that, mount a Docker or Podman secret and set `PFX_PASSWORD_FILE` to its path inside the container. The file takes precedence over `PFX_PASSWORD`. `INPUT_PFX_PASSWORD_FILE` follows the same rules for the input password.

If an environment value is acceptable, write `PFX_PASSWORD: "${PFX_PASSWORD:?}"` in the compose file. Keep the value in a `.env` file with mode `0600` that git ignores. That keeps the value out of the committed compose file, though not out of `docker inspect`.

`OUTPUT_FORMATS=pem` writes each private key as a plaintext `<name>.key` file with mode `0600`. A PFX file protects its key with `PFX_PASSWORD`, and a PEM key file has no such layer. Turn `pem` on only where the output mount itself is access-controlled. The `legacy` and `legacyrc2` encoding profiles weaken that protection, as [Configuration](configuration.md#encoding-profiles) explains.

## Hardened deployment

To lock the container down further, add these settings to the quick start service:

```yaml
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - "/tmp:size=1m,mode=1777,noexec,nosuid,nodev"
```

With `read_only: true`, the health marker still needs a writable `/tmp`, and the tmpfs supplies it. One megabyte is ample, because the marker is the only thing cert-converter writes outside `/output`.

## Accepted scanner finding

semgrep flags the fixed `/tmp/.healthy` marker path as a predictable temporary file. It is a contract between the main process and the `health` probe inside the container's own filesystem, not shared state an attacker can create first. Live scan results are on the repository's Security tab.

## What the image contains

The final image is `gcr.io/distroless/static-debian13:nonroot` with one static Go binary, built from the `golang` Alpine image. The binary links these modules:

- [software.sslmate.com/src/go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12)
- [github.com/fsnotify/fsnotify](https://github.com/fsnotify/fsnotify)
- [github.com/cplieger/atomicfile](https://github.com/cplieger/atomicfile), [envx](https://github.com/cplieger/envx), [health](https://github.com/cplieger/health), [runesafe](https://github.com/cplieger/runesafe), [slogx](https://github.com/cplieger/slogx) and [pathinside](https://github.com/cplieger/pathinside)
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) and [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys)

The license text of every bundled component is in the image under `/usr/share/licenses/`. Dependencies are updated automatically by [Renovate](https://github.com/renovatebot/renovate), and the base images are pinned by digest. Builds carry signed SBOMs and provenance attestations, verifiable with `gh attestation verify`.

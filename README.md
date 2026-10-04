# cert-converter

[![Image Size](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/size.json)](https://github.com/cplieger/cert-converter/pkgs/container/cert-converter) [![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)](https://github.com/cplieger/cert-converter/pkgs/container/cert-converter) [![base: Distroless](https://img.shields.io/badge/base-Distroless_nonroot-4285F4?logo=google)](https://github.com/cplieger/cert-converter/blob/main/Dockerfile) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/cert-converter/badges/mutation.json)](https://github.com/cplieger/cert-converter/issues?q=label%3Agremlins-tracker) [![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/cert-converter/releases)

<!-- hub-overview BEGIN -->
cert-converter keeps PFX copies of your certificates current as they renew, for apps that accept only PFX. It does not request certificates or restart the apps that read them.

## What it does

cert-converter renews the PFX file your app reads each time its certificate renews.

- Writes a password-protected PFX file for each `<name>.crt` and `<name>.key` pair, with the chain from the `.crt` file.
- Converts again a few seconds after a renewal, and rechecks the whole folder every 6 hours by default.
- Can also turn PFX or P12 bundles into PEM files, or write PEM copies beside the PFX files.
- Leaves a file untouched while it matches its certificate, password and encoding profile.

## Who it is for

cert-converter is built for people whose reverse proxy or certificate tool already renews certificates as files, and who run an app that takes only PFX. Examples are .NET apps, Windows tools and the Synology services that take only PFX. It reads `<name>.crt` and `<name>.key` pairs, the way Caddy saves each site's certificate. Certbot's `fullchain.pem` and `privkey.pem` are not read. Your app must reread the PFX file, or be restarted, to use a renewed certificate.

You need Docker on an `amd64` or `arm64` machine, and read access to the certificate files for the container's user.

Consider [acme.sh](https://github.com/acmesh-official/acme.sh) if you want your certificate tool to write the PFX file itself. Its `--to-pkcs12` command exports a certificate and key as a password-protected PFX file.

cert-converter is free software under the GPL-3.0-or-later license.
<!-- hub-overview END -->

## Quick start

The image is on GitHub Container Registry and Docker Hub, for `amd64` and `arm64`. This is the [`compose.yaml`](compose.yaml) in this repository.

```yaml
services:
  cert-converter:
    image: ghcr.io/cplieger/cert-converter:latest
    container_name: cert-converter
    restart: unless-stopped
    # In .env, set PUID and PGID to the user and group that own the certificate files.
    # Create the output folder and run "sudo chown 1000:1000" on it, with those numbers, before the first start.
    user: "${PUID:-1000}:${PGID:-1000}"

    environment:
      # Put PFX_PASSWORD=<a password> in .env. The container does not start without one.
      # docker inspect shows this value. See README "Security" to use a secret file instead.
      PFX_PASSWORD: "${PFX_PASSWORD:-}"
      # warn keeps converted files whose certificate is gone, sync deletes them, keep stays silent.
      # Use sync only once /input holds every certificate you want converted.
      OUTPUT_LIFECYCLE: "${OUTPUT_LIFECYCLE:-warn}"
      PFX_ENCODER: "modern2023"  # modern2023, modern2026, legacy, or legacyrc2

    volumes:
      # The user above must be able to read this folder. See README "Quick start".
      - "/path/to/certificates:/input:ro"
      - "/path/to/converted/output:/output"
```

1. In `compose.yaml`, replace `/path/to/certificates` with your certificate folder and `/path/to/converted/output` with the folder the converted files should go to.
2. Create a file named `.env` beside `compose.yaml` with these lines. Set `PUID` and `PGID` to the user and group that own the certificate files.

   ```text
   PFX_PASSWORD=<the password the PFX files should carry>
   PUID=1000
   PGID=1000
   ```

   Caddy writes each renewed certificate readable by its owner only, so a `chmod` you make on the certificate files is lost at the next renewal.
3. Create the output folder and give it to that user with `mkdir -p /path/to/converted/output && sudo chown 1000:1000 /path/to/converted/output`, using your `PUID` and `PGID` in place of `1000`.
4. Run `docker compose up -d`.

Run `docker logs cert-converter`. You should see `wrote pfx` for each certificate, then `scan complete` with `failed=0`. If you see `no certificate sources found under the input root`, the mounted folder holds no `.crt` and `.key` pair.

## Configuration reference

Settings are environment variables, read when the container starts, so recreate the container after a change. [Configuration](docs/configuration.md) explains each one in full.

| Variable | Description | Default |
| --- | --- | --- |
| `PFX_PASSWORD` | Password every PFX file carries, needed unless `PFX_PASSWORD_FILE` is set. A blank value stops the container at start. | required |
| `PFX_PASSWORD_FILE` | Path to a Docker secret holding that password. It wins over `PFX_PASSWORD`. | _(unset)_ |
| `PFX_ALLOW_EMPTY_PASSWORD` | Set to `true` to allow a blank password, which leaves the private key in each PFX file unprotected. | `false` |
| `PFX_ENCODER` | PFX encoding: `modern2023`, `modern2026` for OpenSSL 3.4.0 or later, `legacy` for older devices, `legacyrc2` as a last resort. | `modern2023` |
| `OUTPUT_FORMATS` | `pfx`, `pem` or `pfx,pem`. `pem` writes a `<name>.crt` and an unencrypted `<name>.key`. | `pfx` |
| `OUTPUT_LAYOUT` | `flat` turns `<issuer>/<site>/<site>.crt` into `<site>/<site>.pfx`, without the issuer folder. `mirror` keeps the full path from `/input`. | `flat` |
| `OUTPUT_LIFECYCLE` | What happens to output whose certificate is gone: `warn` logs it, `sync` deletes it, `keep` stays silent. | `warn` |
| `INPUT_PFX_PASSWORD` | Password for PFX or P12 files under `/input`. Bundle input stays off while it is unset. | _(unset)_ |
| `INPUT_EXCLUDE_PATHS` | Comma-separated paths under `/input` to leave unconverted. | _(unset)_ |
| `FALLBACK_SCAN_HOURS` | Hours between full rechecks of `/input`. At `0`, or above `24`, a full recheck runs once every 24 hours. | `6` |
| `LOG_LEVEL` | `debug`, `info`, `warn` or `error`. | `info` |

`INPUT_PFX_PASSWORD_FILE` and `MAX_SCAN_ENTRIES` are in [Configuration](docs/configuration.md).

| Mount | Description |
| --- | --- |
| `/input` | Certificate folder, read-only and searched to any depth. Must be readable by the container's user. |
| `/output` | Converted files. Must be writable by the container's user. |

Converted files are mode `0600` and belong to the container's user, so the app that reads them must run as that user or as root. The container opens no ports.

## Security

cert-converter opens no network port and runs as a non-root user on an image with no shell. It refuses to convert when `/input` and `/output` are the same folder or one is inside the other. Keep the `/input` mount read-only.

`PFX_PASSWORD` is the only protection on the private key inside each PFX file. A value in `.env` or `environment:` is visible to anyone who can run `docker inspect`. To keep it out, mount a Docker secret and set `PFX_PASSWORD_FILE` to its path inside the container.

With `OUTPUT_FORMATS` set to `pem`, each private key is written as a plain `.key` file, so turn it on only where the output folder is access-controlled. The `legacyrc2` profile uses 40-bit RC2, which can be broken by trying every key, so keep it for a device that accepts nothing else.

[Security](docs/hardening.md) covers the hardened compose settings, the limits on input files and what the image contains.

## Troubleshooting

The healthcheck runs `/cert-watcher health`. It passes while the last scan had no conversion failure and no name collision, and finished within the last 18 hours, or 72 hours when `FALLBACK_SCAN_HOURS` is `0`, `false` or above `24`. The container turns unhealthy when `/input` cannot be read, a certificate fails to convert, or two certificates claim the same output name. It recovers on the next clean scan. Docker does not restart an unhealthy container by itself.

- `refusing to start` in the log means a mount is missing or the container's user cannot open it. The `remediation` field names the fix.
- `the resolved PFX password is empty or blank` means `PFX_PASSWORD` is missing from `.env`.
- `the output volume is not writable by the running UID` means cert-converter cannot write to the output folder, and the `remediation` field names the cause. Most often the folder does not belong to the container's user, so run the `chown` from Quick start step 3 with your `PUID` and `PGID`.
- `output name collision` means two certificate folders share a name. Rename one, or set `OUTPUT_LAYOUT=mirror`.

[How cert-converter works](docs/how-it-works.md#health) lists the conditions that leave health unchanged.

## Monitoring

cert-converter has no metrics endpoint and reports its state in its logs. Fourteen Loki alert rules ship in [`alerts/logql.yaml`](alerts/logql.yaml). [Monitoring and alerts](docs/monitoring.md) lists them and shows how to load them.

## Documentation

- [Configuration](docs/configuration.md) explains every setting, the two mounts and the file permissions.
- [How cert-converter works](docs/how-it-works.md) covers watching, output naming, cleanup and health.
- [Security](docs/hardening.md) covers hardening, input limits and what the image contains.
- [Monitoring and alerts](docs/monitoring.md) lists the log lines and the alert rules.

## Credits

cert-converter writes PFX files with [go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) by SSLMate and watches folders with [fsnotify](https://github.com/fsnotify/fsnotify).

## Contributing

Issues and pull requests are welcome. Please open an issue first for a larger change. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). The image carries the license text of every bundled component under `/usr/share/licenses/`.

# Configuration

This page explains every cert-converter setting, the two mounts and the permissions of the files it writes. It is for readers who want to change more than the quick start sets.

## Where settings live

Every setting is an environment variable. The container reads them once when it starts, so recreate the container after a change. The startup line, `starting cert watcher`, shows the settings in use, and never the passwords themselves. The `health` subcommand also reads `FALLBACK_SCAN_HOURS` on every probe, and it never logs a warning about it.

## Passwords

| Variable | Description | Default |
| --- | --- | --- |
| `PFX_PASSWORD` | Password every PFX file carries, needed unless `PFX_PASSWORD_FILE` is set. A blank value stops the container at start. | required |
| `PFX_PASSWORD_FILE` | Path to a Docker secret holding that password. It wins over `PFX_PASSWORD`. | _(unset)_ |
| `PFX_ALLOW_EMPTY_PASSWORD` | Set to `true` to allow a blank password, which leaves the private key in each PFX file unprotected. | `false` |

The container refuses to start when `PFX_PASSWORD` is empty or blank, unless `PFX_ALLOW_EMPTY_PASSWORD=true` is set. Blank means whitespace only, or invisible characters only, such as a byte-order mark. It also refuses a value that PKCS#12 cannot encode, because such a value produces bundles no consumer can open with the configured secret. Three kinds of value are refused this way. They are a character outside the Basic Multilingual Plane, a byte sequence that is not valid UTF-8, and an embedded NUL.

`PFX_PASSWORD_FILE` reads a Docker secret, a Podman secret or any other mounted file, as [Secrets in files](https://github.com/cplieger/docs/blob/main/docs/hardening.md#secrets-in-files) shows. Setting both logs a WARN naming the one that is ignored. A configured file never falls back to `PFX_PASSWORD`.

- The file is read once, bounded at 1 MB, and used verbatim apart from at most one trailing line ending. Whitespace inside or around the password stays part of it.
- Leading or trailing whitespace draws a WARN on either channel, because every consumer must type that whitespace too.
- The path must already be in cleaned form and must not traverse. `/run/secrets/../secrets/pfx`, a redundant `//`, a `./` prefix and a trailing `/` are all refused.
- An unusable file stops the container at start, and `PFX_ALLOW_EMPTY_PASSWORD=true` does not change that. Unreadable, oversized and rejected-path files are all unusable.
- A blank file is refused exactly like a blank `PFX_PASSWORD`, so the opt-out means one thing however the secret arrives.

With `PFX_ALLOW_EMPTY_PASSWORD=true`, the generated PFX files protect the private key with an empty password, which is effectively no protection. It is not recommended.

## Encoding profiles

`PFX_ENCODER` picks the cipher suite of every generated PFX file. The [go-pkcs12 documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#pkg-variables) describes each one.

| Value | Encoding | Use it for |
| --- | --- | --- |
| `modern2023` | AES-256-CBC with SHA-256 | the default, and what current software reads |
| `modern2026` | AES-256-CBC with PBMAC1 | consumers built on OpenSSL 3.4.0 or later |
| `legacy` | 3DES with SHA-1 | older devices |
| `legacyrc2` | RC2-40 with SHA-1 | a device that accepts nothing else |

`modern` is an alias for `modern2023`, and `legacy` is recorded as `legacydes` in the startup log. An unrecognized value logs a WARN and uses `modern2023`.

Both legacy profiles log a WARN at start, because their single-iteration SHA-1 MAC lets the password be searched offline at about one hash per guess. A 40-bit RC2 key is also brute-forceable, so the private key in a `legacyrc2` bundle is protected only nominally. If you use it, keep the output folder and every copy of it as private as the private keys themselves.

## Output formats and layout

`OUTPUT_FORMATS` is a comma-separated list, and every format in it is kept current for every source. The default is `pfx`.

- `pfx` writes a PKCS#12 bundle for each certificate.
- `pem` writes a `<name>.crt` and `<name>.key` pair. A PEM source is copied verbatim, and a bundle source is decoded and written as PEM. The `.key` file is a plaintext private key on disk. [Security](hardening.md#passwords-and-private-keys) explains when to turn it on.
- An unrecognized entry is ignored with a WARN. A value with no usable entry falls back to the default.
- An invalid value also forces `OUTPUT_LIFECYCLE=warn`, so a typo can never enable deletion under a format set you did not choose.
- Switching a format off leaves its old files in place under `warn` and `keep`. Under `sync` they are removed, because setting `OUTPUT_FORMATS` explicitly states that the remaining set is complete.

`OUTPUT_LAYOUT` decides where files land under `/output`.

- `flat`, the default, names each output after the certificate's own folder. `<issuer>/<site>/<site>.crt` becomes `<site>/<site>.pfx`, so the paths your apps mount never contain the issuing CA's folder, and a change of issuer is invisible to them.
- `mirror` reproduces each source's full path under `/input`.
- Two sources that map to one flat output name are a collision. None of them is converted, an ERROR names the shared name, the number of claimants and a sample of them, and the container stays unhealthy. Rename one source folder, or set `mirror`.
- An unrecognized value uses the default and forces `OUTPUT_LIFECYCLE=warn`.
- Under `sync`, files laid out for the other layout are removed only when `OUTPUT_LAYOUT` is set explicitly. While it is unset they are kept and reported, so an image upgrade never deletes a tree your apps still mount.

## Bundle input

| Variable | Description | Default |
| --- | --- | --- |
| `INPUT_PFX_PASSWORD` | Password for PFX or P12 files under `/input`. Bundle input stays off while it is unset. | _(unset)_ |
| `INPUT_PFX_PASSWORD_FILE` | Path to a file holding that password | _(unset)_ |

While no input password is set, bundle input is off. `.pfx` and `.p12` files are ignored, and PEM pairs convert as always. A configured value must not be blank, because the bundle's authenticity is checked against it before any parsing work. It must also meet the same encoding rules as `PFX_PASSWORD`. A bundle that fails to decode counts as a conversion failure.

`INPUT_PFX_PASSWORD_FILE` follows the same rules as `PFX_PASSWORD_FILE`. It wins over `INPUT_PFX_PASSWORD`, is read once, is bounded at 1 MB and is used verbatim apart from at most one trailing line ending. An unusable file stops the container at start, and a blank file is refused like a blank `INPUT_PFX_PASSWORD`.

## Excluding paths

`INPUT_EXCLUDE_PATHS` is a comma-separated list of paths under `/input`, relative to the mount, that cert-converter must not convert. Use it when the mount also holds certificates that are not yours to convert, so no PFX bundle or PEM copy of their private keys is produced.

- A path naming a folder covers everything beneath it. A path naming a file covers that file.
- Excluding one spelling of a name never strands another, so excluding `site.crt` still lets a `site.pfx` beside it convert.
- Files cert-converter produced earlier for an excluded path become ordinary orphans, and `OUTPUT_LIFECYCLE` decides them as it does when you switch a format off. `keep` is silent, `warn` reports them and `sync` removes them. Cleanup keeps working for every other source.
- An entry that is absolute, climbs above the mount or names the mount itself is reported and ignored. Such an entry also forces `OUTPUT_LIFECYCLE=warn`, so a value cert-converter could only partly parse never authorizes a deletion.
- When every source found is excluded, the scan produces nothing and a WARN says so.

Do not use permissions to leave out a path. A path cert-converter cannot read counts as unreadable, which turns off cleanup for every scan and reports a standing warning. An excluded path leaves cleanup working.

## Removing old output

`OUTPUT_LIFECYCLE` decides what happens to output files cert-converter no longer produces. That happens when the source left `/input`, when `INPUT_EXCLUDE_PATHS` now covers it, or when a format or layout you changed no longer emits it. For a PEM pair, the source is gone only when both the certificate and the private key are gone.

- `warn`, the default, logs those files and leaves them in place.
- `sync` deletes them so `/output` tracks `/input`, after a recheck 30 seconds later confirms the source is still gone. Under the flat layout that recheck reads `/input` again from the start.
- `keep` is silent and never deletes.
- An unrecognized value logs a WARN and uses `warn`.

Only `sync` ever deletes anything, and it removes only files in cert-converter's own output shape, never a folder. It deletes nothing unless the scan proves it read `/input` completely. That proof needs at least one source found, a walk that finished within `MAX_SCAN_ENTRIES`, and no unreadable path, unresolvable symlink, conversion failure or output-name collision. A scan without that proof logs `orphan removal is disabled for this scan` and removes nothing, so a broken or empty mount is never read as "every certificate was deleted". Every scan that deletes something logs a WARN with the count and a sample of the paths.

An output whose `<name>.key` is still present is kept and reported by its own WARN, because a half-written or half-deleted pair does not prove the certificate is gone. Finish the change under `/input` by adding the matching `<name>.crt` or removing the leftover `<name>.key`, and the next scan removes the output.

## Scan cadence and size

`FALLBACK_SCAN_HOURS` sets the hours between full rechecks of `/input`. They catch any change the file watcher missed, for example on a network mount. The default is `6`.

- Only an explicit `0` or `false` turns it off. That stops rechecks on your cadence, but cert-converter still rechecks the whole tree and refreshes its health marker at least once every 24 hours, so a missed renewal is converted late rather than never. Startup logs a WARN naming that delay.
- An empty, whitespace or invalid value uses the 6-hour default, so a blank never turns off the recheck by accident.
- A value above `87600` (10 years) is clamped to that ceiling, and any cadence above 24 hours runs at the 24-hour floor.
- An invalid or clamped value is reported by a WARN at start only.

`MAX_SCAN_ENTRIES` is how many `/input` paths one scan reads before it stops. The default is `10000`.

- When a scan reaches it, the scan converts and removes nothing further. A WARN names the path it reached, and health stays unchanged, because no restart shrinks the tree. Cleanup is skipped for that scan.
- If your certificate tree is larger than the default, raise this and the container's memory limit together. One scan's memory grows with the total length of the paths it reads, not only with their number. Raising this alone can push the scan past a fixed memory limit, where it is killed and converts nothing at all.
- Where the memory limit cannot move, lower this ceiling or set `OUTPUT_LIFECYCLE=keep`, which skips the walk of `/output`.
- An empty, whitespace, invalid, zero or negative value uses `10000`, and a value above `200000` is clamped to that ceiling. Either repair is reported by a WARN at start naming the value you set. No value turns the budget off.

## Logging

`LOG_LEVEL` sets the minimum log level, `debug`, `info`, `warn` or `error`, without regard to case. slog offsets such as `info+2` work too. An unrecognized value falls back to `info`.

`debug` adds the reason each source was skipped, each deletion's own path and the file-watch events. A source is skipped because it is an orphan, unchanged or excluded, because it is a bundle while bundle input is off, because a higher-precedence sibling shadows it, or because its folder is unreadable.

## Volumes and file permissions

`/input` is the certificate folder, mounted read-only.

- A source is a PEM pair, which is `<name>.crt` with its private key as `<name>.key` in the same folder. Once `INPUT_PFX_PASSWORD` is set, a `<name>.pfx` or `<name>.p12` bundle is a source too.
- When one name has both, the PEM pair wins and the bundle is skipped.
- Files with any other extension are ignored. A certbot folder of `fullchain.pem` and `privkey.pem` produces no output and logs `no certificate sources found under the input root`.
- The whole tree is searched to any depth, so every source under the mount is converted. To narrow it, mount the folder you want converted, or list the paths to skip in `INPUT_EXCLUDE_PATHS`.
- The folder and its files must be readable by the user in `user:`. Set `PUID` and `PGID` to the user and group that own the certificate files. Caddy writes each renewed certificate with mode `0600`, readable by its owner only, so a `chgrp` or `chmod` on the files is lost at the next renewal.

`/output` holds the converted files, and it must be writable by the user in `user:`. File paths follow `OUTPUT_LAYOUT`.

Create the host output folder, owned by that user, before the first start. With the default user, run `mkdir -p /path/to/converted/output && sudo chown 1000:1000 /path/to/converted/output`. If `.env` sets `PUID` and `PGID`, use those numbers. If `/output` is not writable, the startup log says so and every conversion fails.

Generated files are mode `0600` and the folders cert-converter creates are `0750`, all owned by that user. The output folder must keep that mode. If inherited ACL entries widen new files there, the startup log warns, every write is refused, and the `remediation` field names the entries to remove. The app that reads them must run as the same user or as a privileged process. Group membership is not enough, because mode `0600` gives the group no read access.

cert-converter never changes the mode of what it finds under `/output`. An output folder more permissive than `0750`, or a file more permissive than `0600`, draws a WARN naming the mode and is left as found. Tighten it yourself, because a group-writable or world-writable output folder lets any other process on that mount replace a file. A file cert-converter writes again, for example after a renewal, lands at `0600`.

An inherited ACL that widens new files, for example on ZFS, stops `/output` from keeping mode `0600`. So does a filesystem that does not store Unix file modes. cert-converter then writes nothing there, and the startup log warns about it at once and names the fix.

## Commands

The binary is `cert-watcher`, and it takes one subcommand. The image supplies `watch` as its default command, so `docker compose up` needs nothing extra.

| Command | Description |
| --- | --- |
| `cert-watcher watch` | Starts the watcher. This is the image's default command |
| `cert-watcher health` | Checks the health marker and exits 0 or 1. The image's `HEALTHCHECK` runs it |

Any other arguments, and no arguments at all, print the usage and exit 2. Without that rule, `docker exec <container> /cert-watcher` would start a second watcher over the same `/input` and `/output` and clear the first one's health marker. Use `docker exec <container> /cert-watcher health` to read the marker, and leave the running watcher alone.

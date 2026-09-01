#!/bin/sh
# Recompute a Dockerfile sha256 integrity pin after its version pin moved.
# Renovate can bump a version literal but cannot compute the sha256 of the
# artifact that names, so this runs as a postUpgradeTask.
#
# Each pin declares its source URL in a marker comment directly above the ARG
# it protects:
#
#   # repin: dep=ryanoasis/nerd-fonts url=https://github.com/ryanoasis/nerd-fonts/releases/download/{version}/Monaspace.tar.xz
#   ARG NERDFONT_SHA256=<64 lowercase hex>
#
# {version} is Renovate's reported version (may lead v); {version_nov} strips
# one leading v. A dep with several pins declares one marker per ARG.
#
# Usage: repin-sha.sh <depName> <newVersion> [dockerfile ...]
# Exits 0, no changes, when no marker names <depName>. Exits non-zero on a
# marker it cannot honour (bad shape, unreachable URL, unchanged file).
set -eu

usage() {
  printf 'usage: repin-sha.sh <depName> <newVersion> [dockerfile ...]\n' >&2
  exit 2
}

[ $# -ge 2 ] || usage
dep=$1
version=$2
shift 2
[ -n "$dep" ] && [ -n "$version" ] || usage

# The version is interpolated into the sed EXPRESSION below (GNU sed's `e`
# flag/command execute the pattern space as a shell command) and reaches curl
# as part of a URL (where `{}`/`[]` trigger curl's own globbing). It is a
# third-party datasource value, not ours, so constrain it to a version's shape
# before any use.
case $version in
  *[!A-Za-z0-9._+~-]*)
    printf 'repin: refusing version with unexpected characters: %s\n' "$version" >&2
    exit 1
    ;;
esac

version_nov=${version#v}

if [ $# -eq 0 ]; then
  set -- Dockerfile
fi

tmp=$(mktemp -d)
# staged is the in-place rewrite target beside the Dockerfile, tracked here so
# the trap can remove it: it lives OUTSIDE $tmp (a rename must be same-filesystem),
# so an interrupt between the copy and the rename would otherwise leave it in the
# working tree for Renovate to carry into a branch.
staged=
cleanup() {
  rm -rf "$tmp"
  [ -n "$staged" ] && rm -f "$staged"
  return 0
}
trap cleanup EXIT INT TERM HUP

# resolve_target prints the real path of $1, following symlinks. The rewrite
# below commits by RENAME, so a Dockerfile reached through a symlink must be
# updated at its TARGET, not replaced by a regular file. realpath/readlink -f
# are probed rather than assumed (neither is POSIX before POSIX.1-2024); with
# neither available a symlinked Dockerfile fails closed.
resolve_target() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  elif command -v readlink >/dev/null 2>&1 && readlink -f "$1" >/dev/null 2>&1; then
    readlink -f "$1"
  else
    if [ -L "$1" ]; then
      printf 'repin: %s: cannot safely update symlink without realpath or readlink -f\n' "$1" >&2
      return 1
    fi
    printf '%s\n' "$1"
  fi
}

updated=0

for dockerfile in "$@"; do
  [ -f "$dockerfile" ] || continue

  dockerfile_target=$(resolve_target "$dockerfile") || {
    printf 'repin: %s: cannot resolve target path\n' "$dockerfile" >&2
    exit 1
  }

  # Emit "<ARG name> <url template>" for every marker naming this dep. The
  # marker must sit directly above its ARG so the pairing is unambiguous when
  # a file carries several pins.
  awk -v dep="$dep" '
		/^#[[:space:]]*repin:/ {
			if (pending_dep != "") { exit 3 }
			d = ""; u = ""
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^dep=/) { d = substr($i, 5) }
				if ($i ~ /^url=/) { u = substr($i, 5) }
			}
			if (d == "" || u == "") {
				printf "repin: malformed marker at %s:%d (need dep= and url=)\n", FILENAME, FNR > "/dev/stderr"
				exit 3
			}
			pending_dep = d; pending_url = u; pending_line = FNR
			next
		}
		pending_dep != "" {
			if ($0 !~ /^ARG [A-Za-z_][A-Za-z0-9_]*=/) { exit 3 }  # END reports it
			if (pending_dep == dep) {
				name = $0
				sub(/^ARG /, "", name)
				sub(/=.*/, "", name)
				printf "%s %s\n", name, pending_url
			}
			pending_dep = ""
			next
		}
		END {
			if (pending_dep != "") {
				printf "repin: marker at %s:%d is not followed by an ARG assignment\n", FILENAME, pending_line > "/dev/stderr"
				exit 3
			}
		}
	' "$dockerfile_target" >"$tmp/pins" || exit $?

  while read -r name url; do
    [ -n "$name" ] || continue

    # A sed replacement is NOT a literal context ('&' re-inserts the match,
    # '\1' a group, '|' closes the command), so this is safe only because the
    # version was constrained to [A-Za-z0-9._+~-] at the argument boundary.
    resolved=$(printf '%s\n' "$url" \
      | sed -e "s|{version}|$version|g" -e "s|{version_nov}|$version_nov|g")

    case $resolved in
      https://*) ;;
      *)
        printf 'repin: %s: refusing non-https URL: %s\n' "$name" "$resolved" >&2
        exit 1
        ;;
    esac

    printf 'repin: %s: %s <- %s\n' "$dockerfile" "$name" "$resolved"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 5 \
      -fsSL -o "$tmp/artifact" "$resolved"

    sha=$(sha256sum "$tmp/artifact" | cut -d' ' -f1)
    case $sha in
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
      *)
        printf 'repin: %s: sha256sum produced no digest\n' "$name" >&2
        exit 1
        ;;
    esac

    # Anchored on the ARG name and the 64-hex value, so nothing else in the
    # file can match; the optional trailing group preserves an inline
    # Renovate anchor comment (ARG X=<sha>  # tool v1.2.3).
    sed -E "s|^(ARG ${name}=)[0-9a-f]{64}([[:space:]].*)?\$|\1${sha}\2|" \
      "$dockerfile_target" >"$tmp/rewritten"

    if ! grep -qE "^ARG ${name}=${sha}([[:space:]]|\$)" "$tmp/rewritten"; then
      printf 'repin: %s: no 64-hex pin to rewrite in %s\n' "$name" "$dockerfile" >&2
      exit 1
    fi

    # Replace atomically: '>' truncates the target before the first byte
    # lands, so a killed postUpgradeTask or ENOSPC would leave a truncated
    # Dockerfile in the branch Renovate commits. Stage beside the TARGET (the
    # mktemp -d above is a different filesystem) and rename over it; `cp -p`
    # carries the original's mode across the replace. mktemp, not a
    # $$-derived name: it creates the file with O_EXCL under an unguessable
    # name, closing the window a predictable name would open to a planted
    # symlink at that path.
    staged=$(mktemp "$dockerfile_target.repin.XXXXXX")
    cp -p "$dockerfile_target" "$staged"
    cat "$tmp/rewritten" >"$staged"
    mv -f "$staged" "$dockerfile_target"
    staged= # renamed away: nothing left for the trap to remove
    updated=$((updated + 1))
  done <"$tmp/pins"
done

if [ "$updated" -eq 0 ]; then
  printf 'repin: no pin declares dep=%s; nothing to do\n' "$dep"
fi

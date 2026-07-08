#!/bin/sh
# Runtime image smoke test for cert-converter. Invoked by the central CI docker job:
#   sh tests/image-smoke.sh <image-ref>
#
# Starts the assembled image and waits for the container's own HEALTHCHECK
# (CMD ["/cert-watcher", "health"], start-period 15s / interval 30s) to report
# "healthy": proves the cert-watcher binary runs in the distroless base, loads
# its config, completes the initial scan, and writes the /tmp/.healthy marker
# that its `health` subcommand probes (health.RunProbe exits 0 iff the marker
# exists).
#
# cert-converter has no network listener, so this stays a health-gated Tier-2
# test (no served surface to assert for Tier 1). Reaching "healthy" needs the
# smallest slice of the app's real config:
#   -e PFX_PASSWORD  config.Load() returns ErrEmptyPassword and main exits 1 on
#                    an empty password unless PFX_ALLOW_EMPTY_PASSWORD=true
#                    (internal/config/config.go); the value itself is unused
#                    here because an empty /input converts nothing.
#   --tmpfs /input   the watch root is the hardcoded /input (main.go), opened
#                    via os.OpenRoot at the start of every scan
#                    (internal/process/process.go). The distroless image ships
#                    no /input, so without this mount the initial scan errors
#                    and the marker never flips healthy. An empty dir converts
#                    zero certs -> ScanResult.Failed==0 -> healthyAfterScan==true.
# No /output or /tmp mount is needed: stale-temp cleanup on a missing /output
# only WARNs, an empty /input writes no PFX, and the distroless base ships a
# writable /tmp for the marker.
set -eu

IMG="${1:?usage: image-smoke.sh <image-ref>}"
NAME="smoke-cert-converter-$$"
TIMEOUT=90 # must cover the 15s start-period + a few 30s healthcheck intervals

# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() {
  code=$?
  # Dump container logs only on failure (a passing run stays quiet).
  if [ "$code" -ne 0 ]; then
    printf '%s\n' "--- container logs (tail) ---" >&2
    docker logs "$NAME" 2>&1 | tail -40 >&2 || true
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$NAME" \
  -e PFX_PASSWORD=smoke-test \
  --tmpfs /input \
  "$IMG" >/dev/null

i=0
status=starting
while [ "$i" -lt "$TIMEOUT" ]; do
  # Fail fast on an early exit: poll .State.Running before the health status so
  # a crash-boot is caught by its exit code (more debuggable than "unhealthy")
  # and the verdict never depends on what health a stopped container reports.
  if [ "$(docker inspect --format '{{ .State.Running }}' "$NAME" 2>/dev/null || echo missing)" != "true" ]; then
    ec=$(docker inspect --format '{{ .State.ExitCode }}' "$NAME" 2>/dev/null || echo '?')
    printf 'FAIL: cert-converter container exited early (exit code %s)\n' "$ec" >&2
    exit 1
  fi
  status=$(docker inspect --format '{{ if .State.Health }}{{ .State.Health.Status }}{{ else }}no-healthcheck{{ end }}' "$NAME" 2>/dev/null || echo gone)
  case "$status" in
    healthy)
      printf 'cert-converter image smoke: ok (healthy after %ss)\n' "$i"
      exit 0
      ;;
    unhealthy)
      printf 'FAIL: cert-converter reported unhealthy\n' >&2
      exit 1
      ;;
    no-healthcheck)
      printf 'FAIL: image has no HEALTHCHECK to assert against\n' >&2
      exit 1
      ;;
    gone)
      printf 'FAIL: cert-converter container is gone\n' >&2
      exit 1
      ;;
  esac
  i=$((i + 1))
  sleep 1
done
printf 'FAIL: cert-converter did not become healthy within %ss (last status: %s)\n' "$TIMEOUT" "$status" >&2
exit 1

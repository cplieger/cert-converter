# check=error=true
FROM golang:1.27-alpine@sha256:7d5cbf6833f7331dafd25a2e8b9673477f559759ff8ed4ca8efabe6795ad08db AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY *.go ./
COPY internal/ internal/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /cert-watcher .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --chmod=755 --from=builder /cert-watcher /cert-watcher
# Distroless's `nonroot` user, spelled numerically: a numeric UID needs no
# /etc/passwd lookup and lets an orchestrator verify the user is non-root
# without resolving a name (hadolint DL3066). Only a default — compose
# overrides it with the operator's own UID.
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD ["/cert-watcher", "health"]
ENTRYPOINT ["/cert-watcher"]
# The watcher is a SUBCOMMAND, not the bare binary, so `docker exec <container>
# /cert-watcher` cannot silently start a second watcher over the same /input and
# /output; a bare argv prints usage and exits 2 instead.
CMD ["watch"]

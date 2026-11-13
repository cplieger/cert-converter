# check=error=true
FROM golang:1.27-alpine@sha256:7d5cbf6833f7331dafd25a2e8b9673477f559759ff8ed4ca8efabe6795ad08db AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY *.go ./
COPY internal/ internal/
ARG BUILD_VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${BUILD_VERSION}" -o /cert-watcher .
COPY LICENSE NOTICE ./
COPY scripts/collect-licenses.sh scripts/
RUN --mount=type=cache,target=/go/pkg/mod \
    sh scripts/collect-licenses.sh --name cert-converter .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

COPY --chmod=755 --from=builder /cert-watcher /cert-watcher
COPY --from=builder /out/usr/share/licenses /usr/share/licenses
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

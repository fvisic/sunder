# Tags are floating by choice (newest-packages policy); pin digests per
# deployment if your compliance process requires reproducible builds.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sunder ./cmd/sunder \
    && mkdir /keystore && chown 65532:65532 /keystore

# Ops variant (build with --target ops): adds openssl for `sunder anchor` /
# `sunder verify-audit`, which shell out to the openssl ts CLI. Meant for
# cron jobs, not for serving traffic.
FROM debian:bookworm-slim AS ops
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 65532 -m sunder
COPY --from=build /sunder /sunder
COPY deploy/freetsa/cacert.pem /etc/sunder/tsa-ca.pem
USER sunder
ENTRYPOINT ["/sunder"]

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /sunder /sunder
# Present in the image so a named volume mounted here inherits nonroot
# ownership (the container runs as uid 65532 and must write keys).
COPY --from=build --chown=65532:65532 /keystore /keystore
USER nonroot
ENTRYPOINT ["/sunder"]
CMD ["serve"]

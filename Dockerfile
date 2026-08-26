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
# cron jobs, not for serving traffic. /creds exists so a named volume
# mounted there inherits the non-root ownership the seeding script needs
# (the same trick /keystore uses in the runtime stage).
FROM debian:bookworm-slim AS ops
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 65532 -m sunder \
    && mkdir /creds && chown 65532:65532 /creds
COPY --from=build /sunder /sunder
COPY deploy/freetsa/cacert.pem /etc/sunder/tsa-ca.pem
USER sunder
ENTRYPOINT ["/sunder"]

# Playground variant (build with --target playground): the interactive demo
# from PLAN 17.4. A separate stage so the runtime image never grows a
# credential-holding demo UI, and a separate binary so nothing here can be
# mistaken for part of the service.
FROM build AS build-playground
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sunder-playground ./cmd/playground

FROM gcr.io/distroless/static-debian12:nonroot AS playground
COPY --from=build-playground /sunder-playground /sunder-playground
USER nonroot
ENTRYPOINT ["/sunder-playground"]

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /sunder /sunder
# Present in the image so a named volume mounted here inherits nonroot
# ownership (the container runs as uid 65532 and must write keys).
COPY --from=build --chown=65532:65532 /keystore /keystore
USER nonroot
ENTRYPOINT ["/sunder"]
CMD ["serve"]

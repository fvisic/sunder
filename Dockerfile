# Tags are floating by choice (newest-packages policy); pin digests per
# deployment if your compliance process requires reproducible builds.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sunder ./cmd/sunder \
    && mkdir /keystore && chown 65532:65532 /keystore

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /sunder /sunder
# Present in the image so a named volume mounted here inherits nonroot
# ownership (the container runs as uid 65532 and must write keys).
COPY --from=build --chown=65532:65532 /keystore /keystore
USER nonroot
ENTRYPOINT ["/sunder"]
CMD ["serve"]

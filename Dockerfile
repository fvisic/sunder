FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sunder ./cmd/sunder

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /sunder /sunder
USER nonroot
ENTRYPOINT ["/sunder"]
CMD ["serve"]

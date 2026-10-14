# knell — a dead man's switch for scheduled work.
#
# Two stages: build a static binary (modernc.org/sqlite is pure Go, so CGO is off
# and the result needs no libc), then ship it on a non-root distroless base.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/0xCyrildev/knell/internal/build.Version=${VERSION} \
        -X github.com/0xCyrildev/knell/internal/build.Commit=${COMMIT} \
        -X github.com/0xCyrildev/knell/internal/build.Date=${BUILD_DATE}" \
      -o /out/knell ./cmd/knell

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/knell /knell

# The database and keyring live here; mount it, or override KNELL_DB/KNELL_KEYS.
ENV KNELL_DB=/data/knell.db \
    KNELL_KEYS=/data/keys.json \
    KNELL_LISTEN=127.0.0.1:8482
VOLUME ["/data"]
EXPOSE 8482
USER nonroot:nonroot

# The health check runs knell itself, because a distroless image has no shell and
# adding curl to a monitoring container would be the joke.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/knell", "ping", "--quiet"]

ENTRYPOINT ["/knell"]
CMD ["serve"]

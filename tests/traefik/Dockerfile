FROM golang:1.25.6-alpine3.22@sha256:fa3380ab0d73b706e6b07d2a306a4dc68f20bfc1437a6a6c47c8f88fe4af6f75 AS builder

WORKDIR /src
COPY go.mod ./
COPY tests/traefik/cmd/harness ./tests/traefik/cmd/harness
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sokol-traefik-harness ./tests/traefik/cmd/harness

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
COPY --from=builder /out/sokol-traefik-harness /usr/local/bin/sokol-traefik-harness
COPY --chmod=0600 tests/traefik/token.fixture /run/secrets/sokol-plugin-token
ENTRYPOINT ["/usr/local/bin/sokol-traefik-harness"]

# Sokol Traefik plugin

Sokol's thin Traefik middleware sends bounded evaluation requests only to the
local native Sokol Edge Agent. It does not call the central Sokol backend,
synchronize policy, embed a WAF, or buffer downstream responses.

The runtime uses only the Go standard library and is tested with Traefik
`v3.7.9` and its embedded Yaegi `v0.16.1`.

## Local installation

Place the checkout at:

```text
/plugins-local/src/git.ksoft.tech/ksoft/sokol-traefik-plugin
```

Enable it in Traefik's static configuration:

```yaml
experimental:
  abortOnPluginFailure: true
  localPlugins:
    sokol:
      moduleName: git.ksoft.tech/ksoft/sokol-traefik-plugin
```

The full dynamic configuration and security model are documented in the Sokol
backend repository under `docs/edge/traefik-plugin.md`.

## Request security

Ordinary JSON, form, and XML requests remain body-inspectable when HTTP/1.1
uses chunked transfer encoding. Capture reads at most the configured maximum
plus one byte and restores the prefix plus unread remainder exactly.
WebSocket, SSE, streaming gRPC, WebDAV, and explicit upload bypasses are never
buffered.

The decision cache is deny-only. It accepts only Agent-authorized block or
rate-limit responses bound to the exact request, client, Resource, decision
scope, and policy revision. Allows and challenge tokens are never cached.

Cloudflare and Bunny modes require explicit `cloudflareCIDRs` or `bunnyCIDRs`.
Their header is trusted only from the matching immediate peer, wins over XFF
only in that explicit mode, and falls back to the direct peer when malformed.
The plugin never auto-detects a provider.

## Default pages

The `pages/` directory contains self-contained Sokol-branded defaults for
block, challenge, rate-limit, and local-Agent-unavailable responses. Copy them
to the configured `responses.root`, which defaults to `/etc/traefik/sokol`.
Operators can replace any page with bounded custom HTML.

These files are compiled from the `sokol-plugin` section of the KSoft error
pages project. They contain no runtime scripts and load only Rubik and Rubik
Dirt from the privacy-focused Bunny Fonts service. The plugin CSP permits only
that exact font origin in addition to inline page styles.

The falcon silhouette is adapted from the public-domain Openclipart
`GDI-CnC3-logo.svg` artwork.

## Verification

```bash
go test -race -count=1 -timeout=2m ./...

cd tests/yaegi
go mod verify
go test -count=1 -timeout=2m ./...

cd ../..
./tests/traefik/run.sh
```

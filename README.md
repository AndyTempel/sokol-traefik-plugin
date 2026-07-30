# Sokol Traefik plugin

Sokol's thin Traefik middleware sends bounded evaluation requests only to the
local native Sokol Edge Agent. It does not call the central Sokol backend,
synchronize policy, embed a WAF, or buffer downstream responses.

The runtime uses only the Go standard library and is tested with Traefik
`v3.7.9` and its embedded Yaegi `v0.16.1`.

## Versioned installation from Gitea

Every successful push to `main` creates the next stable Semantic Version tag
and a Gitea release. Releases begin at `v0.1.0` and increment the patch number
on every push. Each release contains a deterministic runtime-only archive and
its SHA-256 checksum.

Stock Traefik `v3.7.9` downloads remote plugins only through Traefik's public
plugin service, whose catalog accepts public GitHub repositories. It cannot be
pointed at an arbitrary Gitea server. For a self-hosted Gitea repository, use
the supported local-plugin loader with the versioned installer:

```bash
cd deploy/gitea
SOKOL_PLUGIN_VERSION=v0.1.0 docker compose up -d
```

The one-shot installer downloads the selected immutable release directly from
Gitea, verifies its checksum, and atomically installs it in the shared
`plugins-local` volume before Traefik starts. Set
`SOKOL_PLUGIN_RELEASE_BASE_URL` if the repository is exposed at a different
URL. See `deploy/gitea/compose.yml` and `deploy/gitea/traefik-static.yml`.

If native `experimental.plugins` catalog installation is wanted later, the
designated public mirror is
`github.com/AndyTempel/sokol-traefik-plugin`. Catalog publication requires a
deliberate module/import-path migration to that identity, a public repository
with the `traefik-plugin` topic, and mirrored SemVer tags. The Gitea installer
does not require that migration.

Changing `SOKOL_PLUGIN_VERSION` requires recreating the installer and restarting
Traefik because Traefik loads plugins only at startup:

```bash
docker compose run --rm plugin-install
docker compose restart traefik
```

The installer is idempotent for an already installed version. The Compose
example explicitly permits a different checksum-verified version to atomically
replace the previous one; the standalone installer fails closed unless
`SOKOL_PLUGIN_ALLOW_REPLACE=1` is set.

## Manual local installation

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

The immediate peer is checked automatically against Cloudflare's official IPv4
and IPv6 lists and Bunny's official edge and node lists. A verified Cloudflare
peer may supply `CF-Connecting-IP`; a verified Bunny peer may supply
`X-Real-IP`. This detection is independent of the base client-IP strategy, so
CDN-backed and direct sites can share one plugin configuration.

The four fixed HTTPS sources refresh in the background every six hours. Failed
or malformed refreshes preserve the last-known-good source for at most 48
hours, after which it fails closed to ordinary direct/forwarded handling.
Redirects, environment proxies, non-public ranges, oversized responses, and
ambiguous provider overlap are rejected. No provider fetch occurs on a request
path. The old provider CIDR fields are accepted but ignored for configuration
compatibility.

## Default pages

The `pages/` directory contains self-contained Sokol-branded defaults for
block, challenge, rate-limit, and local-Agent-unavailable responses. Copy them
to the configured `responses.root`, which defaults to `/etc/traefik/sokol`.
Operators can replace any page with bounded custom HTML.

These files are compiled from the `sokol-plugin` section of the KSoft error
pages project. Block, rate-limit, and unavailable pages contain no runtime
scripts. The challenge page initializes
`https://sokol-static.my-k.cloud/v1/sokol.iife.js` with the protected Site ID
and uses Sokol's `<sokol-captcha>` component with a same-origin local challenge
URL. It also performs a non-blocking credentialed diagnostic against the
DNT-compatible `https://sokol.my-k.cloud/api/tools/whoami` endpoint. Local
challenge verification remains available when either central origin is
unreachable. All pages load Rubik and Rubik Dirt from the privacy-focused
Bunny Fonts service, and the plugin applies a narrowly scoped CSP. ALTCHA's
native widget is the only manual verification control; low-risk auto-start and
manual widget completion share the same local verification path. The CSP
permits `'wasm-unsafe-eval'` for ALTCHA v3 Argon2 WebAssembly without enabling
the broader `'unsafe-eval'` capability.

Challenge creation and verification reserve `/.sokol` by default. Configure a
different non-root prefix if the protected application already owns that
namespace:

```yaml
challenge:
  pathPrefix: /.sokol
  maximumBodyBytes: 65536
```

The component sends the proof only to the local Agent through the plugin. A
successful response sets the Agent-issued `__Host-sokol_trust` cookie with
`Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`.

The falcon silhouette is adapted from the public-domain Openclipart
`GDI-CnC3-logo.svg` artwork.

## Verification

```bash
./tests/release/run.sh

go test -race -count=1 -timeout=2m ./...

cd tests/yaegi
go mod verify
go test -count=1 -timeout=2m ./...

cd ../..
./tests/traefik/run.sh
```

## Release policy

`main` is the release branch. The Gitea Actions workflow runs all native,
Yaegi, and pinned Traefik compatibility tests before publishing a release.
Tags and release assets are created with the workflow's scoped
`code: write` and `releases: write` token permissions. Existing tags are never
moved or overwritten.

The release publisher handles concurrent pushes by fetching tags again and
retrying with the next patch version if another run created the same tag first.
Release archives exclude tests, fixtures, CI configuration, and development
scripts.

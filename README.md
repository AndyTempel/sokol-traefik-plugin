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

## Default pages

The `pages/` directory contains self-contained Sokol-branded defaults for
block, challenge, rate-limit, and local-Agent-unavailable responses. Copy them
to the configured `responses.root`, which defaults to `/etc/traefik/sokol`.
Operators can replace any page with bounded custom HTML.

These files are compiled from the `sokol-plugin` section of the KSoft error
pages project. They contain no external assets or runtime scripts.

## Verification

```bash
go test -race -count=1 -timeout=2m ./...

cd tests/yaegi
go mod verify
go test -count=1 -timeout=2m ./...

cd ../..
./tests/traefik/run.sh
```

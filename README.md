# passgate

A single-user PassKey gate that adds authentication to any web service — first visit registers your key, every visit after requires it.

Many self-hosted tools ship a web UI with no authentication, leaving you to bolt on something like Caddy basic auth — which means another password to remember and a dialog most password managers won't fill. Passgate replaces that with WebAuthn: a reverse proxy that intercepts every request until a PassKey ceremony succeeds, then keeps you signed in with a JWT cookie.

- **First visit registers** — with no credential on file, the gate page offers a one-click PassKey registration (`/__passgate/`). All of passgate's own paths (gate page, API, assets, health check) live under the `/__passgate/` prefix so nothing collides with the upstream's routes.
- **Every visit after requires it** — once registered, the gate demands an assertion from that key. On success it sets an HttpOnly JWT cookie (HS256, default 7 days) and proxies you through.
- **Authenticated requests are proxied** to the upstream service with `net/http/httputil` (WebSocket-friendly).
- **Single-file state** — the credential and the JWT signing secret live in `$PASSGATE_DATA_DIR/state.json`. There is exactly one user.

## Run

```bash
(cd web && bun install && bun run build)
go build .
./passgate -upstream http://127.0.0.1:3000
```

Then open `http://localhost:8080`, register your PassKey, and you're through. WebAuthn requires a secure context: HTTPS in production, or `localhost` while developing.

## Docker

```bash
docker run -p 8080:8080 -v passgate-data:/data \
  -e PASSGATE_UPSTREAM=http://host.docker.internal:3000 \
  ghcr.io/yankeguo/passgate
```

`.github/workflows/release.yml` builds and pushes `ghcr.io/<owner>/<repo>` via the multi-stage `Dockerfile` (`oven/bun` stage for the frontend, `golang` stage for the binary): push `main` → `latest` and `latest-<short_sha>`, push a git tag → that tag.

## Configuration

Every setting is an environment variable with an equivalent flag.

| Env | Flag | Default | Purpose |
|---|---|---|---|
| `PASSGATE_LISTEN` | `-listen` | `:8080` | HTTP listen address |
| `PASSGATE_UPSTREAM` | `-upstream` | *(required)* | Service to proxy to once authenticated, e.g. `http://127.0.0.1:3000` |
| `PASSGATE_DATA_DIR` | `-data-dir` | `./data` | Where `state.json` (credential + signing secret) lives |
| `PASSGATE_SESSION_TTL` | `-session-ttl` | `168h` | How long a verified session cookie stays valid |
| `PASSGATE_ORIGIN` | `-origin` | per-request | Pin the externally visible origin (e.g. `https://gate.example.com`) |

The WebAuthn RP ID and origin are derived from the request's `Host` header (honoring `X-Forwarded-Proto`), so passgate works behind a TLS-terminating reverse proxy without extra configuration; set `PASSGATE_ORIGIN` if you front it with a fixed domain and want a single canonical RP.

> ⚠️ The PassKey is bound to the RP ID (the hostname). If you later serve passgate under a different hostname, the registered key won't match and you'll be locked out — delete `state.json` to re-register.

## Develop

```bash
# terminal 1: rebuild bundles on change (unminified, inline sourcemaps)
(cd web && bun install && bun run dev)

# terminal 2: run the server
go run . -upstream http://127.0.0.1:3000
```

## Build

```bash
(cd web && bun run typecheck && bun run build)
go test ./...
go build .
```

`web/dist` is git-ignored (only `.gitkeep` is committed), so always run the frontend build before `go build` — in Docker, it happens in the `oven/bun` stage.

## Layout

| Path | Role |
|---|---|
| `main.go` | Flags/env config (`PASSGATE_*`), graceful shutdown |
| `server.go` | Routing, auth middleware (JWT cookie → proxy, else redirect to gate), security headers |
| `gate.go` | WebAuthn ceremonies: register/login begin+finish, RP derived per request origin, in-memory challenges (5 min TTL, single-use) |
| `session.go` | HS256 JWT issue/verify, `passgate_session` cookie |
| `store.go` | Single-user state file (`state.json`): signing secret + `webauthn.Credential`, atomic writes, one-time registration |
| `proxy.go` | `httputil.ReverseProxy` to the upstream |
| `web_tmpl.go` / `web_static.go` | Embedded templates and hashed bundles |
| `web/src/entries/gate.ts` | Gate page logic via `@simplewebauthn/browser` |
| `web/view/gate.html` | Gate page: register prompt (first visit) / sign-in prompt |

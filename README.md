# pgt-energy gateway

Reverse proxy (Express 5) in front of an upstream application (for example Odoo) over a Cloudflare Quick Tunnel.

## Running

Requires Node.js >= 20.6 (`--env-file-if-exists`).

```bash
npm install
npm start
```

`npm start` loads `.env` automatically. If the file is missing, create one in the project root:

```ini
# Random string of at least 32 bytes. Generate it with:
#   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
UPDATE_TOKEN=replace-with-a-random-64-char-token

# Optional: a separate token for the admin UI (recommended)
ADMIN_TOKEN=replace-with-a-different-admin-token

# Public hostname, without https:// and without a port
PUBLIC_HOST=pgt-energy.onrender.com
```

Optional: `PORT` (default `3000`), `PROXY_TIMEOUT_MS` (default `30000`).

The admin UI uses Tailwind CSS v4. Its stylesheet is compiled ahead of time into `public/admin.css`; there is no runtime CDN dependency. Rebuild it after changing markup or classes:

```bash
npm run build:css
```

`public/admin.css` is generated output, so commit it or build it as part of your deploy step.

Quick check after starting:

```bash
curl http://127.0.0.1:3000/_gateway/health
curl http://127.0.0.1:3000/_gateway/status
```

Then open `http://127.0.0.1:3000/_gateway/admin/` and enter the token.

## Environment variables

- `UPDATE_TOKEN` — required, at least 32 bytes. The server refuses to start without it.
- `ADMIN_TOKEN` — optional, at least 32 bytes. A separate token for the admin UI, so the secret held by the tunnel agent is not shared with people. When set, both tokens are accepted.
- `PUBLIC_HOST` — required, public hostname without a port.
- `PORT` — default `3000`.
- `PROXY_TIMEOUT_MS` — default `30000`.

## Admin UI

Open `https://<PUBLIC_HOST>/_gateway/admin/` and enter `ADMIN_TOKEN` (or `UPDATE_TOKEN` if `ADMIN_TOKEN` is not set).

The page shows status (ready, upstream, circuit breaker, uptime), lets you update or clear the Quick Tunnel URL, copy the current upstream, and refresh manually.
The token is kept in the current tab's `sessionStorage` only and is lost when the tab closes.

If the hostname you are visiting differs from `PUBLIC_HOST`, the page shows a warning banner because cookie and header rewrites may be wrong.

> Only enter the token on a trusted machine. The admin UI does not use cookies, so it has no CSRF surface.

## When the backend is unavailable

The gateway distinguishes two kinds of clients:

- **Browsers** (`Accept` contains `text/html`, GET/HEAD): receive a friendly HTML page that reloads after 30 seconds, with a `Retry-After: 30` header.
- **API/XHR clients** (everything else, including all POST requests): still receive JSON `{ "error": "Backend service unavailable" }` as before.

The error page is rendered from `views/unavailable.html` with Tailwind classes, shares the compiled stylesheet, needs no runtime dependency, and escapes the reason text. It is served from a template pre-read into memory.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/_gateway/health` | Liveness |
| GET | `/_gateway/readiness` | Readiness |
| GET | `/_gateway/status` | Publicly returns `{ ready }`; with a Bearer token returns full details |
| POST | `/_gateway/update` | Requires Bearer token, body `{ "url": "https://xxx.trycloudflare.com" }` |
| POST | `/_gateway/clear` | Requires Bearer token |

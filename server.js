import crypto from "node:crypto";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import express from "express";
import { createProxyMiddleware } from "http-proxy-middleware";

const app = express();
app.disable("x-powered-by");
const PORT = process.env.PORT || 3000;
const UPDATE_TOKEN = process.env.UPDATE_TOKEN;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const PUBLIC_HOST = process.env.PUBLIC_HOST;
const UPDATE_WINDOW_MS = 60_000;
const UPDATE_MAX_REQUESTS = 10;
const MAX_TRACKED_UPDATE_CLIENTS = 10_000;
const PROXY_TIMEOUT_MS = Number.parseInt(process.env.PROXY_TIMEOUT_MS || "30000", 10);
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CIRCUIT_COOLDOWN_MS = 30_000;
const ADMIN_PATH = "/_gateway/admin";
const ADMIN_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const UNAVAILABLE_TEMPLATE = await readFile(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "views", "unavailable.html"),
  "utf8"
);
const startedAt = Date.now();

if (!Number.isInteger(PROXY_TIMEOUT_MS) || PROXY_TIMEOUT_MS < 1_000) {
  throw new Error("PROXY_TIMEOUT_MS must be an integer of at least 1000 milliseconds");
}

if (!UPDATE_TOKEN || Buffer.byteLength(UPDATE_TOKEN) < 32) {
  throw new Error("UPDATE_TOKEN must be set and contain at least 32 bytes");
}
if (ADMIN_TOKEN !== undefined && Buffer.byteLength(ADMIN_TOKEN) < 32) {
  throw new Error("ADMIN_TOKEN must contain at least 32 bytes when set");
}
if (!PUBLIC_HOST || !/^[a-z0-9.-]+$/i.test(PUBLIC_HOST)) {
  throw new Error("PUBLIC_HOST must be a public hostname without a port");
}

// This state is intentionally in memory; a restart requires the tunnel agent to update it.
let currentOdooUrl = null;
let upstreamUpdatedAt = null;
let shuttingDown = false;
let consecutiveProxyFailures = 0;
let circuitOpenUntil = 0;
let probeInFlight = false;
let probeResetTimer = null;
const updateAttempts = new Map();

function clientAddress(req) {
  return req.socket.remoteAddress || "unknown";
}

function allowUpdateAttempt(req) {
  const now = Date.now();
  const address = clientAddress(req);
  const attempts = (updateAttempts.get(address) || []).filter(
    (timestamp) => now - timestamp < UPDATE_WINDOW_MS
  );
  if (!updateAttempts.has(address) && updateAttempts.size >= MAX_TRACKED_UPDATE_CLIENTS) {
    for (const [client, timestamps] of updateAttempts) {
      if (timestamps.every((timestamp) => now - timestamp >= UPDATE_WINDOW_MS)) {
        updateAttempts.delete(client);
      }
    }
    if (updateAttempts.size >= MAX_TRACKED_UPDATE_CLIENTS) return false;
  }
  if (attempts.length >= UPDATE_MAX_REQUESTS) {
    updateAttempts.set(address, attempts);
    return false;
  }
  attempts.push(now);
  updateAttempts.set(address, attempts);
  return true;
}

function isAuthorized(req) {
  const authorization = req.headers.authorization;
  const prefix = "Bearer ";
  if (!authorization || !authorization.startsWith(prefix)) return false;

  const suppliedToken = Buffer.from(authorization.slice(prefix.length));
  const expectedToken = Buffer.from(UPDATE_TOKEN);
  const matchesUpdate = suppliedToken.length === expectedToken.length && crypto.timingSafeEqual(suppliedToken, expectedToken);
  if (matchesUpdate) return true;
  if (!ADMIN_TOKEN) return false;

  const adminToken = Buffer.from(ADMIN_TOKEN);
  return suppliedToken.length === adminToken.length && crypto.timingSafeEqual(suppliedToken, adminToken);
}

function authorizeGatewayChange(req, res, next) {
  if (!allowUpdateAttempt(req)) return res.status(429).json({ error: "Too many requests" });
  if (!isAuthorized(req)) return res.status(401).json({ error: "Unauthorized" });
  return next();
}

function setForwardedHeaders(proxyReq, req) {
  // Never forward values supplied by an Internet client.
  proxyReq.setHeader("X-Forwarded-For", clientAddress(req));
  proxyReq.setHeader("X-Forwarded-Proto", "https");
  proxyReq.setHeader("X-Forwarded-Host", PUBLIC_HOST);
  proxyReq.setHeader("X-Forwarded-Port", "443");
}

function replaceTunnelHost(value) {
  if (typeof value !== "string") return value;
  return value.replace(
    /https?:\/\/[a-z0-9-]+\.trycloudflare\.com(?=[:/?#]|$)/gi,
    `https://${PUBLIC_HOST}`
  );
}

function sanitizeUpstreamHeaders(proxyRes) {
  // Do not expose implementation details or the transient tunnel hostname.
  delete proxyRes.headers.server;
  delete proxyRes.headers["x-powered-by"];

  for (const name of ["location", "link", "content-security-policy"]) {
    if (proxyRes.headers[name]) proxyRes.headers[name] = replaceTunnelHost(proxyRes.headers[name]);
  }

  const cookies = proxyRes.headers["set-cookie"];
  if (Array.isArray(cookies)) {
    proxyRes.headers["set-cookie"] = cookies.map((cookie) => cookie.replace(/;\s*domain=\.?[a-z0-9-]+\.trycloudflare\.com/gi, `; Domain=${PUBLIC_HOST}`));
  }
}
function clearProbe() {
  if (probeResetTimer) {
    clearTimeout(probeResetTimer);
    probeResetTimer = null;
  }
  probeInFlight = false;
}

function startProbe() {
  clearProbe();
  probeInFlight = true;
  probeResetTimer = setTimeout(() => {
    probeResetTimer = null;
    probeInFlight = false;
    console.warn("[gateway] probe timed out; allowing another probe");
  }, PROXY_TIMEOUT_MS + 1_000);
  probeResetTimer.unref();
}
function resetUpstreamHealth() {
  consecutiveProxyFailures = 0;
  circuitOpenUntil = 0;
  clearProbe();
}

function markUpstreamFailure() {
  consecutiveProxyFailures += 1;
  clearProbe();

  if (consecutiveProxyFailures >= CIRCUIT_FAILURE_THRESHOLD || circuitOpenUntil > 0) {
    circuitOpenUntil = Date.now() + CIRCUIT_COOLDOWN_MS;
    console.warn("[gateway] upstream circuit opened");
  }
}

function canProxy() {
  if (!currentOdooUrl) return false;
  if (!circuitOpenUntil) return true;
  if (Date.now() < circuitOpenUntil) return false;
  if (probeInFlight) return false;
  startProbe();
  return true;
}

function wantsHtml(req) {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  const accept = req.headers.accept;
  return typeof accept === "string" && accept.includes("text/html");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function unavailablePage(reason) {
  return UNAVAILABLE_TEMPLATE.replace("{{REASON}}", escapeHtml(reason));
}

// Browser navigations get a readable page; API clients keep the JSON contract.
// Works with both Express responses and raw ServerResponse objects.
function sendUnavailable(req, res, status, reason) {
  if (res.headersSent) {
    if (!res.writableEnded) res.end();
    return;
  }

  if (!wantsHtml(req)) {
    const body = JSON.stringify({ error: "Backend service unavailable" });
    res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
    return res.end(body);
  }

  const html = unavailablePage(reason);
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    "Cache-Control": "no-store",
    "Retry-After": "30",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
  });
  return res.end(html);
}
// The admin UI never goes through the upstream proxy, so it stays usable while Odoo is down.
app.use(
  ADMIN_PATH,
  (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    return next();
  },
  express.static(ADMIN_DIR, { index: "admin.html", dotfiles: "deny", fallthrough: true })
);

// Keep unmatched admin paths out of the proxy.
app.use(ADMIN_PATH, (req, res) => res.status(404).json({ error: "Not found" }));

// Avoid proxying the browser's automatic favicon request.
app.get("/favicon.ico", (req, res) => res.status(204).end());

// Liveness only: the Node process can accept requests.
app.get("/_gateway/health", (req, res) => res.json({ status: "ok" }));

// Readiness: the gateway can send requests to Odoo.
app.get("/_gateway/readiness", (req, res) => {
  const ready = Boolean(currentOdooUrl) && !shuttingDown && !circuitOpenUntil;
  return res.status(ready ? 200 : 503).json({ ready });
});

app.post("/_gateway/update", express.json({ limit: "4kb" }), authorizeGatewayChange, (req, res) => {
  const { url } = req.body || {};
  if (typeof url !== "string" || !/^https:\/\/[a-z0-9-]+\.trycloudflare\.com\/?$/i.test(url)) {
    return res.status(400).json({ error: "Invalid Quick Tunnel URL" });
  }
  currentOdooUrl = url.replace(/\/$/, "");
  upstreamUpdatedAt = Date.now();
  resetUpstreamHealth();
  console.log("[gateway] upstream updated");
  return res.json({ success: true });
});

// Clears all in-memory gateway state and immediately stops proxying traffic.
app.post("/_gateway/clear", authorizeGatewayChange, (req, res) => {
  currentOdooUrl = null;
  upstreamUpdatedAt = null;
  resetUpstreamHealth();
  console.log("[gateway] upstream cleared");
  return res.json({ success: true, ready: false });
});

app.get("/_gateway/status", (req, res) => {
  const ready = Boolean(currentOdooUrl) && !shuttingDown && !circuitOpenUntil;
  if (!isAuthorized(req)) return res.json({ ready });

  return res.json({
    authorized: true,
    ready,
    upstream: currentOdooUrl,
    publicHost: PUBLIC_HOST,
    upstreamUpdatedAt,
    circuitOpen: circuitOpenUntil > Date.now(),
    circuitRemainingMs: Math.max(0, circuitOpenUntil - Date.now()),
    consecutiveFailures: consecutiveProxyFailures,
    uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000)
  });
});

// Return controlled JSON for malformed/oversized update bodies.
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && "body" in err) return res.status(400).json({ error: "Invalid JSON body" });
  if (err && err.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  return next(err);
});

const odooProxy = createProxyMiddleware({
  router: () => currentOdooUrl || "http://127.0.0.1:1",
  changeOrigin: true,
  ws: true,
  xfwd: false,
  secure: true,
  proxyTimeout: PROXY_TIMEOUT_MS,
  timeout: PROXY_TIMEOUT_MS,
  on: {
    proxyReq: setForwardedHeaders,
    proxyReqWs: setForwardedHeaders,
    proxyRes: (proxyRes) => {
      sanitizeUpstreamHeaders(proxyRes);
      // Cloudflare uses 520-530 when the Quick Tunnel cannot reach its origin.
      if (proxyRes.statusCode >= 520 && proxyRes.statusCode <= 530) {
        markUpstreamFailure();
        return;
      }
      resetUpstreamHealth();
    },
    error: (err, req, res) => {
      markUpstreamFailure();
      console.error("[gateway] proxy error:", err.code || err.message);
      if (res && typeof res.writeHead === "function") {
        sendUnavailable(req, res, 502, "The backend service is not reachable.");
      } else if (res && typeof res.destroy === "function") {
        res.destroy();
      }
    }
  }
});

app.use((req, res, next) => {
  if (shuttingDown) return sendUnavailable(req, res, 503, "The service is undergoing maintenance.");
  if (!canProxy()) return sendUnavailable(req, res, 503, "The backend service is not reachable.");
  return next();
});
app.use(odooProxy);

// Never return error stacks or internal paths to a public client.
app.use((err, req, res, next) => {
  console.error("[gateway] unexpected error:", err.message);
  if (res.headersSent) return next(err);
  return res.status(500).json({ error: "Internal gateway error" });
});
const server = app.listen(PORT, "0.0.0.0", () => console.log(`Gateway listening on port ${PORT}`));
const sockets = new Set();
server.on("connection", (socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
});

server.on("upgrade", (req, socket, head) => {
  if (shuttingDown || !canProxy()) {
    socket.end("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    return;
  }
  odooProxy.upgrade(req, socket, head);
});

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[gateway] ${signal} received; draining connections`);
  server.close(() => process.exit(0));
  server.closeIdleConnections?.();
  const forceCloseTimer = setTimeout(() => {
    for (const socket of sockets) socket.destroy();
    process.exit(1);
  }, 30_000);
  forceCloseTimer.unref();
}

process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));

const crypto = require("crypto");
const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");

const app = express();
app.disable("x-powered-by");
const PORT = process.env.PORT || 3000;
const UPDATE_TOKEN = process.env.UPDATE_TOKEN;
const PUBLIC_HOST = process.env.PUBLIC_HOST;
const UPDATE_WINDOW_MS = 60_000;
const UPDATE_MAX_REQUESTS = 10;
const MAX_TRACKED_UPDATE_CLIENTS = 10_000;
const PROXY_TIMEOUT_MS = Number.parseInt(process.env.PROXY_TIMEOUT_MS || "30000", 10);
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CIRCUIT_COOLDOWN_MS = 30_000;

if (!Number.isInteger(PROXY_TIMEOUT_MS) || PROXY_TIMEOUT_MS < 1_000) {
  throw new Error("PROXY_TIMEOUT_MS must be an integer of at least 1000 milliseconds");
}

if (!UPDATE_TOKEN || Buffer.byteLength(UPDATE_TOKEN) < 32) {
  throw new Error("UPDATE_TOKEN must be set and contain at least 32 bytes");
}
if (!PUBLIC_HOST || !/^[a-z0-9.-]+$/i.test(PUBLIC_HOST)) {
  throw new Error("PUBLIC_HOST must be a public hostname without a port");
}

// This state is intentionally in memory; a restart requires the tunnel agent to update it.
let currentOdooUrl = null;
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
  return suppliedToken.length === expectedToken.length && crypto.timingSafeEqual(suppliedToken, expectedToken);
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
  resetUpstreamHealth();
  console.log("[gateway] upstream updated");
  return res.json({ success: true });
});

// Clears all in-memory gateway state and immediately stops proxying traffic.
app.post("/_gateway/clear", authorizeGatewayChange, (req, res) => {
  currentOdooUrl = null;
  resetUpstreamHealth();
  console.log("[gateway] upstream cleared");
  return res.json({ success: true, ready: false });
});

app.get("/_gateway/status", (req, res) => {
  return res.json({ ready: Boolean(currentOdooUrl) && !shuttingDown && !circuitOpenUntil });
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
      // Cloudflare uses 520â€“530 when the Quick Tunnel cannot reach its origin.
      if (proxyRes.statusCode >= 520 && proxyRes.statusCode <= 530) {
        markUpstreamFailure();
        return;
      }
      resetUpstreamHealth();
    },
    error: (err, req, res) => {
      markUpstreamFailure();
      console.error("[gateway] proxy error:", err.message);
      if (res && typeof res.writeHead === "function") {
        if (!res.headersSent) res.writeHead(502, { "Content-Type": "application/json" });
        if (!res.writableEnded) res.end(JSON.stringify({ error: "Odoo backend unavailable" }));
      } else if (res && typeof res.destroy === "function") {
        res.destroy();
      }
    }
  }
});

app.use((req, res, next) => {
  if (shuttingDown || !canProxy()) return res.status(503).json({ error: "Odoo backend unavailable" });
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

const TOKEN_KEY = "gatewayAdminToken";
const REFRESH_MS = 5000;
const TUNNEL_URL = /^https:\/\/[a-z0-9-]+\.trycloudflare\.com\/?$/i;

const BADGE_BASE = "rounded-full px-3 py-1 text-[13px] font-semibold";
const BADGE_OK = "bg-green-500/15 text-green-400";
const BADGE_BAD = "bg-red-500/15 text-red-400";
const VALUE_BASE = "mt-1 break-words text-sm font-semibold";
const MESSAGE_BASE = "mt-4 min-h-[22px] text-[13px]";
const MESSAGE_ERROR = "text-red-400";
const MESSAGE_SUCCESS = "text-green-400";

const el = {
  token: document.getElementById("token"),
  login: document.getElementById("login"),
  logout: document.getElementById("logout"),
  refresh: document.getElementById("refresh"),
  copy: document.getElementById("copy"),
  authSection: document.getElementById("auth-section"),
  dashboard: document.getElementById("dashboard-section"),
  host: document.getElementById("public-host"),
  hostWarning: document.getElementById("host-warning"),
  ready: document.getElementById("ready-badge"),
  upstream: document.getElementById("upstream"),
  circuit: document.getElementById("circuit"),
  failures: document.getElementById("failures"),
  uptime: document.getElementById("uptime"),
  upstreamUpdatedAt: document.getElementById("upstream-updated-at"),
  checkedAt: document.getElementById("checked-at"),
  form: document.getElementById("update-form"),
  url: document.getElementById("url"),
  clear: document.getElementById("clear"),
  message: document.getElementById("message")
};

let token = sessionStorage.getItem(TOKEN_KEY) || "";
let refreshTimer = null;
let currentUpstream = null;

el.host.textContent = window.location.host;

function say(text, kind = "") {
  el.message.textContent = text;
  const tone = kind === "error" ? MESSAGE_ERROR : kind === "success" ? MESSAGE_SUCCESS : "";
  el.message.className = `${MESSAGE_BASE} ${tone}`.trim();
}

function headers() {
  return { Authorization: `Bearer ${token}` };
}

async function request(path, options = {}) {
  const { probe = false, ...init } = options;
  let response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { ...headers(), ...(init.headers || {}) },
      cache: "no-store"
    });
  } catch {
    throw new Error("Unable to reach the gateway.");
  }

  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (response.status === 401) {
    if (!probe) signOut("Invalid or expired token.");
    throw new Error("Unauthorized");
  }
  if (response.status === 429) {
    throw new Error("Too many requests. Please try again in a minute.");
  }
  if (!response.ok) {
    throw new Error(body?.error || `Request failed (${response.status})`);
  }
  return body;
}

function render(data) {
  const { ready, upstream, publicHost, upstreamUpdatedAt, circuitOpen, circuitRemainingMs, consecutiveFailures, uptimeSeconds } = data;

  currentUpstream = upstream || null;
  el.copy.disabled = !currentUpstream;

  el.ready.textContent = ready ? "Ready" : "Not ready";
  el.ready.className = `${BADGE_BASE} ${ready ? BADGE_OK : BADGE_BAD}`;

  el.upstream.textContent = currentUpstream || "Not configured";
  el.circuit.textContent = circuitOpen ? `Open (${Math.ceil(circuitRemainingMs / 1000)}s left)` : "Closed";
  el.circuit.className = circuitOpen ? `${VALUE_BASE} text-amber-400` : VALUE_BASE;
  el.failures.textContent = String(consecutiveFailures ?? 0);
  el.uptime.textContent = formatUptime(uptimeSeconds);
  el.upstreamUpdatedAt.textContent = upstreamUpdatedAt ? new Date(upstreamUpdatedAt).toLocaleString("en-US") : "—";
  el.checkedAt.textContent = new Date().toLocaleTimeString("en-US");

  const mismatch = publicHost && publicHost.toLowerCase() !== window.location.host.toLowerCase();
  el.hostWarning.hidden = !mismatch;
  if (mismatch) {
    el.hostWarning.textContent = `PUBLIC_HOST in .env is "${publicHost}" but you are visiting "${window.location.host}". Cookie and header rewrites may be wrong.`;
  }
}

function formatUptime(seconds) {
  if (!Number.isFinite(seconds)) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m`;
  return `${seconds}s`;
}

async function refresh() {
  if (!token || document.hidden) return;
  try {
    render(await request("/_gateway/status"));
  } catch (error) {
    if (error.message !== "Unauthorized") say(error.message, "error");
  }
}

function startRefresh() {
  stopRefresh();
  refresh();
  refreshTimer = setInterval(refresh, REFRESH_MS);
}

function stopRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = null;
}

function signOut(message = "") {
  token = "";
  currentUpstream = null;
  sessionStorage.removeItem(TOKEN_KEY);
  stopRefresh();
  el.dashboard.hidden = true;
  el.authSection.hidden = false;
  el.hostWarning.hidden = true;
  el.token.value = "";
  el.token.focus();
  say(message, message ? "error" : "");
}

async function signIn(newToken) {
  const candidate = newToken.trim();
  if (!candidate) return say("Please enter a token.", "error");

  el.login.disabled = true;
  const previous = token;
  token = candidate;
  try {
    const data = await request("/_gateway/status", { probe: true });
    if (!data?.authorized) throw new Error("Unauthorized");
    render(data);
  } catch (error) {
    token = previous;
    say(error.message === "Unauthorized" ? "Invalid or expired token." : error.message, "error");
    return;
  } finally {
    el.login.disabled = false;
  }

  sessionStorage.setItem(TOKEN_KEY, token);
  el.authSection.hidden = true;
  el.dashboard.hidden = false;
  say("");
  startRefresh();
}

el.login.addEventListener("click", () => signIn(el.token.value));
el.token.addEventListener("keydown", (event) => {
  if (event.key === "Enter") signIn(el.token.value);
});
el.logout.addEventListener("click", () => signOut());
el.refresh.addEventListener("click", () => refresh());

el.copy.addEventListener("click", async () => {
  if (!currentUpstream) return;
  try {
    await navigator.clipboard.writeText(currentUpstream);
    say("Upstream copied.", "success");
  } catch {
    say("The browser blocked clipboard access. Please copy it manually.", "error");
  }
});

el.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = el.url.value.trim();
  if (!TUNNEL_URL.test(url)) {
    return say("URL must look like https://<name>.trycloudflare.com", "error");
  }
  if (currentUpstream && !confirm(`Change upstream from\n${currentUpstream}\nto\n${url}?`)) return;

  el.form.querySelectorAll("button").forEach((button) => (button.disabled = true));
  try {
    await request("/_gateway/update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    el.url.value = "";
    say("Upstream updated.", "success");
    await refresh();
  } catch (error) {
    if (error.message !== "Unauthorized") say(error.message, "error");
  } finally {
    el.form.querySelectorAll("button").forEach((button) => (button.disabled = false));
    el.copy.disabled = !currentUpstream;
  }
});

el.clear.addEventListener("click", async () => {
  if (!confirm("Clear the upstream? The gateway will stop forwarding traffic until a new URL is set.")) return;

  el.clear.disabled = true;
  try {
    await request("/_gateway/clear", { method: "POST" });
    say("Upstream cleared.", "success");
    await refresh();
  } catch (error) {
    if (error.message !== "Unauthorized") say(error.message, "error");
  } finally {
    el.clear.disabled = false;
  }
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh();
});

if (token) {
  el.authSection.hidden = true;
  el.dashboard.hidden = false;
  startRefresh();
} else {
  el.token.focus();
}

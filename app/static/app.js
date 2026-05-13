"use strict";

// ── Token store ──────────────────────────────────────────────────
const tokens = {};
// keys: "task1", "task1-forged", "task2", "task2-forged",
//       "task3", "task3-forged", "fixed"

// ── Fetch helper ─────────────────────────────────────────────────
async function apiFetch(method, url, { body, auth } = {}) {
  const headers = {};
  if (body)  headers["Content-Type"] = "application/json";
  if (auth)  headers["Authorization"] = `Bearer ${auth}`;
  const res  = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// ── JWT helpers ──────────────────────────────────────────────────
function decodeJWT(token) {
  try {
    const dec = s => JSON.parse(atob(
      s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")
    ));
    const [h, p] = token.split(".");
    return { header: dec(h), payload: dec(p) };
  } catch { return null; }
}

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function highlightJSON(obj, changedKeys = []) {
  const lines = JSON.stringify(obj, null, 2).split("\n");
  return lines.map(line => {
    const isChanged = changedKeys.some(k => {
      const re = new RegExp(`"${k}"\\s*:`);
      return re.test(line);
    });
    return isChanged
      ? `<span class="changed">${esc(line)}</span>`
      : esc(line);
  }).join("\n");
}

function copyToken(key) {
  const t = tokens[key];
  if (!t) return;
  navigator.clipboard.writeText(t).then(() => {
    const btn = document.querySelector(`[data-copy="${key}"]`);
    if (!btn) return;
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
}

// ── Render helpers ───────────────────────────────────────────────
function renderTokenCard(key, containerId, { label = "Token", compareKey = null } = {}) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const token = tokens[key];
  if (!token) return;

  const decoded = decodeJWT(token);
  if (!decoded) return;
  const { header, payload } = decoded;

  let changed = [];
  if (compareKey && tokens[compareKey]) {
    const orig = decodeJWT(tokens[compareKey]);
    if (orig) {
      changed = Object.keys(payload).filter(
        k => JSON.stringify(payload[k]) !== JSON.stringify(orig.payload[k])
      );
      // Also check header keys
      const hChanged = Object.keys(header).filter(
        k => JSON.stringify(header[k]) !== JSON.stringify(orig.header[k])
      );
      changed = [...new Set([...changed, ...hChanged])];
    }
  }

  const short = token.length > 64 ? token.slice(0, 64) + "…" : token;

  el.innerHTML = `
    <div class="token-raw">
      <span class="token-raw-label">${esc(label)}</span>
      <span class="token-raw-value" title="${esc(token)}">${esc(short)}</span>
      <button class="copy-btn" data-copy="${key}" onclick="copyToken('${key}')">Copy</button>
    </div>
    <div class="token-parts">
      <div class="token-part">
        <div class="token-part-label">Header</div>
        <pre>${highlightJSON(header, changed)}</pre>
      </div>
      <div class="token-part">
        <div class="token-part-label">
          Payload${changed.length ? ' &nbsp;<span class="changed" style="font-size:0.65rem;font-family:sans-serif;letter-spacing:0.06em;font-weight:700">CHANGES IN RED</span>' : ''}
        </div>
        <pre>${highlightJSON(payload, changed)}</pre>
      </div>
    </div>
  `;
  el.classList.remove("hidden");
}

function renderResult(containerId, { ok, status, data }) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const cls   = ok ? "ok" : "err";
  const label = ok ? `✓ ${status} OK` : `✗ ${status} Error`;
  el.innerHTML = `
    <div class="result-status ${cls}">${label}</div>
    <div class="result-body">${esc(JSON.stringify(data, null, 2))}</div>
  `;
  el.classList.remove("hidden");
}

function renderPill(containerId, { ok, warn, data }) {
  const el = document.getElementById(containerId);
  if (!el) return;
  let cls, text;
  if (warn) {
    cls  = "warn";
    text = `⚠ ${data}`;
  } else if (ok) {
    cls  = "ok";
    text = "✓ Access granted";
  } else {
    cls  = "err";
    text = `✗ ${data.error || "Rejected"}`;
  }
  el.className = `result-pill ${cls}`;
  el.textContent = text;
}

// ── Task actions ─────────────────────────────────────────────────
async function loginTask(n) {
  const r = await apiFetch("POST", `/task${n}/login`, {
    body: { username: "alice", password: "password123" },
  });
  if (!r.ok) { alert("Login failed: " + (r.data.error || "unknown")); return; }
  tokens[`task${n}`] = r.data.token;
  renderTokenCard(`task${n}`, `task${n}-token`, { label: "alice's token" });
}

async function forgeTask(n) {
  const orig = tokens[`task${n}`];
  if (!orig) { alert("Complete Step 1 first — get alice's token."); return; }
  const r = await apiFetch("POST", `/api/exploit/task${n}`, { body: { token: orig } });
  if (!r.ok) { alert("Forge failed: " + (r.data.error || "unknown")); return; }
  tokens[`task${n}-forged`] = r.data.forged_token;
  renderTokenCard(`task${n}-forged`, `task${n}-forged`, {
    label: "Forged token",
    compareKey: `task${n}`,
  });
}

async function attackTask(n) {
  const forged = tokens[`task${n}-forged`];
  if (!forged) { alert("Complete Step 2 first — forge the token."); return; }
  const r = await apiFetch("GET", `/task${n}/admin`, { auth: forged });
  renderResult(`task${n}-result`, r);
}

// ── Fixed / Task 4 ───────────────────────────────────────────────
async function loginFixed() {
  const r = await apiFetch("POST", "/fixed/login", {
    body: { username: "admin", password: "admin123" },
  });
  if (!r.ok) { alert("Login failed: " + (r.data.error || "unknown")); return; }
  tokens["fixed"] = r.data.token;
  renderTokenCard("fixed", "fixed-token", { label: "admin token" });
  document.getElementById("fixed-test-btn").classList.remove("hidden");
}

async function attackFixed() {
  const t = tokens["fixed"];
  if (!t) { alert("Login as admin first."); return; }
  const r = await apiFetch("GET", "/fixed/admin", { auth: t });
  renderResult("fixed-result", r);
}

async function testForgedOnFixed(n) {
  const forged = tokens[`task${n}-forged`];
  const pid    = `fixed-test${n}`;
  if (!forged) {
    renderPill(pid, { warn: true, data: `Complete Task ${n} first` });
    return;
  }
  const r = await apiFetch("GET", "/fixed/admin", { auth: forged });
  renderPill(pid, r);
}

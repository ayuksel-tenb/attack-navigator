"use strict";

// Runtime config: injected by gen-config.sh (Docker) via config.js, with safe
// defaults for opening the page directly without the container.
const CONFIG = Object.assign(
  {
    scUrl: "https://localhost:8443",
    pluginUrlTemplate:
      "{scUrl}/#vulnerabilities/cumulative/listvuln/%7B%22filt%22%3A%5B%7B%22id%22%3A%22pluginID%22%2C%22filterName%22%3A%22pluginID%22%2C%22operator%22%3A%22%3D%22%2C%22type%22%3A%22vuln%22%2C%22isPredefined%22%3Atrue%2C%22value%22%3A%22{pluginId}%22%7D%5D%2C%22sortCol%22%3A%22none%22%2C%22sortDir%22%3A%22desc%22%7D/0/0",
  },
  window.TAM_CONFIG || {}
);

const els = {
  matrix: document.getElementById("matrix"),
  hint: document.getElementById("hint"),
  onlyExposed: document.getElementById("onlyExposed"),
  loadDefault: document.getElementById("loadDefault"),
  fileInput: document.getElementById("fileInput"),
  openSc: document.getElementById("openSc"),
  scInfo: document.getElementById("scInfo"),
  drawer: document.getElementById("drawer"),
  drawerId: document.getElementById("drawerId"),
  drawerName: document.getElementById("drawerName"),
  drawerBody: document.getElementById("drawerBody"),
  drawerClose: document.getElementById("drawerClose"),
  scrim: document.getElementById("scrim"),
};

els.scInfo.textContent = "SC: " + CONFIG.scUrl;

const state = {
  catalog: null, // {tactics:[{id,name}], techniques:[{id,name,tactics,parent}]}
  byId: {}, // techniqueID -> catalog technique
  subsByParent: {}, // parentID -> [sub catalog techniques]
  index: {}, // techniqueID -> exposure info from the layer
};

// --- Wiring ---------------------------------------------------------------

els.openSc.addEventListener("click", () => window.open(CONFIG.scUrl, "tenable-sc"));
els.loadDefault.addEventListener("click", () => loadLayer("layers/layer.json"));
els.onlyExposed.addEventListener("change", renderMatrix);
els.drawerClose.addEventListener("click", closeDrawer);
els.scrim.addEventListener("click", closeDrawer);
els.fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const r = new FileReader();
  r.onload = () => {
    const layer = safeParse(r.result);
    if (layer) {
      buildIndex(layer);
      renderMatrix();
    }
  };
  r.readAsText(file);
});

boot();

async function boot() {
  state.catalog = await fetchJson("attack-catalog.json");
  if (!state.catalog) {
    els.matrix.innerHTML = '<div class="empty">Could not load attack-catalog.json.</div>';
    return;
  }
  for (const t of state.catalog.techniques) {
    state.byId[t.id] = t;
    if (t.parent) (state.subsByParent[t.parent] ||= []).push(t);
  }
  const layer = await fetchJson("layers/layer.json");
  if (layer) buildIndex(layer);
  renderMatrix();
}

// --- Loading & parsing ----------------------------------------------------

async function fetchJson(url) {
  try {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(r.status);
    return await r.json();
  } catch {
    return null;
  }
}

async function loadLayer(url) {
  const layer = await fetchJson(url);
  if (layer) {
    buildIndex(layer);
    renderMatrix();
  }
}

function safeParse(t) {
  try { return JSON.parse(t); } catch { return null; }
}

function buildIndex(layer) {
  if (Array.isArray(layer)) layer = layer[0];
  state.index = {};
  if (!layer || !Array.isArray(layer.techniques)) return;
  for (const t of layer.techniques) {
    if (typeof t.score !== "number") continue;
    state.index[t.techniqueID] = parseTechnique(t);
  }
}

function parseTechnique(t) {
  const meta = t.metadata || [];
  const links = t.links || [];
  const findings = [];
  for (const m of meta) {
    if (!m || !m.name || !m.name.startsWith("plugin ")) continue;
    const pid = m.name.slice("plugin ".length).trim();
    findings.push(parseFinding(pid, m.value || "", links));
  }
  return {
    score: t.score,
    color: t.color || "#777",
    findings,
    count: parseInt(getMeta(meta, "findings") || findings.length, 10) || findings.length,
    vpr: getMeta(meta, "total_vpr") || "",
    needsReview: getMeta(meta, "needs_review") === "true",
  };
}

function parseFinding(pluginId, value, links) {
  const cves = value.match(/CVE-\d{4}-\d+/gi) || [];
  const vpr = (value.match(/VPR\s+([\d.]+)/i) || [])[1] || "";
  const hosts = (value.match(/×(\d+)\s*hosts/i) || [])[1] || "";
  const name = value.split(" — ")[0].trim();
  const link = links.find((l) => l && l.label && l.label.startsWith(pluginId + ":"));
  return { pluginId, name, cves, vpr, hosts, pluginPageUrl: link ? link.url : "" };
}

function getMeta(meta, key) {
  const row = meta.find((m) => m && m.name === key);
  return row ? row.value : undefined;
}

// --- Matrix rendering -----------------------------------------------------

// Exposure info for a base technique: its own score plus any scored sub-techniques.
function exposureFor(baseId) {
  const direct = state.index[baseId] || null;
  const subs = (state.subsByParent[baseId] || [])
    .filter((s) => state.index[s.id])
    .map((s) => ({ id: s.id, name: s.name, info: state.index[s.id] }));
  let color = direct ? direct.color : null;
  let score = direct ? direct.score : null;
  for (const s of subs) {
    if (score === null || s.info.score > score) { score = s.info.score; color = s.info.color; }
  }
  return { direct, subs, exposed: !!direct || subs.length > 0, color, score };
}

function renderMatrix() {
  els.matrix.innerHTML = "";
  const onlyExposed = els.onlyExposed.checked;
  let totalExposed = 0;

  for (const tactic of state.catalog.tactics) {
    const bases = state.catalog.techniques.filter(
      (t) => !t.parent && t.tactics.includes(tactic.id)
    );
    const cells = [];
    let exposedCount = 0;
    for (const base of bases) {
      const exp = exposureFor(base.id);
      if (exp.exposed) exposedCount++;
      if (onlyExposed && !exp.exposed) continue;
      cells.push(cellEl(base, exp));
    }
    totalExposed += exposedCount;
    if (onlyExposed && exposedCount === 0) continue;

    const col = document.createElement("div");
    col.className = "col";
    const head = document.createElement("div");
    head.className = "col-head";
    head.innerHTML = `<span>${esc(tactic.name)}</span><span class="n">${exposedCount}</span>`;
    const body = document.createElement("div");
    body.className = "col-cells";
    cells.forEach((c) => body.appendChild(c));
    col.appendChild(head);
    col.appendChild(body);
    els.matrix.appendChild(col);
  }

  els.hint.textContent = onlyExposed
    ? `${totalExposed} exposed technique(s). Click one to see the vulnerabilities behind it.`
    : "Click a colored (exposed) technique to see the vulnerabilities behind it.";
}

function cellEl(base, exp) {
  const cell = document.createElement("div");
  cell.className = "cell" + (exp.exposed ? " exposed" : " dim");
  if (exp.exposed) {
    cell.style.background = exp.color;
    cell.style.color = textColor(exp.color);
  }
  const subBadge = exp.subs.length
    ? `<span class="sub-badge">${exp.subs.length}</span>`
    : "";
  const score = exp.score !== null ? `<span class="score">${exp.score.toFixed(0)}</span>` : "";
  cell.innerHTML =
    subBadge +
    `<span class="tid">${esc(base.id)}</span>${score}` +
    `<span class="tname">${esc(base.name)}</span>`;
  if (exp.exposed) cell.addEventListener("click", () => openDrawer(base, exp));
  return cell;
}

// --- Findings drawer ------------------------------------------------------

function openDrawer(base, exp) {
  els.drawerId.textContent = base.id;
  els.drawerName.textContent = base.name;
  els.drawerBody.innerHTML = "";

  const entries = [];
  if (exp.direct) entries.push({ id: base.id, name: base.name, info: exp.direct });
  for (const s of exp.subs) entries.push(s);

  for (const e of entries) {
    const head = document.createElement("div");
    head.className = "sec-head";
    const review = e.info.needsReview ? '<span class="badge-review">needs review</span>' : "";
    head.innerHTML =
      `<span><b>${esc(e.id)}</b> <span class="sname">${esc(e.name)}</span>${review}</span>` +
      `<span>${e.info.count} finding(s) · VPR ${esc(e.info.vpr)}</span>`;
    els.drawerBody.appendChild(head);
    els.drawerBody.appendChild(findingsTable(e.info.findings));
  }

  els.drawer.classList.add("open");
  els.drawer.setAttribute("aria-hidden", "false");
  els.scrim.hidden = false;
}

function closeDrawer() {
  els.drawer.classList.remove("open");
  els.drawer.setAttribute("aria-hidden", "true");
  els.scrim.hidden = true;
}

function findingsTable(findings) {
  if (!findings.length) {
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = "No per-finding detail recorded.";
    return d;
  }
  const table = document.createElement("table");
  table.innerHTML =
    "<thead><tr><th>Plugin</th><th>Vulnerability</th><th>CVE</th><th>VPR</th><th>Actions</th></tr></thead>";
  const tbody = document.createElement("tbody");
  for (const f of findings) tbody.appendChild(findingRow(f));
  table.appendChild(tbody);
  return table;
}

function findingRow(f) {
  const tr = document.createElement("tr");
  const sc = scLink(f.pluginId);
  const actions =
    `<a href="${esc(sc)}" target="tenable-sc">Open in SC ↗</a>` +
    (f.pluginPageUrl
      ? `<a href="${esc(f.pluginPageUrl)}" target="_blank" rel="noopener noreferrer">Plugin ↗</a>`
      : "");
  tr.innerHTML =
    `<td>${esc(f.pluginId)}</td>` +
    `<td>${esc(f.name)}</td>` +
    `<td class="cve">${esc(f.cves.join(", "))}</td>` +
    `<td class="vpr">${esc(f.vpr)}</td>` +
    `<td class="actions">${actions}</td>`;
  return tr;
}

function scLink(pluginId) {
  return CONFIG.pluginUrlTemplate
    .replace(/\{scUrl\}/g, CONFIG.scUrl.replace(/\/+$/, ""))
    .replace(/\{pluginId\}/g, encodeURIComponent(pluginId));
}

// --- helpers --------------------------------------------------------------

function textColor(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
  if (!m) return "#111";
  const n = parseInt(m[1], 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  // Relative luminance; light bg -> dark text, dark bg -> light text.
  const lum = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  return lum > 0.55 ? "#111" : "#fff";
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

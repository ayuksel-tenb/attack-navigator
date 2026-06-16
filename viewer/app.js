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

const MAX_INLINE_FINDINGS = 100; // cap per technique section, with a "+N more" note

const els = {
  matrix: document.getElementById("matrix"),
  hint: document.getElementById("hint"),
  onlyExposed: document.getElementById("onlyExposed"),
  loadDefault: document.getElementById("loadDefault"),
  fileInput: document.getElementById("fileInput"),
  openSc: document.getElementById("openSc"),
  scInfo: document.getElementById("scInfo"),
};

els.scInfo.textContent = "SC: " + CONFIG.scUrl;

const state = {
  catalog: null,
  byId: {},
  subsByParent: {},
  index: {},
  openId: null, // currently expanded base technique id (accordion)
};

// --- Wiring ---------------------------------------------------------------

els.openSc.addEventListener("click", () => window.open(CONFIG.scUrl, "tenable-sc"));
els.loadDefault.addEventListener("click", () => loadLayer("layers/layer.json"));
els.onlyExposed.addEventListener("change", renderMatrix);
els.fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const r = new FileReader();
  r.onload = () => {
    const layer = safeParse(r.result);
    if (layer) { buildIndex(layer); renderMatrix(); }
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
  } catch { return null; }
}

async function loadLayer(url) {
  const layer = await fetchJson(url);
  if (layer) { buildIndex(layer); renderMatrix(); }
}

function safeParse(t) { try { return JSON.parse(t); } catch { return null; } }

function buildIndex(layer) {
  if (Array.isArray(layer)) layer = layer[0];
  state.index = {};
  state.openId = null;
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
    findings.push(parseFinding(m.name.slice(7).trim(), m.value || "", links));
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
  const name = value.split(" — ")[0].trim();
  const link = links.find((l) => l && l.label && l.label.startsWith(pluginId + ":"));
  return { pluginId, name, cves, vpr, pluginPageUrl: link ? link.url : "" };
}

function getMeta(meta, key) {
  const row = meta.find((m) => m && m.name === key);
  return row ? row.value : undefined;
}

// --- Matrix rendering -----------------------------------------------------

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
  let total = 0;

  for (const tactic of state.catalog.tactics) {
    const bases = state.catalog.techniques.filter(
      (t) => !t.parent && t.tactics.includes(tactic.id)
    );
    let exposedCount = 0;
    const cells = [];
    for (const base of bases) {
      const exp = exposureFor(base.id);
      if (exp.exposed) exposedCount++;
      if (onlyExposed && !exp.exposed) continue;
      cells.push(cellEl(base, exp));
    }
    total += exposedCount;
    if (onlyExposed && exposedCount === 0) continue;

    const col = document.createElement("div");
    col.className = "col";
    const head = document.createElement("div");
    head.className = "col-head";
    head.innerHTML = `<span>${esc(tactic.name)}</span><span class="n">${exposedCount}</span>`;
    const body = document.createElement("div");
    body.className = "col-cells";
    cells.forEach((c) => body.appendChild(c));
    col.append(head, body);
    els.matrix.appendChild(col);
  }

  els.hint.textContent = onlyExposed
    ? `${total} exposed technique(s) across the matrix. Click one to expand its vulnerabilities.`
    : "Click a colored (exposed) technique to expand its vulnerabilities.";
}

function cellEl(base, exp) {
  const cell = document.createElement("div");
  cell.className = "cell " + (exp.exposed ? "exposed" : "dim");
  cell.dataset.id = base.id;
  if (exp.exposed) {
    cell.style.background = exp.color;
    cell.style.color = textColor(exp.color);
    cell.style.borderColor = "rgba(0,0,0,0.25)";
  }
  const score = exp.score !== null ? `<span class="score">${exp.score.toFixed(0)}</span>` : "";
  const subsNote = exp.subs.length
    ? `<span class="subs-note">▸ ${exp.subs.length} sub-technique${exp.subs.length > 1 ? "s" : ""}</span>`
    : "";
  cell.innerHTML =
    `<div class="cell-top"><span class="tid">${esc(base.id)}</span>${score}</div>` +
    `<span class="tname">${esc(base.name)}</span>${subsNote}`;
  if (exp.exposed) cell.addEventListener("click", () => toggleCell(cell, base, exp));
  return cell;
}

// --- Inline expansion (accordion) -----------------------------------------

function toggleCell(cell, base, exp) {
  const isOpen = cell.classList.contains("open");
  // Close any other open cell (one at a time keeps the matrix tidy).
  if (state.openId && state.openId !== base.id) {
    const prev = els.matrix.querySelector('.cell.open[data-id="' + cssEsc(state.openId) + '"]');
    if (prev) collapse(prev);
  }
  if (isOpen) { collapse(cell); state.openId = null; return; }

  const detail = document.createElement("div");
  detail.className = "cell-detail";
  detail.addEventListener("click", (e) => e.stopPropagation()); // clicks inside don't re-toggle

  const entries = [];
  if (exp.direct) entries.push({ id: base.id, name: base.name, info: exp.direct });
  for (const s of exp.subs) entries.push(s);

  for (const e of entries) {
    if (entries.length > 1 || e.id !== base.id) {
      const sh = document.createElement("div");
      sh.className = "sec-head";
      const review = e.info.needsReview ? '<span class="badge-review">review</span>' : "";
      sh.innerHTML = `<b>${esc(e.id)}</b> ${esc(e.name)}${review} · ${e.info.count}`;
      detail.appendChild(sh);
    }
    const shown = e.info.findings.slice(0, MAX_INLINE_FINDINGS);
    for (const f of shown) detail.appendChild(findingRow(f));
    if (e.info.findings.length > shown.length) {
      const more = document.createElement("div");
      more.className = "more";
      more.textContent = `+${e.info.findings.length - shown.length} more finding(s)`;
      detail.appendChild(more);
    }
  }

  cell.appendChild(detail);
  cell.classList.add("open");
  state.openId = base.id;
}

function collapse(cell) {
  const d = cell.querySelector(".cell-detail");
  if (d) d.remove();
  cell.classList.remove("open");
}

function findingRow(f) {
  const row = document.createElement("div");
  row.className = "fr";
  const meta = [f.cves.join(", "), f.vpr ? "VPR " + f.vpr : ""].filter(Boolean).join(" · ");
  row.innerHTML =
    `<div class="fr-name">${esc(f.pluginId)} · ${esc(f.name)}</div>` +
    (meta ? `<div class="fr-meta">${esc(meta)}</div>` : "") +
    `<a href="${esc(scLink(f.pluginId))}" target="tenable-sc">Open in SC ↗</a>` +
    (f.pluginPageUrl
      ? `<a href="${esc(f.pluginPageUrl)}" target="_blank" rel="noopener noreferrer">Plugin ↗</a>`
      : "");
  return row;
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
  const lum = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  return lum > 0.55 ? "#111" : "#fff";
}

function cssEsc(s) {
  return String(s).replace(/["\\]/g, "\\$&");
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

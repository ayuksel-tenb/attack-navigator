"use strict";

// Runtime config: injected by gen-config.sh (Docker) via config.js, with safe
// defaults for opening the page directly without the container.
const CONFIG = Object.assign(
  {
    scUrl: "https://localhost:8443",
    // Tenable.sc cumulative-vulnerabilities view filtered to one plugin. The hash
    // route carries a URL-encoded JSON filter; {pluginId} sits in its "value".
    pluginUrlTemplate:
      "{scUrl}/#vulnerabilities/cumulative/listvuln/%7B%22filt%22%3A%5B%7B%22id%22%3A%22pluginID%22%2C%22filterName%22%3A%22pluginID%22%2C%22operator%22%3A%22%3D%22%2C%22type%22%3A%22vuln%22%2C%22isPredefined%22%3Atrue%2C%22value%22%3A%22{pluginId}%22%7D%5D%2C%22sortCol%22%3A%22none%22%2C%22sortDir%22%3A%22desc%22%7D/0/0",
  },
  window.TAM_CONFIG || {}
);

const els = {
  techniques: document.getElementById("techniques"),
  hint: document.getElementById("hint"),
  scInfo: document.getElementById("scInfo"),
  fileInput: document.getElementById("fileInput"),
  loadDefault: document.getElementById("loadDefault"),
  openSc: document.getElementById("openSc"),
};

els.scInfo.textContent = "SC: " + CONFIG.scUrl;

// Open Security Center in the shared "tenable-sc" window so the user can log in
// once; every "Open in SC" link then reuses that authenticated tab.
els.openSc.addEventListener("click", () => {
  window.open(CONFIG.scUrl, "tenable-sc");
});

// --- Event wiring -----------------------------------------------------------

els.loadDefault.addEventListener("click", () => loadFromUrl("layers/layer.json"));
els.fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => handleLayer(safeParse(reader.result), file.name);
  reader.readAsText(file);
});

// Try to auto-load the default layer on first paint.
loadFromUrl("layers/layer.json", { quiet: true });

// --- Loading ----------------------------------------------------------------

async function loadFromUrl(url, opts = {}) {
  try {
    const resp = await fetch(url, { cache: "no-store" });
    if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
    handleLayer(await resp.json(), url.split("/").pop());
  } catch (err) {
    if (!opts.quiet) renderEmpty("Could not load " + url + ": " + err.message);
  }
}

function safeParse(text) {
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

function handleLayer(layer, sourceName) {
  // The standard Navigator format allows a single layer or a list of layers.
  if (Array.isArray(layer)) layer = layer[0];
  if (!layer || !Array.isArray(layer.techniques)) {
    renderEmpty("That file is not a valid ATT&CK Navigator layer.");
    return;
  }
  const techniques = layer.techniques
    .map(parseTechnique)
    .filter((t) => t.score !== null)
    .sort((a, b) => b.score - a.score);
  render(techniques);
}

// --- Parsing the standard layer format --------------------------------------

function parseTechnique(t) {
  const meta = t.metadata || [];
  const links = t.links || [];
  const comment = t.comment || "";
  // First comment line is the technique name when it isn't a stat line.
  const firstLine = comment.split("\n")[0] || "";
  const name = /^\d|finding/i.test(firstLine) ? "" : firstLine;

  const findings = [];
  for (const m of meta) {
    if (!m || !m.name || !m.name.startsWith("plugin ")) continue;
    const pluginId = m.name.slice("plugin ".length).trim();
    findings.push(parseFinding(pluginId, m.value || "", links));
  }

  return {
    id: t.techniqueID,
    name: name,
    score: typeof t.score === "number" ? t.score : null,
    color: t.color || "#666",
    needsReview: getMeta(meta, "needs_review") === "true",
    count: parseInt(getMeta(meta, "findings") || findings.length, 10) || findings.length,
    totalVpr: getMeta(meta, "total_vpr") || "",
    findings: findings,
  };
}

function parseFinding(pluginId, value, links) {
  const cves = value.match(/CVE-\d{4}-\d+/gi) || [];
  const vprMatch = value.match(/VPR\s+([\d.]+)/i);
  const hostsMatch = value.match(/×(\d+)\s*hosts/i);
  // The first " — " segment is the plugin name.
  const name = value.split(" — ")[0].trim();
  // Public plugin page comes from the matching link, when present.
  const link = links.find(
    (l) => l && l.label && l.label.startsWith(pluginId + ":")
  );
  return {
    pluginId: pluginId,
    name: name,
    cves: cves,
    vpr: vprMatch ? vprMatch[1] : "",
    hosts: hostsMatch ? hostsMatch[1] : "",
    pluginPageUrl: link ? link.url : "",
  };
}

function getMeta(meta, key) {
  const row = meta.find((m) => m && m.name === key);
  return row ? row.value : undefined;
}

// --- Rendering --------------------------------------------------------------

function render(techniques) {
  if (!techniques.length) {
    renderEmpty("No scored techniques in this layer.");
    return;
  }
  els.hint.style.display = "";
  els.techniques.innerHTML = "";
  for (const t of techniques) els.techniques.appendChild(techniqueEl(t));
}

function renderEmpty(message) {
  els.hint.style.display = "none";
  els.techniques.innerHTML = '<div class="empty">' + esc(message) + "</div>";
}

function techniqueEl(t) {
  const wrap = document.createElement("div");
  wrap.className = "tech";

  const head = document.createElement("div");
  head.className = "tech-head";
  head.innerHTML =
    '<span class="swatch" style="background:' + esc(t.color) + '"></span>' +
    '<div class="score-bar"><span style="width:' + Math.max(2, t.score) +
      "%;background:" + esc(t.color) + '"></span></div>' +
    '<div class="tech-id">' + esc(t.id) +
      '<span class="name">' + esc(t.name) + "</span>" +
      (t.needsReview ? '<span class="badge-review">needs review</span>' : "") +
    "</div>" +
    '<div class="count">' + t.count + " finding(s)" +
      (t.totalVpr ? " · VPR " + esc(t.totalVpr) : "") + "</div>" +
    '<div class="score-val">' + t.score.toFixed(0) + "</div>";
  head.addEventListener("click", () => wrap.classList.toggle("open"));

  const body = document.createElement("div");
  body.className = "findings";
  body.appendChild(findingsTable(t.findings));

  wrap.appendChild(head);
  wrap.appendChild(body);
  return wrap;
}

function findingsTable(findings) {
  if (!findings.length) {
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = "No per-finding detail recorded in this layer.";
    return d;
  }
  const table = document.createElement("table");
  table.innerHTML =
    "<thead><tr><th>Plugin</th><th>Vulnerability</th><th>CVE</th>" +
    "<th>VPR</th><th>Hosts</th><th>Actions</th></tr></thead>";
  const tbody = document.createElement("tbody");
  for (const f of findings) tbody.appendChild(findingRow(f));
  table.appendChild(tbody);
  return table;
}

function findingRow(f) {
  const tr = document.createElement("tr");
  const scUrl = scLink(f.pluginId);
  // All "Open in SC" links share one named window ("tenable-sc"), so you log in
  // once and every later click reuses that already-authenticated tab instead of
  // spawning a fresh tab that asks for login again. (No rel=noopener here — it
  // would prevent reusing the named window.)
  const actions =
    '<a href="' + esc(scUrl) + '" target="tenable-sc">Open in SC ↗</a>' +
    (f.pluginPageUrl
      ? '<a href="' + esc(f.pluginPageUrl) + '" target="_blank" rel="noopener noreferrer">Plugin page ↗</a>'
      : "");
  tr.innerHTML =
    "<td>" + esc(f.pluginId) + "</td>" +
    "<td>" + esc(f.name) + "</td>" +
    '<td class="cve">' + esc(f.cves.join(", ")) + "</td>" +
    '<td class="vpr">' + esc(f.vpr) + "</td>" +
    "<td>" + esc(f.hosts) + "</td>" +
    '<td class="actions">' + actions + "</td>";
  return tr;
}

// Build the Security Center deep link for one plugin from the configured template.
function scLink(pluginId) {
  return CONFIG.pluginUrlTemplate
    .replace(/\{scUrl\}/g, CONFIG.scUrl.replace(/\/+$/, ""))
    .replace(/\{pluginId\}/g, encodeURIComponent(pluginId));
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

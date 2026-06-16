# attack-navigator — on-prem ATT&CK matrix viewer

Companion to **[tenable-attack-mapper](https://github.com/ayuksel-tenb/tenable-attack-mapper)**.
A local **ATT&CK matrix** UI you bring up with one `docker compose` command — your
exposure data never leaves the machine. Click a technique to see the vulnerabilities
behind it (with an ⓘ rationale), and click a finding to open its detail page on your
own Security Center.

> Usually you don't run this directly — just tell tenable-attack-mapper **"open the
> attack matrix"** and its `show-matrix` skill clones this, maps your findings, brings
> it up, and opens the browser.

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/ayuksel-tenb/attack-navigator
cd attack-navigator
```

### 2. Configure

```bash
cp .env.example .env        # set SC_URL to your Security Center (for "Open in SC" links)
```

### 3. Use

Drop a layer from tenable-attack-mapper into `layers/layer.json`, then:

```bash
docker compose up -d viewer
open http://localhost:8080            # macOS · Linux: xdg-open · Windows: start
```

A sample layer is bundled, so it works out of the box. The matrix is colored by VPR
exposure; "Only exposed" toggles the full matrix vs. just what's exposed.

> Also bundles the official MITRE ATT&CK Navigator (`docker compose up -d --build navigator`,
> `http://localhost:4200`) for standard-format viewing.

---

## How it stays on-prem

Both services run in local containers; `layers/*.json` is git-ignored (your exposure
data is never committed) and the SC URL is injected at container start from `.env`.

| Variable | Purpose | Default |
|---|---|---|
| `SC_URL` | Security Center base URL for "Open in SC" links | `https://localhost:8443` |
| `VIEWER_PORT` / `NAVIGATOR_PORT` | host ports if 8080/4200 are taken | `8080` / `4200` |
| `SC_PLUGIN_URL_TEMPLATE` | per-plugin SC deep-link (`{scUrl}`, `{pluginId}`) | Tenable.sc cumulative-vuln view |

## License

MIT — see [LICENSE](LICENSE).

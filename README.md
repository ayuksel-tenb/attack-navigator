# attack-navigator — on-prem viewer for tenable-attack-mapper layers

A self-hosted companion to
[**tenable-attack-mapper**](https://github.com/ayuksel-tenb/tenable-attack-mapper).
Bring up a local UI with `docker compose up` and analyze your exposure with all
the drill-downs you want — **your data never leaves the machine** (no cloud, no
public Navigator instance).

It ships **two** ways to look at the same standard ATT&CK Navigator layer:

1. **Custom viewer** (`http://localhost:8080`) — better UX for this use case:
   click a technique to expand the **vulnerabilities behind it**, and click a
   finding to open its **detail page on your own Security Center** (the SC URL
   comes from your `.env`, never hard-coded).
2. **Official MITRE ATT&CK Navigator** (`http://localhost:4200`) — the stock
   matrix UI, for anyone who wants the standard tool. The layer is plain
   Navigator v4.5 format, so it loads anywhere.

> Standalone by design. The core mapper stays clean and headless; this is a
> separate, optional project you stand up only when you want a UI on-prem.

---

## Quick start

```bash
# 1. point it at your Security Center (for the "Open in SC" deep links)
cp .env.example .env          # edit SC_URL

# 2. bring it up (first run builds the official Navigator from source)
docker compose up --build

# 3. drop a layer in and open the viewer
#    (a sample layer is already included so it works out of the box)
open http://localhost:8080
```

To view a layer you generated with the mapper:

```bash
# from the tenable-attack-mapper repo:
tenable-attack-mapper run --repo 1 --out /tmp/layer.json

# then load it here:
bin/load-layer.sh /tmp/layer.json
# refresh http://localhost:8080  (the viewer auto-loads layers/layer.json)
```

---

## Session — an end-to-end on-prem analysis

A full local workflow, nothing leaving the host:

1. **Generate** a VPR-scored layer from Security Center with the mapper:
   ```bash
   tenable-attack-mapper run --repo 1 --out /tmp/layer.json --report /tmp/coverage.md
   ```
2. **Load** it into this viewer:
   ```bash
   bin/load-layer.sh /tmp/layer.json
   ```
3. **Open** `http://localhost:8080`. Techniques are listed by exposure, darkest
   (highest VPR-weighted score) first.
4. **Click a hot technique** (e.g. *Exploit Public-Facing Application / T1190*).
   It expands into a table of the vulnerabilities driving it — plugin, CVE, VPR,
   host count.
5. **Click “Open in SC ↗”** on a finding. The viewer opens that plugin’s
   vulnerability detail on **your** Security Center (`SC_URL` from `.env`), so you
   go straight from “this technique is exposed” to “here are the exact hosts to
   fix.” “Plugin page ↗” opens the public Tenable plugin reference instead.
6. Need the stock matrix? Open the same layer in the official Navigator:
   `http://localhost:4200/#layerURL=http://localhost:8080/layers/layer.json`.

Because both services run locally and `layers/*.json` is git-ignored, your
exposure data is never uploaded anywhere or committed.

---

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `SC_URL` | Security Center base URL for “Open in SC” links | `https://localhost:8443` |
| `SC_PLUGIN_URL_TEMPLATE` | Per-plugin deep-link template (`{scUrl}`, `{pluginId}`) | Tenable.sc cumulative-vulnerabilities view filtered to the plugin (see below) |

The default deep-link opens Tenable.sc’s **cumulative vulnerabilities** view
filtered to one plugin (the hash route carries a URL-encoded JSON filter where
`{pluginId}` is the filter `value`):

```
{scUrl}/#vulnerabilities/cumulative/listvuln/%7B%22filt%22%3A%5B%7B%22id%22%3A%22pluginID%22%2C%22filterName%22%3A%22pluginID%22%2C%22operator%22%3A%22%3D%22%2C%22type%22%3A%22vuln%22%2C%22isPredefined%22%3Atrue%2C%22value%22%3A%22{pluginId}%22%7D%5D%2C%22sortCol%22%3A%22none%22%2C%22sortDir%22%3A%22desc%22%7D/0/0
```

If your SC version routes differently, override `SC_PLUGIN_URL_TEMPLATE` in
`.env` — it’s a one-line change, no rebuild.

Running the viewer **without Docker?** Copy `viewer/config.example.js` to
`viewer/config.js`, set your values, and serve the `viewer/` + `layers/` folders
with any static server.

---

## How it stays on-prem

- The viewer and the layer file server both run in local containers.
- `layers/*.json` is git-ignored (except the bundled `sample-layer.json`), so you
  can’t accidentally commit real exposure data.
- The SC URL is injected at container start from your `.env`; it’s never baked
  into an image or the repo.

---

## Project layout

```
docker-compose.yml         # viewer + official navigator
viewer/                    # custom UI (vanilla JS, no build step)
  index.html  app.js  styles.css  config.example.js
nginx/viewer.conf          # serves viewer + layers (CORS for the official Nav)
bin/gen-config.sh          # writes viewer/config.js from SC_URL at start
bin/load-layer.sh          # copy a generated layer into ./layers
layers/                    # drop layer.json here (git-ignored; sample committed)
```

## License

MIT — see [LICENSE](LICENSE).

// Example runtime config. In Docker this file is generated as config.js from the
// SC_URL / SC_PLUGIN_URL_TEMPLATE environment variables (see bin/gen-config.sh).
// To run the viewer without Docker, copy this to config.js and edit the values.
window.TAM_CONFIG = {
  scUrl: "https://localhost:8443",
  // {scUrl} and {pluginId} are substituted at click time. This targets Tenable.sc's
  // cumulative-vulnerabilities view filtered to the plugin; tune if your SC differs.
  pluginUrlTemplate:
    "{scUrl}/#vulnerabilities/cumulative/listvuln/%7B%22filt%22%3A%5B%7B%22id%22%3A%22pluginID%22%2C%22filterName%22%3A%22pluginID%22%2C%22operator%22%3A%22%3D%22%2C%22type%22%3A%22vuln%22%2C%22isPredefined%22%3Atrue%2C%22value%22%3A%22{pluginId}%22%7D%5D%2C%22sortCol%22%3A%22none%22%2C%22sortDir%22%3A%22desc%22%7D/0/0",
};

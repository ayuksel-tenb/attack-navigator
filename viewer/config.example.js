// Example runtime config. In Docker this file is generated as config.js from the
// SC_URL / SC_PLUGIN_URL_TEMPLATE environment variables (see bin/gen-config.sh).
// To run the viewer without Docker, copy this to config.js and edit the values.
window.TAM_CONFIG = {
  scUrl: "https://localhost:8443",
  // {scUrl} and {pluginId} are substituted at click time. Tune the path to your
  // Security Center version if its deep-link route differs.
  pluginUrlTemplate:
    "{scUrl}/#/analysis/vulnerabilities/sumid?sourceType=cumulative&pluginID={pluginId}",
};

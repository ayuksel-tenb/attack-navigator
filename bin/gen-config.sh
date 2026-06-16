#!/bin/sh
# Generates the viewer's runtime config from environment variables at container
# start, so the SC base URL never has to be baked into the image or committed.
set -e

: "${SC_URL:=https://localhost:8443}"
: "${SC_PLUGIN_URL_TEMPLATE:={scUrl}/#/analysis/vulnerabilities/sumid?sourceType=cumulative&pluginID={pluginId}}"

cat > /usr/share/nginx/html/config.js <<EOF
// Generated at container start from environment variables — do not edit by hand.
window.TAM_CONFIG = {
  scUrl: "${SC_URL}",
  pluginUrlTemplate: "${SC_PLUGIN_URL_TEMPLATE}"
};
EOF

echo "tam-config: scUrl=${SC_URL}"

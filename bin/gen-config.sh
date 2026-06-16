#!/bin/sh
# Generates the viewer's runtime config from environment variables at container
# start, so the SC base URL never has to be baked into the image or committed.
set -e

: "${SC_URL:=https://localhost:8443}"

# The default deep-link template contains literal { } braces ({scUrl}/{pluginId}),
# which can't live in a compose/shell ${VAR:-default}. Assign it with single
# quotes so every character stays literal; only fall back when no override is set.
if [ -z "${SC_PLUGIN_URL_TEMPLATE:-}" ]; then
  SC_PLUGIN_URL_TEMPLATE='{scUrl}/#vulnerabilities/cumulative/listvuln/%7B%22filt%22%3A%5B%7B%22id%22%3A%22pluginID%22%2C%22filterName%22%3A%22pluginID%22%2C%22operator%22%3A%22%3D%22%2C%22type%22%3A%22vuln%22%2C%22isPredefined%22%3Atrue%2C%22value%22%3A%22{pluginId}%22%7D%5D%2C%22sortCol%22%3A%22none%22%2C%22sortDir%22%3A%22desc%22%7D/0/0'
fi

cat > /usr/share/nginx/html/config.js <<EOF
// Generated at container start from environment variables — do not edit by hand.
window.TAM_CONFIG = {
  scUrl: "${SC_URL}",
  pluginUrlTemplate: "${SC_PLUGIN_URL_TEMPLATE}"
};
EOF

echo "tam-config: scUrl=${SC_URL}"

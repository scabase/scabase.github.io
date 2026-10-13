#!/bin/sh
# ScaBase · 容器启动时按环境变量生成前端运行时配置
# 由 nginx 官方镜像的 /docker-entrypoint.d/ 自动执行（在 nginx 启动之前）。
set -eu

CONF_DIR=/usr/share/nginx/html/assets
CONF_FILE="$CONF_DIR/config.js"

OFFLINE="${SCABASE_OFFLINE:-false}"
OSV_API="${SCABASE_OSV_API:-https://api.osv.dev/v1/query}"
OSV_VULN_API="${SCABASE_OSV_VULN_API:-https://api.osv.dev/v1/vulns/}"
OSV_WEB="${SCABASE_OSV_WEB:-https://osv.dev/vulnerability/}"
NVD_WEB="${SCABASE_NVD_WEB:-https://nvd.nist.gov/vuln/detail/}"

# 去掉可能破坏 JS 字面量的引号与反斜杠
sanitize() { printf '%s' "$1" | tr -d "\"'\\"; }

OFFLINE=$(sanitize "$OFFLINE")
OSV_API=$(sanitize "$OSV_API")
OSV_VULN_API=$(sanitize "$OSV_VULN_API")
OSV_WEB=$(sanitize "$OSV_WEB")
NVD_WEB=$(sanitize "$NVD_WEB")

mkdir -p "$CONF_DIR"
cat > "$CONF_FILE" <<EOF
/* 由容器启动脚本生成（docker/10-env-config.sh），请勿手工编辑 */
window.SCABASE_CONFIG = {
  offline: "$OFFLINE" === "true",
  osvApi: "$OSV_API",
  osvVulnApi: "$OSV_VULN_API",
  osvWeb: "$OSV_WEB",
  nvdWeb: "$NVD_WEB"
};
EOF

chmod 644 "$CONF_FILE" 2>/dev/null || true
echo "[scabase] runtime config written: offline=$OFFLINE osvApi=$OSV_API"

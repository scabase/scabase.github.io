#!/bin/sh
# ScaBase · 内网定时导入与评估任务
#
# 扫描摆渡目录中的数据包 → 按 seq 顺序导入 → 生成群组评估报告。
# 处理成功的包会被移到 imported/，避免重复导入触发 seq 回退告警。
set -eu

FACTS="${SCABASE_FACTS_DIR:-/data/facts}"
FERRY="${SCABASE_FERRY_DIR:-/data/ferry}"
REPORTS="${SCABASE_REPORT_DIR:-/data/reports}"
ASSETS="${SCABASE_ASSETS:-}"
BASE_DIR="${SCABASE_BASE_DIR:-/work}"
INTERVAL="${SCABASE_SYNC_INTERVAL:-3600}"

mkdir -p "$FACTS" "$FERRY" "$FERRY/imported" "$REPORTS"

while true; do
  for bundle in "$FERRY"/*.tar.gz; do
    [ -e "$bundle" ] || continue
    echo "[intake] 导入 $(basename "$bundle")"
    if python -m oss_intake.cli import --facts "$FACTS" --bundle "$bundle"; then
      mv "$bundle" "$FERRY/imported/" 2>/dev/null || true
    else
      echo "[intake] 导入失败，保留在摆渡目录：$bundle"
    fi
  done

  if [ -n "$ASSETS" ] && [ -f "$ASSETS" ]; then
    echo "[intake] 生成群组评估报告"
    python -m oss_intake.cli assess \
      --facts "$FACTS" \
      --assets "$ASSETS" \
      --base-dir "$BASE_DIR" \
      --md "$REPORTS/group-assessment.md" || echo "[intake] 评估失败"
  fi

  sleep "$INTERVAL"
done

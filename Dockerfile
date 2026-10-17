# ScaBase · 静态站点镜像（nginx:alpine）
# 构建：docker build -t scabase:latest .
# 运行：docker run -d -p 8080:8080 -e SCABASE_OFFLINE=true scabase:latest
#
# 多架构：docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/roweb/scabase:latest --push .
FROM nginx:1.27-alpine

LABEL org.opencontainers.image.title="ScaBase" \
      org.opencontainers.image.description="开源组件漏洞查询（OSV + NVD），结果以 CVE 编号呈现" \
      org.opencontainers.image.source="https://github.com/scabase/scabase.github.io" \
      org.opencontainers.image.licenses="MIT"

ARG VERSION=dev
ARG BUILD_DATE=""
ENV SCABASE_OFFLINE=false \
    SCABASE_OSV_API="https://api.osv.dev/v1/query" \
    SCABASE_OSV_VULN_API="https://api.osv.dev/v1/vulns/" \
    SCABASE_OSV_WEB="https://osv.dev/vulnerability/" \
    SCABASE_NVD_WEB="https://nvd.nist.gov/vuln/detail/" \
    VERSION=${VERSION} \
    BUILD_DATE=${BUILD_DATE}

# nginx 以非 root 用户运行，需提前放开 conf.d 缓存目录写入权限
RUN mkdir -p /var/cache/nginx /var/log/nginx && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx /usr/share/nginx/html

# nginx 站点配置（监听 8080，兼容 OpenShift / 非 root 场景）
COPY docker/nginx-default.conf /etc/nginx/conf.d/default.conf

# 容器启动脚本：按环境变量生成 assets/config.js
COPY docker/10-env-config.sh /docker-entrypoint.d/10-env-config.sh
RUN chmod +x /docker-entrypoint.d/10-env-config.sh

# 站点静态文件
COPY index.html /usr/share/nginx/html/index.html
COPY llms.txt /usr/share/nginx/html/llms.txt
COPY assets/ /usr/share/nginx/html/assets/
COPY scabase-fetcher/data/ /usr/share/nginx/html/scabase-fetcher/data/

# 给静态资源 URL 附加内容版本号（与 pages.yml 一致）。
# nginx 对 /assets/ 缓存 1 小时（max-age=3600），而 index.html 为 no-cache：
# 只更新 HTML 会拿到「新页面 + 旧脚本」，表现为 tab 切换等交互点了没反应。
RUN V="$(cat /usr/share/nginx/html/assets/app.js /usr/share/nginx/html/assets/style.css /usr/share/nginx/html/assets/config.js | sha256sum | cut -c1-10)" && \
    sed -i -E 's#(assets/(app\.js|style\.css|config\.js))#\1?v='"${V}"'#g' /usr/share/nginx/html/index.html

# 漏洞库目录可在运行时挂载外部数据覆盖，无需重建镜像：
#   -v ./data:/usr/share/nginx/html/scabase-fetcher/data:ro

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]

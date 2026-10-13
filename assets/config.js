/* ScaBase 运行时配置
 *
 * Docker / 内网部署时，容器启动脚本会覆盖本文件（见 docker/10-env-config.sh），
 * 通过环境变量注入：
 *   SCABASE_OFFLINE   true / false   离线模式：禁用实时 OSV 请求，仅查本地漏洞库
 *   SCABASE_OSV_API   OSV API 地址   内网自建 OSV 代理时填写
 *   SCABASE_NVD_BASE  NVD 详情地址前缀
 *
 * GitHub Pages 部署时保持下方默认值即可。
 */
window.SCABASE_CONFIG = {
  offline: false,
  osvApi: "https://api.osv.dev/v1/query",
  osvVulnApi: "https://api.osv.dev/v1/vulns/",
  osvWeb: "https://osv.dev/vulnerability/",
  nvdWeb: "https://nvd.nist.gov/vuln/detail/"
};

# ScaBase
> ScaBase: Open Source Software Composition Analysis (SCA) Platform
[](https://github.com/scabase/scabase-fetcher/actions)
[](https://osv.dev/)
[](LICENSE)

Online Site: https://scabase.roweb.cn

## Introduction
ScaBase is an open-source SCA (Software Composition Analysis) vulnerability query platform built for DevSecOps and application security teams.
It supports vulnerability lookup for open-source packages across **Maven / NPM / PyPI / Go**, powered by OSV and NVD dual vulnerability databases.

- ✅ Multi ecosystem support: Maven GAV, NPM, Python PyPI, Go Module
- ✅ Data sources: OSV as primary source, NVD for standard CVSS / CWE enrichment
- ✅ Auto update: GitHub Actions scheduled workflow to fetch latest vulnerabilities
- ✅ Static frontend: No backend server, deploy on GitHub Pages or Cloudflare Pages
- ✅ Optional backup: Sync vulnerability JSON to your personal NAS via Cloudflare R2

> SCA (Software Composition Analysis): Identify third-party open-source dependencies in your project and query CVE risk information for software supply chain security.

## Repo Organization
This GitHub organization contains multiple repositories:
- `scabase-fetcher`: Vulnerability collector script + GitHub Actions workflow, generates `data/vulns.json`
- `scabase-web`: Static website frontend for vulnerability search
- `scabase-docs`: Project documentation and user guides

### Directory Structure (scabase-fetcher)
scabase-fetcher/
├── .github/workflows/update-vuln.yml   # GitHub Action scheduled task
├── scripts/fetch_osv\[_nvd.py](_nvd.py)            # OSV + NVD vulnerability fetcher
└── data/
├── pkg_list.txt                    # Watchlist of packages
└── vulns.json                      # Auto-generated vulnerability database
## Package Watchlist Format `data/pkg_list.txt`
Format: `ecosystem|package|version`
```txt
# ecosystem: maven / npm / pypi / go
# Maven package uses groupId:artifactId
maven|org.springframework.boot:spring-boot-starter-web|2.7.0
maven|com.alibaba:fastjson|1.2.24
npm|lodash|4.17.20
pypi|requests|2.20.0
go|github.com/gin-gonic/gin|1.6.0
How it works
1. GitHub Actions runs automatically at UTC 02:00 daily, also supports manual trigger.
2. Reads pkg_list.txt, queries OSV API for vulnerabilities of each package.
3. For entries with CVE IDs, fetch NVD API to enrich CVSS score and CWE details.
4. Merge all vulnerability data into data/vulns.json and commit back to repository.
5. Static web frontend loads vulns.json and provides browser-based search.
6. Optional: Upload vulns.json to Cloudflare R2, NAS periodically pull for local backup.
Deployment Guide
1. Repository Configuration
1. Clone or fork this repository
2. Go to repository Settings → Actions → General → Workflow permissions
Enable Read and write permissions, required for bot commit.
3. [Optional] Apply NVD API Key: https://nvd.nist.gov/developers/request-an-api-key
Add repository secret named NVD_API_KEY to improve NVD request rate limit.
2. Run Collector Workflow
- Automatic: Runs daily at UTC 02:00
- Manual trigger: Actions → Update SCA Vulnerability Data → Run workflow
After workflow completes, data/vulns.json will be updated.
3. Deploy Web Frontend
This site is fully static and supports two deployment paths: **GitHub Pages (public)** and **Docker (intranet / offline)**.

#### Option A: GitHub Pages
1. Repo Settings → Pages → Build and deployment → Source = **GitHub Actions**.
2. Every push to `main` triggers `.github/workflows/pages.yml`, which assembles `_site`
   (index.html + assets + scabase-fetcher/data + CNAME) and publishes it.
3. Custom domain: edit the `CNAME` file at repo root (currently `scabase.roweb.cn`) and point
   a DNS CNAME record to `<org>.github.io`.
4. Manual run: Actions → Deploy GitHub Pages → Run workflow.

> `.nojekyll` is included so Jekyll does not skip underscore directories.

#### Option B: Docker (intranet / offline)
Image is based on `nginx:1.27-alpine` (`Dockerfile`); the CI workflow
`.github/workflows/docker.yml` builds `linux/amd64,linux/arm64`, pushes to Alibaba Cloud
Container Registry, and also publishes an offline-loadable image tar artifact.

```bash
# 1) Build locally and start
docker compose up -d          # or: docker build -t scabase:latest .
# visit http://<intranet-ip>:8080

# 2) Use the CI-built image
docker pull registry.cn-hangzhou.aliyuncs.com/roweb/scabase:latest
docker run -d --name scabase -p 8080:8080 \
  -e SCABASE_OFFLINE=true \
  registry.cn-hangzhou.aliyuncs.com/roweb/scabase:latest

# 3) Fully offline (no registry access): import the artifact tar
docker load -i scabase-linux-amd64.tar     # arm64: scabase-linux-arm64.tar
docker run -d --name scabase -p 8080:8080 -e SCABASE_OFFLINE=true scabase:latest
```

Runtime environment variables (written into `assets/config.js` at container start, no rebuild needed):

| Variable | Default | Description |
| --- | --- | --- |
| `SCABASE_OFFLINE` | `false` | When `true`, disables live OSV requests; only the bundled local DB is queried and an "offline" badge is shown |
| `SCABASE_OSV_API` | `https://api.osv.dev/v1/query` | Point to a self-hosted OSV proxy (turn off offline mode first) |
| `SCABASE_OSV_VULN_API` | `https://api.osv.dev/v1/vulns/` | OSV single-vuln endpoint |
| `SCABASE_OSV_WEB` | `https://osv.dev/vulnerability/` | OSV detail page prefix |
| `SCABASE_NVD_WEB` | `https://nvd.nist.gov/vuln/detail/` | NVD detail page prefix |

Refresh the vulnerability DB without rebuilding the image:

```bash
docker run -d --name scabase -p 8080:8080 -e SCABASE_OFFLINE=true \
  -v /opt/scabase/data:/usr/share/nginx/html/scabase-fetcher/data:ro \
  scabase:latest
```

> The container listens on **8080** (unprivileged port, nginx runs as non-root);
> `/healthz` is provided for health checks in both the image and compose file.
Extended Features
- 🔔 Vulnerability alert: Send DingTalk / WeCom notification when new CVE found
- 📄 SBOM parser: Auto generate pkg_list from pom.xml / package.json / go.mod
- ☁️ Cloudflare R2 + NAS backup pipeline
- 📊 Export vulnerability report
Data Source Comparison
Source
Purpose
Features
OSV
Primary vulnerability source
Native support for Maven/NPM/PyPI/Go, no API key required, includes GHSA vulnerabilities without CVE
NVD
Supplementary enrichment
NIST official CVE database, provides standard CVSS score and CWE classification, API key recommended
## Open-Source Intake Evaluation (SBOM · offline ferry)

On top of vulnerability lookup, ScaBase ships an **open-source intake evaluation** system:
it unifies internet-side vulnerability intel, component health, license compliance and
intranet application GAV assets into one PURL-keyed fact layer, and supports a
**pre-introduction gate** plus **per-app-group risk assessment**. Fully isolated intranets
are served by signed, incrementally chained bundles ferried one way.

```bash
# Zone A: collect -> fact layer -> build signed bundle
python -m oss_intake.cli bundle --facts scabase-fetcher/data/facts \
  --dataset vulns --out bundles --mode snapshot

# Zone B: verify + import -> intake gate / group assessment
python -m oss_intake.cli import --facts intranet-data/facts --bundle bundles/bundle-vulns-0001-*.tar.gz
python -m oss_intake.cli gate --facts intranet-data/facts --purl pkg:maven/com.alibaba/fastjson@1.2.24 --tier core
python -m oss_intake.cli assess --facts intranet-data/facts --assets examples/assets.json --base-dir .
```

- Specs and change proposal: `openspec/`
- Design and operations guide: [`docs/oss-intake.md`](docs/oss-intake.md)
- Tests: `python -m unittest discover -s tests`

Notes
1. OSV API has rate limits. Add sleep delay in loop when scanning large package lists.
2. NVD API is optional; without a key the fetcher still queries NVD but at a lower rate (configuring NVD_API_KEY is recommended).
3. This project is for vulnerability information lookup only. It does not perform vulnerability exploitation or active scanning.
4. Vulnerability data is for security reference only, and cannot be used as the sole basis for compliance audit.
License
MIT
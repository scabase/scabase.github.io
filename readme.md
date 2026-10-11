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
The static frontend in scabase-web can be deployed on:
- GitHub Pages
- Cloudflare Pages (recommended for global CDN)
Website: https://scabase.roweb.cn
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
Notes
1. OSV API has rate limits. Add sleep delay in loop when scanning large package lists.
2. NVD API is optional; without a key the fetcher still queries NVD but at a lower rate (configuring NVD_API_KEY is recommended).
3. This project is for vulnerability information lookup only. It does not perform vulnerability exploitation or active scanning.
4. Vulnerability data is for security reference only, and cannot be used as the sole basis for compliance audit.
License
MIT
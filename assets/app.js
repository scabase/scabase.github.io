/* ScaBase · 漏洞查询前端
 *
 * 数据来源：
 *   1) 本地漏洞库  scabase-fetcher/data/vulns.json
 *      结构：{ "eco|pkg|ver": { "osv_raw": {vulns:[...]}, "enriched": [{osv, nvd}, ...] }, ... }
 *   2) 实时查询    https://api.osv.dev/v1/query
 *
 * 结果展示以 CVE 编号为主键：
 *   - 一条 OSV 记录可能对应多个 CVE，全部展开（不再只取第一个别名）
 *   - 支持「按组件」/「按 CVE」两种视图
 *   - 支持按 CVE 编号过滤、按严重度 / CVE / 时间排序、一键复制 CVE 清单
 *
 * 输入格式（每行一条，支持 # 注释、空行）：
 *   - CVE 编号     CVE-2021-44228
 *   - pkg_list    ecosystem|package|version      （与 data/pkg_list.txt 一致）
 *   - GAV         groupId:artifactId[:version]   （Maven）
 *   - 简写        ecosystem:package[@version]
 */
(function () {
  "use strict";

  /* 运行时配置（assets/config.js；Docker 部署时由容器启动脚本覆盖） */
  var CONFIG = (typeof window !== "undefined" && window.SCABASE_CONFIG) || {};
  function flag(v) { return v === true || String(v) === "true"; }

  var OFFLINE = flag(CONFIG.offline);          // 内网离线：禁用一切外部请求
  var VULNS_URL = "scabase-fetcher/data/vulns.json";
  var PKG_LIST_URL = "scabase-fetcher/data/pkg_list.txt";
  /* 报告由 community-health.yml 生成并提交到受版本管理的 data 目录，
   * pages.yml / Dockerfile 再随站点一同发布（reports/ 为 gitignore 产物，不入库）。 */
  var HEALTH_URL = CONFIG.healthUrl || "scabase-fetcher/data/community-support.json";
  var POPULAR_URL = CONFIG.popularUrl || "scabase-fetcher/data/popular-packages.json";
  var OSV_API = CONFIG.osvApi || "https://api.osv.dev/v1/query";
  var OSV_VULN = CONFIG.osvWeb || "https://osv.dev/vulnerability/";
  var OSV_VULN_API = CONFIG.osvVulnApi || "https://api.osv.dev/v1/vulns/";
  var NVD_VULN = CONFIG.nvdWeb || "https://nvd.nist.gov/vuln/detail/";
  var CONCURRENCY = 4;

  /* OSV 生态名 + 常用别名 */
  var ECOSYSTEMS = [
    "AlmaLinux", "Alpine", "Android", "Bioconductor", "Bitnami", "CRAN",
    "Chainguard", "ConanCenter", "Debian", "GIT", "GitHub Actions", "Go",
    "Hackage", "Hex", "Linux", "Mageia", "Maven", "NuGet", "OSS-Fuzz",
    "Packagist", "Photon OS", "Pub", "PyPI", "Red Hat", "Rocky Linux",
    "RubyGems", "SwiftURL", "Ubuntu", "Wolfi", "crates.io", "npm", "openSUSE"
  ];
  var ALIASES = {
    pip: "PyPI", python: "PyPI", pypi: "PyPI",
    node: "npm", npm: "npm", javascript: "npm",
    cargo: "crates.io", rust: "crates.io", crates: "crates.io",
    gem: "RubyGems", rubygems: "RubyGems",
    composer: "Packagist", packagist: "Packagist",
    go: "Go", golang: "Go",
    maven: "Maven", java: "Maven", gradle: "Maven",
    nuget: "NuGet", dotnet: "NuGet",
    hex: "Hex", pub: "Pub", hackage: "Hackage", cran: "CRAN",
    deb: "Debian", debian: "Debian", alpine: "Alpine", ubuntu: "Ubuntu"
  };
  var ECO_LOOKUP = {};
  ECOSYSTEMS.forEach(function (e) { ECO_LOOKUP[e.toLowerCase()] = e; });

  /* 严重度 */
  var SEV_RANK = { CRITICAL: 5, HIGH: 4, MODERATE: 3, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 1 };
  var SEV_ZH = {
    CRITICAL: "严重", HIGH: "高危", MODERATE: "中危", MEDIUM: "中危",
    LOW: "低危", NONE: "无", UNKNOWN: "未知"
  };
  var SEV_FILTERS = [
    ["ALL", "全部严重度"], ["CRITICAL", "严重 CRITICAL"], ["HIGH", "高危 HIGH"],
    ["MODERATE", "中危 MODERATE"], ["LOW", "低危 LOW"], ["UNKNOWN", "未知 UNKNOWN"]
  ];
  var SORTS = [
    ["sev", "排序：严重度"], ["cve", "排序：CVE 编号"], ["date", "排序：发布时间"], ["pkg", "排序：组件名"]
  ];

  /* ------------------------------ utils ------------------------------ */
  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function fmtDate(value) {
    if (!value) return "";
    var d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    return d.toISOString().slice(0, 10);
  }

  function dateVal(value) {
    if (!value) return 0;
    var t = new Date(value).getTime();
    return isNaN(t) ? 0 : t;
  }

  function sevRank(label) {
    return SEV_RANK[String(label || "UNKNOWN").toUpperCase()] || 1;
  }

  /* 生态别名 -> OSV 规范名 */
  function canonEco(raw) {
    var key = String(raw || "").trim();
    var lower = key.toLowerCase();
    if (ECO_LOOKUP[lower]) return ECO_LOOKUP[lower];
    if (ALIASES[lower]) return ALIASES[lower];
    return key;
  }

  /* --------------------------- CVE 工具 --------------------------- */
  var CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

  function isCve(x) { return CVE_RE.test(String(x || "").trim()); }

  function normCve(x) { return String(x || "").trim().toUpperCase(); }

  /* 年份新 -> 旧；同年编号大 -> 小 */
  function cveCmp(a, b) {
    if (isCve(a) && isCve(b)) {
      var pa = a.split("-"), pb = b.split("-");
      if (pa[1] !== pb[1]) return Number(pb[1]) - Number(pa[1]);
      return Number(pb[2]) - Number(pa[2]);
    }
    return String(a).localeCompare(String(b));
  }

  function sortCves(list) { return list.slice().sort(cveCmp); }

  function collectCves(osv, nvd) {
    var out = [];
    function push(x) {
      if (!isCve(x)) return;
      var u = normCve(x);
      if (out.indexOf(u) === -1) out.push(u);
    }
    push(osv && osv.id);
    ((osv && osv.aliases) || []).forEach(push);
    push(nvd && nvd.id);
    ((nvd && nvd.aliases) || []).forEach(push);
    return sortCves(out);
  }

  /* --------------------------- 输入解析 --------------------------- */
  /* 返回 { ecosystem, name, version, kind } 或 { kind:'cve', cve } */
  function parseLine(line) {
    var text = line.trim();

    // 0) CVE 编号直查
    if (isCve(text)) return { kind: "cve", cve: normCve(text) };

    // 1) pkg_list 格式：ecosystem|package|version
    if (text.indexOf("|") !== -1) {
      var seg = text.split("|");
      var eco = (seg[0] || "").trim();
      var pkg = (seg[1] || "").trim();
      var ver = seg.length > 2 ? seg[2].trim() : "";
      if (!eco || !pkg) throw new Error("pkg_list 格式需为 ecosystem|package|version：" + text);
      return { ecosystem: canonEco(eco), name: pkg, version: ver || null, kind: "pkg_list" };
    }

    var colon = text.indexOf(":");
    if (colon !== -1) {
      var head = text.slice(0, colon).trim().toLowerCase();

      // 2) 简写：ecosystem:package[@version]
      if (ECO_LOOKUP[head] || ALIASES[head]) {
        var rest = text.slice(colon + 1).trim();
        var at = rest.lastIndexOf("@");
        var name = at > 0 ? rest.slice(0, at).trim() : rest;
        var version = at > 0 ? rest.slice(at + 1).trim() : null;
        if (!name) throw new Error("缺少包名：" + text);
        return { ecosystem: canonEco(head), name: name, version: version || null, kind: "short" };
      }

      // 3) GAV：groupId:artifactId[:version]
      var parts = text.split(":").map(function (s) { return s.trim(); }).filter(Boolean);
      if (parts.length >= 2) {
        return {
          ecosystem: "Maven",
          name: parts[0] + ":" + parts[1],
          version: parts.length >= 3 ? parts[2] : null,
          kind: "gav"
        };
      }
    }
    throw new Error("无法识别（需为 CVE 编号 / pkg_list / GAV / ecosystem:package@version）：" + text);
  }

  function parseInput(raw) {
    var entries = [], errors = [];
    raw.split(/\r?\n/).forEach(function (line, i) {
      var text = line.trim();
      if (!text || text.charAt(0) === "#") return;
      try { entries.push(parseLine(text)); }
      catch (err) { errors.push("第 " + (i + 1) + " 行：" + err.message); }
    });
    return { entries: entries, errors: errors };
  }

  /* --------------------------- 漏洞归一化 --------------------------- */
  function oneUrl(r) { return typeof r === "string" ? r : (r && (r.url || r.link)); }

  function refs(list) {
    if (!Array.isArray(list)) return [];
    return list.map(oneUrl).filter(Boolean);
  }

  function osvSev(v) {
    var db = v.database_specific || {};
    var label = typeof db.severity === "string" ? db.severity : null;
    var vector = null;
    if (Array.isArray(v.severity)) {
      vector = v.severity.map(function (s) { return s && s.score; }).filter(Boolean)[0] || null;
    } else if (typeof v.severity === "string") {
      if (/^[A-Za-z]{3,12}$/.test(v.severity)) label = label || v.severity;
      else vector = v.severity;
    }
    if (!label && db.cvss && typeof db.cvss === "object") label = db.cvss.severity || null;
    return { label: label ? label.toUpperCase() : null, vector: vector };
  }

  function nvdInfo(nvd) {
    var out = { label: null, vector: null, score: null, desc: "", cwe: [] };
    if (!nvd) return out;
    var m = nvd.metrics || {};
    var arr = m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [];
    if (arr[0]) {
      var d = arr[0].cvssData || {};
      out.score = d.baseScore != null ? d.baseScore : null;
      out.label = d.baseSeverity || arr[0].baseSeverity || null;
      out.vector = d.vectorString || null;
    }
    (nvd.weaknesses || []).forEach(function (w) {
      (w.description || []).forEach(function (x) {
        if (x && /^CWE-/.test(x.value || "") && out.cwe.indexOf(x.value) === -1) out.cwe.push(x.value);
      });
    });
    (nvd.descriptions || []).forEach(function (x) {
      if (x && x.lang === "en" && !out.desc) out.desc = x.value || "";
    });
    return out;
  }

  /* item = { osv, nvd } -> 以 CVE 为主键的展示模型 */
  function normalize(item) {
    var v = item.osv || item || {};
    var nvd = item.nvd || null;
    var ns = nvdInfo(nvd);
    var os = osvSev(v);
    var osvId = v.id || (nvd && nvd.id) || "(unknown)";
    var cves = collectCves(v, nvd);
    var primaryCve = (nvd && isCve(nvd.id)) ? normCve(nvd.id) : (cves[0] || null);
    var otherIds = (Array.isArray(v.aliases) ? v.aliases : [])
      .filter(function (a) { return a && !isCve(a) && a !== osvId; });
    var refUrls = refs(v.references);
    if (nvd && nvd.references) refUrls = refUrls.concat(refs(nvd.references));

    var severityLabel = (ns.label || os.label || "UNKNOWN").toUpperCase();
    return {
      id: primaryCve || osvId,          // 以 CVE 为唯一键
      osvId: osvId,
      cves: cves,
      primaryCve: primaryCve,
      otherIds: otherIds,
      summary: v.summary || ns.desc || "",
      details: (v.details || "").trim(),
      published: v.published || (nvd && nvd.published) || null,
      modified: v.modified || (nvd && nvd.lastModified) || null,
      severityLabel: severityLabel,
      rank: sevRank(severityLabel),
      score: ns.score,
      vector: ns.vector || os.vector || null,
      cwe: ns.cwe,
      hasNvd: !!nvd,
      refs: refUrls.filter(function (u, i, a) { return a.indexOf(u) === i; })
    };
  }

  /* 从本地记录中取出 {osv,nvd} 列表（兼容 {entry:{...}} 与直接 {...} 两种形态） */
  function recordItems(rec) {
    var e = (rec && rec.entry) ? rec.entry : (rec || {});
    if (Array.isArray(e.enriched) && e.enriched.length) {
      return e.enriched.map(function (x) {
        if (x && (x.osv || x.nvd)) return { osv: x.osv || {}, nvd: x.nvd || null };
        return { osv: x || {}, nvd: null };
      });
    }
    var raws = (e.osv_raw && e.osv_raw.vulns) || [];
    return raws.map(function (v) { return { osv: v, nvd: null }; });
  }

  /* --------------------------- 本地漏洞库 --------------------------- */
  var localIndex = []; // [{eco, pkg, ver, key, entry}]

  function buildIndex(raw) {
    localIndex = [];
    if (!raw || typeof raw !== "object") return;
    Object.keys(raw).forEach(function (key) {
      var seg = key.split("|");
      localIndex.push({
        eco: canonEco(seg[0] || ""),
        pkg: (seg[1] || "").trim(),
        ver: (seg[2] || "").trim(),
        key: key,
        entry: raw[key]
      });
    });
  }

  function localLookup(entry) {
    var eco = entry.ecosystem.toLowerCase();
    var pkg = entry.name.toLowerCase();
    var matches = localIndex.filter(function (k) {
      return k.eco.toLowerCase() === eco && k.pkg.toLowerCase() === pkg;
    });
    if (!matches.length) return null;
    if (entry.version) {
      var exact = matches.filter(function (k) { return k.ver === entry.version; });
      return exact.length ? exact[0] : null;
    }
    return matches[0];
  }

  /* 反向：按 CVE 找本地受影响组件 */
  function cveLocalHits(cve) {
    var out = [];
    localIndex.forEach(function (k) {
      var items = dedupe(recordItems(k.entry).map(normalize)).filter(function (v) {
        return v.cves.indexOf(cve) !== -1;
      });
      if (items.length) {
        out.push({
          entry: { ecosystem: k.eco, name: k.pkg, version: k.ver },
          localHit: true, usedLive: false, vulns: items, error: null
        });
      }
    });
    return out;
  }

  /* 离线模式下本地库未收录时的占位卡片 */
  function offlineMiss(label) {
    return {
      entry: { ecosystem: "?", name: label, version: null },
      localHit: false, usedLive: false, vulns: [], error: null,
      note: "离线模式：本地漏洞库未收录 " + label +
            "，且未连接 OSV。可将该条目加入 pkg_list.txt 重新采集，或开启联网后重试。"
    };
  }

  function resolveCve(cve, forceLive) {
    var hits = cveLocalHits(cve);
    if (hits.length && !forceLive) return Promise.resolve(hits);
    if (OFFLINE) return Promise.resolve([offlineMiss(cve)]);

    return fetch(OSV_VULN_API + encodeURIComponent(cve))
      .then(function (r) {
        if (!r.ok) throw new Error("OSV HTTP " + r.status);
        return r.json();
      })
      .then(function (v) {
        var nv = normalize({ osv: v, nvd: null });
        var pkgs = [];
        (v.affected || []).forEach(function (a) {
          var p = a && a.package;
          if (p && p.name) pkgs.push({ ecosystem: canonEco(p.ecosystem), name: p.name, version: null });
        });
        return [{
          entry: pkgs[0] || { ecosystem: "?", name: cve, version: null },
          localHit: false, usedLive: true, vulns: [nv], error: null,
          note: pkgs.length > 1
            ? "该 CVE 共涉及 " + pkgs.length + " 个包，此处仅展示首个（" + pkgs[0].name + "）"
            : ""
        }];
      })
      .catch(function (err) {
        if (hits.length) return hits;
        return [{
          entry: { ecosystem: "?", name: cve, version: null },
          localHit: false, usedLive: false, vulns: [], error: null,
          note: "本地漏洞库未收录 " + cve + "，OSV 查询失败（" + err.message +
                "）。可直接访问 NVD：" + NVD_VULN + cve
        }];
      });
  }

  /* --------------------------- 实时 OSV --------------------------- */
  function osvQuery(entry) {
    if (OFFLINE) return Promise.reject(new Error("离线模式：未连接 OSV"));
    var body = { package: { name: entry.name, ecosystem: entry.ecosystem } };
    if (entry.version) body.version = entry.version;
    return fetch(OSV_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (!r.ok) throw new Error("OSV HTTP " + r.status);
      return r.json();
    }).then(function (data) {
      return (data.vulns || []).map(function (v) { return { osv: v, nvd: null }; });
    });
  }

  function mapLimit(items, limit, worker) {
    return new Promise(function (resolve) {
      var out = new Array(items.length), next = 0, active = 0, done = 0;
      if (!items.length) return resolve(out);
      function pump() {
        while (active < limit && next < items.length) {
          (function (idx) {
            active++; next++;
            Promise.resolve(worker(items[idx], idx)).then(function (res) {
              out[idx] = res;
            }, function (err) {
              out[idx] = { __error: err };
            }).then(function () {
              active--; done++;
              if (done === items.length) resolve(out); else pump();
            });
          })(next);
        }
      }
      pump();
    });
  }

  /* --------------------------- 渲染 --------------------------- */
  function sevClass(label) { return "sev sev-" + String(label || "UNKNOWN").toUpperCase(); }

  function cveTag(cve) {
    var a = el("a", "cve-tag", cve);
    a.href = NVD_VULN + encodeURIComponent(cve);
    a.target = "_blank"; a.rel = "noopener";
    a.title = "在 NVD 查看 " + cve;
    return a;
  }

  function renderVuln(v) {
    var box = el("div", "vuln");
    var top = el("div", "vuln-top");

    // 主标识：优先 CVE
    if (v.primaryCve) {
      var a = el("a", "vid cve-main", v.primaryCve);
      a.href = NVD_VULN + encodeURIComponent(v.primaryCve);
      a.target = "_blank"; a.rel = "noopener";
      a.title = "NVD · " + v.primaryCve;
      top.appendChild(a);
    } else {
      var g = el("a", "vid no-cve", v.osvId);
      g.href = OSV_VULN + encodeURIComponent(v.osvId);
      g.target = "_blank"; g.rel = "noopener";
      g.title = "OSV · " + v.osvId;
      top.appendChild(g);
    }

    var sevText = v.score != null ? v.severityLabel + " " + v.score : v.severityLabel;
    top.appendChild(el("span", sevClass(v.severityLabel), sevText));

    // 其余 CVE（一条 OSV 记录可能对应多个 CVE）
    v.cves.forEach(function (c) {
      if (c !== v.primaryCve) top.appendChild(cveTag(c));
    });

    // 非 CVE 标识（GHSA / OSV 等）
    if (v.osvId && v.osvId !== v.primaryCve) {
      var oid = el("a", "altid", v.osvId);
      oid.href = OSV_VULN + encodeURIComponent(v.osvId);
      oid.target = "_blank"; oid.rel = "noopener";
      oid.title = "OSV · " + v.osvId;
      top.appendChild(oid);
    }
    v.otherIds.forEach(function (x) { top.appendChild(el("span", "altid", x)); });

    if (v.hasNvd) top.appendChild(el("span", "src nvd", "NVD"));
    if (v.published) top.appendChild(el("span", "date", fmtDate(v.published)));
    box.appendChild(top);

    var metaBits = [];
    if (v.score != null) metaBits.push("CVSS " + v.score);
    if (v.vector) metaBits.push(v.vector);
    if (v.cwe.length) metaBits.push(v.cwe.join(", "));
    if (v.modified) metaBits.push("更新 " + fmtDate(v.modified));
    if (metaBits.length) box.appendChild(el("div", "vuln-meta", metaBits.join("  ·  ")));

    if (v.summary) box.appendChild(el("p", "summary", v.summary));

    if (v.details || v.refs.length) {
      var details = el("details", "detail");
      details.appendChild(el("summary", null, "详情与参考链接"));
      if (v.details) details.appendChild(el("pre", null, v.details));
      if (v.refs.length) {
        var ul = el("ul", "refs");
        v.refs.slice(0, 12).forEach(function (url) {
          var li = el("li");
          var ra = el("a", null, url);
          ra.href = url; ra.target = "_blank"; ra.rel = "noopener";
          li.appendChild(ra); ul.appendChild(li);
        });
        details.appendChild(ul);
      }
      box.appendChild(details);
    }
    return box;
  }

  function renderCard(result) {
    var entry = result.entry;
    var card = el("article", "card");

    var head = el("div", "card-head");
    var pkg = el("div", "pkg");
    pkg.appendChild(el("span", "eco", entry.ecosystem));
    pkg.appendChild(el("span", "name", entry.name));
    if (entry.version) pkg.appendChild(el("span", "ver", "@" + entry.version));
    head.appendChild(pkg);

    var badges = el("div", "badges");
    if (result.localHit) badges.appendChild(el("span", "src local", "本地漏洞库"));
    if (result.usedLive) badges.appendChild(el("span", "src live", "实时 OSV"));
    badges.appendChild(el("span", "count", result.vulns.length + " 条 / " + cveCount(result.vulns) + " CVE"));
    head.appendChild(badges);
    card.appendChild(head);

    var body = el("div", "vulns");
    if (result.error) {
      body.appendChild(el("div", "empty", "查询失败：" + result.error));
    } else if (!result.vulns.length && result.note) {
      body.appendChild(el("div", "empty", result.note));
    } else if (!result.vulns.length) {
      body.appendChild(el("div", "empty no-vuln", "✓ 未发现已知漏洞"));
    } else {
      result.vulns.forEach(function (v) { body.appendChild(renderVuln(v)); });
      if (result.note) body.appendChild(el("div", "empty", result.note));
    }
    card.appendChild(body);
    return card;
  }

  /* CVE 视图：以 CVE 为聚合键 */
  function renderCveCard(g) {
    var card = el("article", "card cve-card");
    var head = el("div", "card-head");

    var titleWrap = el("div", "pkg");
    if (g.cve) {
      var a = el("a", "cve-main", g.cve);
      a.href = NVD_VULN + encodeURIComponent(g.cve);
      a.target = "_blank"; a.rel = "noopener";
      a.title = "NVD · " + g.cve;
      titleWrap.appendChild(a);
    } else {
      titleWrap.appendChild(el("span", "cve-main no-cve", g.osvId));
    }
    head.appendChild(titleWrap);

    var badges = el("div", "badges");
    var sevText = g.score != null ? g.severityLabel + " " + g.score : g.severityLabel;
    badges.appendChild(el("span", sevClass(g.severityLabel), sevText));
    if (g.hasNvd) badges.appendChild(el("span", "src nvd", "NVD"));
    badges.appendChild(el("span", "count", g.components.length + " 个组件"));
    if (g.published) badges.appendChild(el("span", "date", fmtDate(g.published)));
    head.appendChild(badges);
    card.appendChild(head);

    var body = el("div", "vulns");
    if (g.summary) body.appendChild(el("p", "summary", g.summary));

    var metaBits = [];
    if (g.score != null) metaBits.push("CVSS " + g.score);
    if (g.vector) metaBits.push(g.vector);
    if (g.cwe.length) metaBits.push(g.cwe.join(", "));
    if (metaBits.length) body.appendChild(el("div", "vuln-meta", metaBits.join("  ·  ")));

    var aff = el("div", "affected");
    g.components.forEach(function (c) {
      var chip = el("span", "aff");
      chip.appendChild(el("span", "eco", c.eco));
      chip.appendChild(el("span", "name", c.name));
      if (c.version) chip.appendChild(el("span", "ver", "@" + c.version));
      aff.appendChild(chip);
    });
    body.appendChild(aff);

    var idWrap = el("div", "vuln-meta");
    var idBits = [];
    if (g.osvId && g.osvId !== g.cve) idBits.push(g.osvId);
    idBits = idBits.concat(g.otherIds || []);
    if (idBits.length) {
      idWrap.textContent = "其他标识：" + idBits.join(", ");
      body.appendChild(idWrap);
    }

    if (g.details || g.refs.length) {
      var details = el("details", "detail");
      details.appendChild(el("summary", null, "详情与参考链接"));
      if (g.details) details.appendChild(el("pre", null, g.details));
      if (g.refs.length) {
        var ul = el("ul", "refs");
        g.refs.slice(0, 12).forEach(function (url) {
          var li = el("li");
          var ra = el("a", null, url);
          ra.href = url; ra.target = "_blank"; ra.rel = "noopener";
          li.appendChild(ra); ul.appendChild(li);
        });
        details.appendChild(ul);
      }
      body.appendChild(details);
    }
    card.appendChild(body);
    return card;
  }

  function setStatus(text, isErr, spinner) {
    var node = $("status");
    if (!text) { node.hidden = true; node.textContent = ""; return; }
    node.hidden = false;
    node.className = "status" + (isErr ? " err" : "");
    node.textContent = "";
    if (spinner) node.appendChild(el("span", "spin"));
    node.appendChild(el("span", null, text));
  }

  /* --------------------------- 过滤 / 排序 / 聚合 --------------------------- */
  function cveCount(vulns) {
    var seen = {}, n = 0;
    vulns.forEach(function (v) {
      v.cves.forEach(function (c) { if (!seen[c]) { seen[c] = 1; n++; } });
    });
    return n;
  }

  function haystack(v, entry) {
    return [
      v.cves.join(" "), v.osvId, v.otherIds.join(" "), v.summary, v.details,
      v.cwe.join(" "),
      entry ? (entry.ecosystem + " " + entry.name + " " + (entry.version || "")) : ""
    ].join(" ").toLowerCase();
  }

  function matchVuln(v, entry, toks) {
    if (!toks.length) return true;
    var h = haystack(v, entry);
    return toks.every(function (t) { return h.indexOf(t) !== -1; });
  }

  function matchSev(v, key) {
    if (key === "ALL") return true;
    return v.rank === SEV_RANK[key];
  }

  function sortVulns(list, mode) {
    return list.slice().sort(function (a, b) {
      var ka = a.primaryCve || a.osvId, kb = b.primaryCve || b.osvId;
      if (mode === "cve") return cveCmp(ka, kb);
      if (mode === "date") {
        return (dateVal(b.published) - dateVal(a.published)) || (b.rank - a.rank) || cveCmp(ka, kb);
      }
      return (b.rank - a.rank) || ((b.score || 0) - (a.score || 0)) || cveCmp(ka, kb);
    });
  }

  /* result[] -> CVE 分组 */
  function cveGroups(results) {
    var map = {}, order = [];
    results.forEach(function (r) {
      (r.vulns || []).forEach(function (v) {
        var keys = v.cves.length ? v.cves : [null];
        keys.forEach(function (cve) {
          var key = cve || ("OSV:" + v.osvId);
          var g = map[key];
          if (!g) {
            g = map[key] = {
              cve: cve,
              osvId: v.osvId,
              otherIds: v.otherIds.slice(),
              severityLabel: v.severityLabel,
              rank: v.rank,
              score: v.score,
              vector: v.vector,
              cwe: v.cwe.slice(),
              published: v.published,
              modified: v.modified,
              summary: v.summary,
              details: v.details,
              refs: v.refs.slice(),
              hasNvd: v.hasNvd,
              components: []
            };
            order.push(g);
          }
          // 合并：优先保留更完整 / 更严重的元数据
          if (!g.summary && v.summary) g.summary = v.summary;
          if (!g.details && v.details) g.details = v.details;
          if (!g.vector && v.vector) g.vector = v.vector;
          if (!g.published || (v.published && dateVal(v.published) < dateVal(g.published))) g.published = v.published;
          v.cwe.forEach(function (c) { if (g.cwe.indexOf(c) === -1) g.cwe.push(c); });
          v.refs.forEach(function (u) { if (g.refs.indexOf(u) === -1) g.refs.push(u); });
          v.otherIds.forEach(function (u) { if (g.otherIds.indexOf(u) === -1) g.otherIds.push(u); });
          if ((v.score || 0) > (g.score || 0)) {
            g.score = v.score;
            g.severityLabel = v.severityLabel;
            g.vector = v.vector || g.vector;
          }
          g.rank = Math.max(g.rank, v.rank);
          g.hasNvd = g.hasNvd || v.hasNvd;

          var comp = { eco: r.entry.ecosystem, name: r.entry.name, version: r.entry.version };
          var dup = g.components.some(function (c) {
            return c.eco === comp.eco && c.name === comp.name && c.version === comp.version;
          });
          if (!dup) g.components.push(comp);
        });
      });
    });
    return order;
  }

  function sortGroups(list, mode) {
    return list.slice().sort(function (a, b) {
      var ka = a.cve || a.osvId, kb = b.cve || b.osvId;
      if (mode === "cve") return cveCmp(ka, kb);
      if (mode === "date") {
        return (dateVal(b.published) - dateVal(a.published)) || (b.rank - a.rank) || cveCmp(ka, kb);
      }
      if (mode === "pkg") {
        return ((a.components[0] && a.components[0].name) || "").localeCompare(
               ((b.components[0] && b.components[0].name) || "")) || (b.rank - a.rank);
      }
      return (b.rank - a.rank) || ((b.score || 0) - (a.score || 0)) || cveCmp(ka, kb);
    });
  }

  /* --------------------------- 结果状态与渲染入口 --------------------------- */
  var state = { results: [], view: "pkg", filter: "", sev: "ALL", sort: "sev" };

  function visibleResults() {
    var toks = state.filter.toLowerCase().split(/\s+/).filter(Boolean);
    var cveToks = toks.filter(function (t) { return t.indexOf("cve") === 0; });
    var out = [];
    state.results.forEach(function (r) {
      if (!r || r.__error) return;
      var vs = [];
      (r.vulns || []).forEach(function (v) {
        if (!matchSev(v, state.sev)) return;
        if (!matchVuln(v, r.entry, toks)) return;
        if (cveToks.length && v.cves.length) {
          var hit = v.cves.filter(function (c) {
            return cveToks.some(function (t) { return c.toLowerCase().indexOf(t) !== -1; });
          });
          if (!hit.length) return;
          v = cloneWithCves(v, hit);
        }
        vs.push(v);
      });
      // 无漏洞但有提示/报错的条目（如离线未收录）也要保留卡片
      var keepMsg = (r.error || r.note) && !toks.length && state.sev === "ALL";
      if (vs.length || keepMsg) {
        out.push({
          entry: r.entry, localHit: r.localHit, usedLive: r.usedLive,
          vulns: sortVulns(vs, state.sort === "pkg" ? "sev" : state.sort),
          error: keepMsg ? r.error : null,
          note: r.note
        });
      }
    });
    if (state.sort === "pkg") {
      out.sort(function (a, b) { return a.entry.name.localeCompare(b.entry.name); });
    }
    return out;
  }

  function renderStats(list) {
    var node = $("cveStats");
    node.textContent = "";
    var seen = {}, cves = [], buckets = {}, pkgs = 0, worst = 0;
    list.forEach(function (r) {
      pkgs++;
      (r.vulns || []).forEach(function (v) {
        worst = Math.max(worst, v.rank);
        v.cves.forEach(function (c) {
          if (!seen[c]) { seen[c] = 1; cves.push(c); }
        });
        var lab = v.severityLabel;
        buckets[lab] = (buckets[lab] || 0) + 1;
      });
    });
    cves = sortCves(cves);

    node.appendChild(statChip("CVE " + cves.length + " 个", ""));
    node.appendChild(statChip("漏洞 " + list.reduce(function (n, r) { return n + r.vulns.length; }, 0) + " 条", ""));
    node.appendChild(statChip("组件 " + pkgs + " 个", ""));
    ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"].forEach(function (k) {
      if (!buckets[k]) return;
      node.appendChild(statChip((SEV_ZH[k] || k) + " " + buckets[k], "stat-" + k));
    });
    if (cves.length) {
      node.appendChild(statChip("最新 " + cves[0], ""));
    }
    node.hidden = false;
  }

  function statChip(text, cls) {
    var s = el("span", "stat " + (cls || ""));
    var parts = String(text).split(" ");
    if (parts.length > 1) {
      s.appendChild(el("b", null, parts[0]));
      s.appendChild(document.createTextNode(" " + parts.slice(1).join(" ")));
    } else {
      s.textContent = text;
    }
    return s;
  }

  function render() {
    var host = $("results");
    host.textContent = "";

    var list = visibleResults();
    renderStats(list);

    if (!list.length) {
      host.appendChild(el("div", "empty",
        state.filter || state.sev !== "ALL"
          ? "没有匹配的漏洞（当前过滤条件：" + (state.filter || "无关键词") + " / " + state.sev + "）"
          : "✓ 未发现已知漏洞"));
      return;
    }

    if (state.view === "cve") {
      var groups = sortGroups(cveGroups(list), state.sort);
      groups.forEach(function (g) { host.appendChild(renderCveCard(g)); });
    } else {
      list.forEach(function (r) { host.appendChild(renderCard(r)); });
    }
  }

  /* --------------------------- 主流程 --------------------------- */
  var running = false;

  /* CVE 集合完全相同的多条 advisory（如 GHSA-A / GHSA-B 指向同一组 CVE）合并为一条 */
  function mergeVuln(a, b) {
    var main = a, other = b;
    if ((b.score || 0) > (a.score || 0)) { main = b; other = a; }
    else if (b.hasNvd && !a.hasNvd) { main = b; other = a; }

    var out = {};
    Object.keys(main).forEach(function (k) { out[k] = main[k]; });
    out.cves = sortCves(main.cves.concat(other.cves).filter(function (c, i, arr) {
      return arr.indexOf(c) === i;
    }));
    out.otherIds = main.otherIds.slice();
    out.cwe = main.cwe.slice();
    out.refs = main.refs.slice();

    [main.osvId, other.osvId].forEach(function (x) {
      if (x && x !== out.osvId && out.otherIds.indexOf(x) === -1) out.otherIds.push(x);
    });
    other.otherIds.forEach(function (x) {
      if (x && x !== out.osvId && out.otherIds.indexOf(x) === -1) out.otherIds.push(x);
    });
    other.cwe.forEach(function (c) { if (out.cwe.indexOf(c) === -1) out.cwe.push(c); });
    other.refs.forEach(function (u) { if (out.refs.indexOf(u) === -1) out.refs.push(u); });
    if (!out.summary && other.summary) out.summary = other.summary;
    if (!out.details && other.details) out.details = other.details;
    if (!out.vector && other.vector) out.vector = other.vector;
    if (out.score == null && other.score != null) { out.score = other.score; out.severityLabel = other.severityLabel; }
    out.rank = Math.max(main.rank, other.rank);
    out.hasNvd = main.hasNvd || other.hasNvd;
    // 主 CVE 优先沿用 NVD 富化所对应的那个，避免标题与 CVSS/描述错位
    out.primaryCve = (main.primaryCve && out.cves.indexOf(main.primaryCve) !== -1)
      ? main.primaryCve : (out.cves[0] || null);
    out.id = out.primaryCve || out.osvId;
    return out;
  }

  function dedupe(items) {
    var map = {}, order = [];
    items.forEach(function (v) {
      var key = v.cves.length ? "CVE:" + v.cves.join(",") : "OSV:" + v.osvId;
      if (!map[key]) { map[key] = v; order.push(key); }
      else { map[key] = mergeVuln(map[key], v); }
    });
    return order.map(function (k) { return map[k]; });
  }

  /* 按 CVE 过滤时，只保留命中的 CVE（避免「按 CVE」视图连带显示同一记录上的其他 CVE） */
  function cloneWithCves(v, cves) {
    var out = {};
    Object.keys(v).forEach(function (k) { out[k] = v[k]; });
    out.cves = sortCves(cves);
    out.primaryCve = (v.primaryCve && out.cves.indexOf(v.primaryCve) !== -1)
      ? v.primaryCve : (out.cves[0] || null);
    out.id = out.primaryCve || v.osvId;
    return out;
  }

  function flatten(list) {
    var out = [];
    list.forEach(function (x) {
      if (Array.isArray(x)) out = out.concat(x);
      else out.push(x);
    });
    return out;
  }

  function run() {
    if (running) return;
    var parsed = parseInput($("query").value);
    var errors = parsed.errors.slice();
    if (!parsed.entries.length && !errors.length) {
      setStatus("请输入至少一个组件（pkg_list 或 GAV）或 CVE 编号。", true);
      return;
    }

    running = true;
    $("run").disabled = true;
    $("results").textContent = "";
    state.results = [];
    $("toolbar").hidden = false;
    setStatus("正在查询 " + parsed.entries.length + " 个条目…", false, true);

    var forceLive = $("forceLive").checked;
    var allCve = parsed.entries.every(function (e) { return e.kind === "cve"; });
    if (allCve) { state.view = "cve"; syncViewSwitch(); }

    mapLimit(parsed.entries, CONCURRENCY, function (entry) {
      if (entry.kind === "cve") return resolveCve(entry.cve, forceLive);

      var rec = localLookup(entry);
      var cachedVulns = rec ? dedupe(recordItems(rec.entry).map(normalize)) : null;

      if (!rec && OFFLINE) return offlineMiss(entry.name + (entry.version ? "@" + entry.version : ""));

      if (rec && !forceLive) {
        return { entry: entry, localHit: true, usedLive: false, vulns: cachedVulns, error: null };
      }

      return osvQuery(entry).then(function (liveItems) {
        var live = liveItems.map(normalize);
        if (rec) {
          return {
            entry: entry, localHit: true, usedLive: true,
            vulns: dedupe(live.concat(cachedVulns)), error: null
          };
        }
        return { entry: entry, localHit: false, usedLive: true, vulns: dedupe(live), error: null };
      }).catch(function (err) {
        if (rec) {
          return {
            entry: entry, localHit: true, usedLive: false,
            vulns: cachedVulns, error: null, note: "实时 OSV 查询失败，已回退本地漏洞库：" + err.message
          };
        }
        return { entry: entry, localHit: false, usedLive: true, vulns: [], error: err.message };
      });
    }).then(function (raw) {
      var results = flatten(raw);
      results.forEach(function (r) {
        if (r && r.__error) {
          state.results.push({
            entry: { ecosystem: "?", name: "(error)", version: null },
            vulns: [], error: r.__error.message
          });
          return;
        }
        if (r) state.results.push(r);
      });

      var total = results.reduce(function (n, r) {
        return n + (r && r.vulns ? r.vulns.length : 0);
      }, 0);
      var uniq = cveCount(flatten(results.map(function (r) { return r && r.vulns ? r.vulns : []; })));

      var msg = "完成：" + parsed.entries.length + " 个条目，" + total + " 条漏洞，" + uniq + " 个 CVE";
      if (errors.length) msg += "；" + errors.length + " 行无法解析（" + errors.join("；") + "）";
      setStatus(msg, false);
      running = false;
      $("run").disabled = false;
      render();
    });
  }

  /* --------------------------- 工具栏 --------------------------- */
  function buildSelect(node, options) {
    node.textContent = "";
    options.forEach(function (pair) {
      var o = el("option", null, pair[1]);
      o.value = pair[0];
      node.appendChild(o);
    });
  }

  function syncViewSwitch() {
    var btns = document.querySelectorAll(".viewswitch button");
    for (var i = 0; i < btns.length; i++) {
      btns[i].className = "vs" + (btns[i].getAttribute("data-view") === state.view ? " active" : "");
    }
  }

  function copyCves() {
    var seen = {}, cves = [];
    visibleResults().forEach(function (r) {
      (r.vulns || []).forEach(function (v) {
        v.cves.forEach(function (c) { if (!seen[c]) { seen[c] = 1; cves.push(c); } });
      });
    });
    cves = sortCves(cves);
    if (!cves.length) { setStatus("当前没有可复制的 CVE。", true); return; }

    var text = cves.join("\n");
    function done() { setStatus("已复制 " + cves.length + " 个 CVE 编号到剪贴板。", false); }
    function fallback() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        done();
      } catch (e) { setStatus("复制失败，请手动选择复制。", true); }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  function initToolbar() {
    buildSelect($("sevFilter"), SEV_FILTERS);
    buildSelect($("sortBy"), SORTS);

    var timer = null;
    $("filter").addEventListener("input", function () {
      var v = this.value;
      clearTimeout(timer);
      timer = setTimeout(function () { state.filter = v; render(); }, 150);
    });
    $("sevFilter").addEventListener("change", function () { state.sev = this.value; render(); });
    $("sortBy").addEventListener("change", function () { state.sort = this.value; render(); });
    $("copyCves").addEventListener("click", copyCves);

    var btns = document.querySelectorAll(".viewswitch button");
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener("click", function () {
        state.view = this.getAttribute("data-view");
        syncViewSwitch();
        render();
      });
    }
    syncViewSwitch();
  }

  /* --------------------------- 示例 chips --------------------------- */
  /* 点击示例统一「追加」到输入框（不清空已有内容），多行清单同理 */
  function fillTextarea(id, text) {
    var ta = $(id);
    if (!ta) return;
    ta.value = ta.value.trim() ? ta.value.replace(/\s*$/, "") + "\n" + text : text.trim();
    ta.focus();
  }

  function renderChips(lines) {
    var wrap = $("exampleChips");
    if (!wrap) return;
    wrap.textContent = "";
    lines.slice(0, 14).forEach(function (text) {
      var chip = el("button", "chip", text);
      chip.type = "button";
      chip.addEventListener("click", function () { fillTextarea("query", text); });
      wrap.appendChild(chip);
    });
  }

  function loadChips() {
    fetch(PKG_LIST_URL, { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error(); return r.text(); })
      .then(function (text) {
        var lines = text.split(/\r?\n/).map(function (s) { return s.trim(); })
          .filter(function (s) { return s && s.charAt(0) !== "#" && s.indexOf("|") !== -1; });
        renderChips(lines);
      })
      .catch(function () {
        renderChips([
          "maven|com.alibaba:fastjson|1.2.24",
          "maven|org.springframework.boot:spring-boot-starter-web|2.7.0",
          "npm|lodash|4.17.20",
          "pypi|requests|2.20.0",
          "go|github.com/gin-gonic/gin|1.6.0",
          "org.springframework.boot:spring-boot-starter-web:2.7.0"
        ]);
      });
  }

  /* --------------------------- 常用依赖 Top 清单 --------------------------- */
  /* data/popular-packages.json 由 gen_popular_packages.py 生成：
   *   { lists: [{ key, label, ecosystem, count, rank_basis,
   *               items: [{rank,name,version,desc,line,meta}] }] }
   * 面板支持按生态切换、名称过滤、增量渲染与一键填入；健康度 tab 另有精简 chips。 */
  var popularState = {
    data: null, attempted: false, eco: "maven", query: "",
    filtered: [], shown: 0, chunk: 60
  };

  function popularList(key) {
    var lists = (popularState.data && popularState.data.lists) || [];
    for (var i = 0; i < lists.length; i++) {
      if (lists[i].ecosystem === key || lists[i].key === key) return lists[i];
    }
    return null;
  }

  function fmtNum(n) {
    n = Number(n) || 0;
    if (n >= 1e8) return (n / 1e8).toFixed(1).replace(/\.0$/, "") + " 亿";
    if (n >= 1e4) return (n / 1e4).toFixed(1).replace(/\.0$/, "") + " 万";
    return String(n);
  }

  function popularMetaText(item) {
    var meta = item.meta || {};
    if (meta.weekly_downloads) return "周下载 " + fmtNum(meta.weekly_downloads);
    if (meta.monthly_downloads) return "月下载 " + fmtNum(meta.monthly_downloads);
    if (meta.dependents) return "被依赖 " + fmtNum(meta.dependents);
    if (meta.stars) return "★ " + fmtNum(meta.stars);
    return "";
  }

  function popularFiltered() {
    var list = popularList(popularState.eco);
    var items = (list && list.items) || [];
    var q = String(popularState.query || "").trim().toLowerCase();
    if (!q) return items;
    return items.filter(function (item) {
      var hay = (String(item.name || "") + " " + String(item.desc || "")).toLowerCase();
      return hay.indexOf(q) !== -1;
    });
  }

  function popularLines(items, topN) {
    return (items || [])
      .filter(function (item) { return item && item.name; })
      .slice(0, topN)
      .map(function (item) { return item.line; })
      .join("\n");
  }

  function renderPopularTabs() {
    var wrap = $("popTabs");
    if (!wrap) return;
    var lists = (popularState.data && popularState.data.lists) || [];
    wrap.textContent = "";
    lists.forEach(function (list) {
      var btn = el("button", "pop-tab" + (list.ecosystem === popularState.eco ? " active" : ""),
        (list.label || list.ecosystem) + " · " + (list.count || 0));
      btn.type = "button";
      btn.setAttribute("data-eco", list.ecosystem);
      btn.addEventListener("click", function () {
        if (popularState.eco === list.ecosystem) return;
        popularState.eco = list.ecosystem;
        popularState.query = "";
        var search = $("popSearch");
        if (search) search.value = "";
        renderPopular();
      });
      wrap.appendChild(btn);
    });
  }

  function renderPopularBasis() {
    var host = $("popBasis");
    if (!host) return;
    var list = popularList(popularState.eco);
    var stamp = (popularState.data && popularState.data.generated_at) || "";
    host.textContent = (list && list.rank_basis ? list.rank_basis : "") +
      (stamp ? " · 数据生成于 " + stamp.replace("T", " ").replace("Z", " UTC") : "");
  }

  function appendPopularRows() {
    var host = $("popList");
    if (!host) return;
    var items = popularState.filtered;
    var end = Math.min(popularState.shown + popularState.chunk, items.length);
    var frag = document.createDocumentFragment();
    for (var i = popularState.shown; i < end; i++) {
      frag.appendChild(popularRow(items[i], i + 1));
    }
    host.appendChild(frag);
    popularState.shown = end;
    var more = $("popMore");
    if (more) more.hidden = popularState.shown >= items.length;
    var count = $("popCount");
    if (count) count.textContent = "已显示 " + popularState.shown + " / " + items.length + " 条";
  }

  function popularRow(item, rank) {
    var row = el("div", "pop-row");
    var no = el("span", "pop-rank", String(rank));
    var main = el("div", "pop-main");
    var name = el("div", "pop-name");
    name.appendChild(el("span", "pop-pkg", item.name));
    if (item.version) name.appendChild(el("span", "pop-ver", "@" + item.version));
    main.appendChild(name);
    if (item.desc) main.appendChild(el("div", "pop-desc", item.desc));
    var meta = popularMetaText(item);
    if (meta) main.appendChild(el("div", "pop-meta", meta));
    var add = el("button", "pop-add", "填入");
    add.type = "button";
    add.title = "把该行追加到查询框";
    add.addEventListener("click", function (ev) {
      ev.stopPropagation();
      fillTextarea("query", item.line);
    });
    row.appendChild(no);
    row.appendChild(main);
    row.appendChild(add);
    row.title = "点击填入：" + item.line;
    row.addEventListener("click", function () { fillTextarea("query", item.line); });
    return row;
  }

  function renderPopular() {
    renderPopularTabs();
    renderPopularBasis();
    popularState.filtered = popularFiltered();
    popularState.shown = 0;
    var host = $("popList");
    if (host) host.textContent = "";
    appendPopularRows();
  }

  function initPopularControls() {
    var search = $("popSearch");
    if (search) search.addEventListener("input", function () {
      popularState.query = this.value;
      renderPopular();
    });
    var fill = $("popFill");
    if (fill) fill.addEventListener("click", function () {
      var sel = $("popFillN");
      var n = sel ? parseInt(sel.value, 10) : 50;
      var lines = popularLines(popularState.filtered, n || popularState.filtered.length);
      if (lines) fillTextarea("query", lines);
    });
    var copy = $("popCopy");
    if (copy) copy.addEventListener("click", function () {
      var sel = $("popFillN");
      var n = sel ? parseInt(sel.value, 10) : 50;
      var lines = popularLines(popularState.filtered, n || popularState.filtered.length);
      copyText(lines, copy);
    });
    var more = $("popMore");
    if (more) more.addEventListener("click", function () { appendPopularRows(); });
    var list = $("popList");
    if (list) list.addEventListener("scroll", function () {
      if (this.scrollTop + this.clientHeight >= this.scrollHeight - 120 &&
          popularState.shown < popularState.filtered.length) {
        appendPopularRows();
      }
    });
  }

  /* 健康度 tab 的精简 chips：每生态 Top 20 + 四生态合并 */
  function renderHealthChips() {
    var wrap = $("healthExampleChips");
    if (!wrap) return;
    var lists = (popularState.data && popularState.data.lists) || [];
    wrap.textContent = "";
    lists.forEach(function (list) {
      var chip = el("button", "chip chip-list",
        (list.ecosystem === "maven" ? "Maven" : list.ecosystem.toUpperCase()) + " Top 20");
      chip.type = "button";
      chip.title = (list.rank_basis || "") + " · 共 " + (list.count || 0) + " 项";
      chip.addEventListener("click", function () {
        fillTextarea("healthQuery", popularLines(list.items, 20));
      });
      wrap.appendChild(chip);
    });
    var chipAll = el("button", "chip chip-list", "四生态各 Top 20");
    chipAll.type = "button";
    chipAll.title = "四个生态各取前 20 条合并填入";
    chipAll.addEventListener("click", function () {
      var all = lists.map(function (list) { return popularLines(list.items, 20); })
        .filter(Boolean).join("\n");
      fillTextarea("healthQuery", all);
    });
    wrap.appendChild(chipAll);
  }

  function loadPopular() {
    if (popularState.attempted) return;
    popularState.attempted = true;
    fetch(POPULAR_URL, { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (json) {
        popularState.data = json;
        var panel = $("popularPanel");
        if (panel) panel.hidden = false;
        var wrapH = $("healthExamples");
        if (wrapH) wrapH.hidden = false;
        renderPopular();
        renderHealthChips();
      })
      .catch(function () { popularState.data = null; });
  }

  /* --------------------------- 开源软件支持力度与活跃度 --------------------------- */
  var healthState = {
    data: null, attempted: false, sort: "grade", grade: "ALL", query: "",
    queryMode: false, matched: [], missing: [], pendingQuery: false
  };

  /* 数据来源展示名（与 community_report.py 的 SOURCE_LABELS 保持一致） */
  var SOURCE_LABELS = {
    "github": "GitHub",
    "deps.dev": "deps.dev",
    "npm-registry": "npm registry",
    "pypi": "PyPI",
    "repo-map": "repo-map"
  };

  /* pkg: eco/namespace/name@version -> { type, ns, name, version } */
  function parseHealthPurl(value) {
    var body = String(value || "").replace(/^pkg:/i, "");
    var at = body.lastIndexOf("@");
    var version = at > 0 ? body.slice(at + 1) : "";
    var path = at > 0 ? body.slice(0, at) : body;
    var slash = path.indexOf("/");
    var type = slash > 0 ? path.slice(0, slash) : path;
    var rest = slash > 0 ? path.slice(slash + 1) : "";
    var segs = rest.split("/");
    var name = segs.pop() || "";
    var ns = segs.join("/");
    return { type: String(type).toLowerCase(), ns: ns, name: name, version: version };
  }

  /* 同一个组件在输入里可能有多种写法，全部登记，保证「怎么写都能查到」 */
  function healthNameKeys(info) {
    var out = [];
    function push(x) {
      x = String(x || "").toLowerCase();
      if (x && out.indexOf(x) === -1) out.push(x);
    }
    if (info.type === "maven") {
      if (info.ns) push(info.ns + ":" + info.name);
      push(info.name);
    } else if (info.ns) {
      if (info.type === "npm") {
        push("@" + info.ns + "/" + info.name);
        push(info.ns + "/" + info.name);   // 无 @ 写法（purl 内 scope 不带 @）
      } else if (info.type === "golang" || info.type === "go") {
        push(info.ns + "/" + info.name);
        push(info.name);
      } else {
        push(info.name);
      }
    } else {
      push(info.name);
    }
    return out;
  }

  function buildHealthIndex(report) {
    var exact = {}, byName = {};
    (report.components || []).forEach(function (c) {
      var eco = canonEco(c.eco || "").toLowerCase();
      var info = parseHealthPurl(c.purl);
      healthNameKeys(info).forEach(function (nameKey) {
        var key = eco + "|" + nameKey;
        (byName[key] = byName[key] || []).push(c);
        if (info.version) {
          var vk = key + "|" + info.version.toLowerCase();
          (exact[vk] = exact[vk] || []).push(c);
        }
      });
    });
    return { exact: exact, byName: byName };
  }

  function matchHealth(entry, index) {
    var eco = canonEco(entry.ecosystem || "").toLowerCase();
    var name = String(entry.name || "").toLowerCase();
    var version = entry.version ? String(entry.version).toLowerCase() : "";
    if (version) {
      var hits = index.exact[eco + "|" + name + "|" + version];
      if (hits && hits.length) return { component: hits[0], exactVersion: true, candidates: hits.length };
    }
    var list = index.byName[eco + "|" + name];
    if (list && list.length) {
      list = list.slice().sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
      return { component: list[0], exactVersion: false, candidates: list.length };
    }
    return null;
  }

  function healthHay(component) {
    return (String(component.display || "") + " " + String(component.purl || "") + " " +
      String(component.eco || "")).toLowerCase();
  }

  function healthEntryLine(entry) {
    if (entry.version) return entry.ecosystem + "|" + entry.name + "|" + entry.version;
    return entry.ecosystem + "|" + entry.name;
  }

  function componentVersion(component) {
    return parseHealthPurl(component.purl).version;
  }

  function copyText(text, onDone) {
    function fallback() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        onDone();
      } catch (e) { onDone(new Error("copy-failed")); }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onDone, fallback);
    } else {
      fallback();
    }
  }

  function renderHealthMatchedCard(item) {
    var card = renderHealthCard(item.component);
    var ver = componentVersion(item.component);
    var notes = [];
    if (item.entry && item.entry.version && ver && ver !== String(item.entry.version)) {
      notes.push("查询版本 " + item.entry.version + "，报告实际评估版本 " + ver);
    } else if (item.entry && !item.entry.version) {
      notes.push("未指定版本，按组件名匹配（报告版本 " + (ver || "未知") + "）");
    }
    if (item.candidates > 1) {
      notes.push("同一组件共 " + item.candidates + " 个已采集版本，此处取评分最高者");
    }
    if (item.duplicates && item.duplicates.length) {
      notes.push("清单中另有 " + item.duplicates.length + " 行指向同一组件");
    }
    if (!notes.length) return card;
    var body = card.querySelector(".health-body");
    if (!body) return card;
    var note = el("p", "health-querynote", notes.join("；"));
    body.insertBefore(note, body.firstChild);
    return card;
  }

  function renderHealthMissingCard(item) {
    var card = el("article", "card health-card health-miss");
    var head = el("div", "card-head");
    var pkg = el("div", "pkg");
    pkg.appendChild(el("span", "eco", item.entry.ecosystem || "—"));
    pkg.appendChild(el("span", "name", item.entry.name || "—"));
    head.appendChild(pkg);
    head.appendChild(el("div", "badges")).appendChild(el("span", "grade grade-na", "未收录"));
    card.appendChild(head);

    var body = el("div", "health-body");
    body.appendChild(el("p", "health-missing",
      (item.reason || "健康度数据未收录该组件") + "：" + healthEntryLine(item.entry)));
    body.appendChild(el("p", "advice",
      "把该条加进 scabase-fetcher/data/pkg_list.txt（或用 gen_popular_packages.py 生成的 " +
      "pkg_list_popular.txt），执行 community-health 工作流采集后即可在此查询。"));
    card.appendChild(body);
    return card;
  }

  function runHealthQuery() {
    var ta = $("healthQuery");
    if (!ta) return;

    if (!ta.value.trim()) {
      healthState.queryMode = false;
      healthState.matched = [];
      healthState.missing = [];
      healthState.pendingQuery = false;
      var copyBtn = $("healthCopyMissing");
      if (copyBtn) copyBtn.hidden = true;
      if (!healthState.data) return;
      healthStatus("");
      renderHealth();
      return;
    }

    if (!healthState.data) {
      // 数据尚未到位（切 tab 时会触发加载）：先标记，加载完成后自动补跑；
      // 若此前加载失败过，这里重置 attempted 以便重试一次。
      healthState.pendingQuery = true;
      if (healthState.attempted) healthState.attempted = false;
      healthStatus("正在加载健康度数据，加载完成后自动查询…", false, true);
      loadHealth();
      return;
    }

    var parsed = parseInput(ta.value);
    if (!parsed.entries.length) {
      healthStatus(parsed.errors.length ? parsed.errors.join("；") : "没有可查询的条目。", true);
      return;
    }

    var index = buildHealthIndex(healthState.data);
    var matched = [], missing = [], taken = {};
    parsed.entries.forEach(function (entry) {
      if (entry.kind === "cve") {
        missing.push({
          entry: { ecosystem: "?", name: entry.cve, version: null },
          reason: "CVE 编号用于漏洞查询，此处需填写组件"
        });
        return;
      }
      var hit = matchHealth(entry, index);
      if (!hit) { missing.push({ entry: entry, reason: "健康度数据未收录" }); return; }
      var key = hit.component.purl;
      if (taken[key]) { taken[key].duplicates.push(entry); return; }
      taken[key] = {
        component: hit.component, entry: entry,
        exactVersion: hit.exactVersion, candidates: hit.candidates || 1, duplicates: []
      };
      matched.push(taken[key]);
    });

    healthState.queryMode = true;
    healthState.matched = matched;
    healthState.missing = missing;
    healthState.pendingQuery = false;
    renderHealth();

    var msg = "输入 " + parsed.entries.length + " 条 · 命中 " + matched.length +
      " 个组件 · 未收录 " + missing.length + " 条";
    if (parsed.errors.length) msg += " · 解析失败 " + parsed.errors.length + " 行：" + parsed.errors.join("；");
    healthStatus(msg, !!parsed.errors.length);
    var btn = $("healthCopyMissing");
    if (btn) btn.hidden = !missing.length;
  }

  function copyHealthMissing() {
    var lines = healthState.missing.map(function (item) { return healthEntryLine(item.entry); });
    if (!lines.length) return;
    copyText(lines.join("\n"), function (err) {
      healthStatus(err ? "复制失败，请手动选择复制。" : "已复制 " + lines.length + " 条未收录条目到剪贴板。", !!err);
    });
  }

  function orgLabel(b) {
    if (!b) return "未知";
    var t = String(b).toLowerCase();
    if (t === "foundation") return "基金会";
    if (t === "vendor") return "厂商";
    if (t === "organization") return "组织";
    if (t === "personal") return "个人";
    return String(b);
  }

  function fmtDays(d) {
    if (d == null) return "未知";
    var n = Math.round(d);
    if (n < 1) return "今日";
    if (n < 30) return n + " 天前";
    if (n < 365) return Math.round(n / 30) + " 个月前";
    return (n / 365).toFixed(1) + " 年前";
  }

  function fmtCount(n) {
    if (n == null) return "未知";
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "k";
    return String(n);
  }

  function gradeClass(g) { return "grade grade-" + g; }

  function healthStatus(text, isErr, spinner) {
    var node = $("healthStatus");
    if (!text) { node.hidden = true; node.textContent = ""; return; }
    node.hidden = false;
    node.className = "status" + (isErr ? " err" : "");
    node.textContent = "";
    if (spinner) node.appendChild(el("span", "spin"));
    node.appendChild(el("span", null, text));
  }

  function loadHealth() {
    if (healthState.attempted) return;
    healthState.attempted = true;
    healthStatus("加载社区支持力度与活跃度数据…", false, true);
    fetch(HEALTH_URL, { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (json) {
        healthState.data = json;
        healthStatus("");
        renderHealth();
        // 数据到位后补跑此前被阻塞的查询
        if (healthState.pendingQuery) runHealthQuery();
      })
      .catch(function () {
        healthStatus("未能加载社区健康报告（" + HEALTH_URL + "）。请先由 community-health.yml 工作流或 " +
          "python scabase-fetcher/scripts/community_report.py 生成该文件后再查看。", true, false);
        $("healthResults").textContent = "";
      });
  }

  function kpiCard(grade, title, value, sub, pct) {
    var card = el("div", "kpi kpi-" + grade);
    var top = el("div", "kpi-top");
    top.appendChild(el("span", "kpi-title", title));
    top.appendChild(el("b", "kpi-value", value));
    card.appendChild(top);
    var bar = el("div", "kpi-bar");
    var fill = el("i");
    fill.style.width = (grade === "total" ? 100 : (pct || 0)) + "%";
    bar.appendChild(fill);
    card.appendChild(bar);
    card.appendChild(el("div", "kpi-sub", sub));
    return card;
  }

  function renderHealthKpis(report) {
    var box = $("healthKpis");
    if (!box) return;
    box.textContent = "";
    if (!report) return;
    var counts = report.grade_counts || {};
    var comps = report.components || [];
    var total = report.component_count != null ? report.component_count : comps.length;
    var order = ["A", "B", "C", "D"];
    var names = { A: "强", B: "较强", C: "一般", D: "弱" };

    box.appendChild(kpiCard("total", "组件总数", String(total), "纳入评估", 100));
    order.forEach(function (g) {
      var n = counts[g] || 0;
      var pct = total ? Math.round(n * 100 / total) : 0;
      box.appendChild(kpiCard(g, g + " 级 · " + names[g], String(n), n + " 个 · " + pct + "%", pct));
    });

    var stamp = $("healthStamp");
    if (stamp) {
      stamp.textContent = report.generated_at ? "更新于 " + fmtDate(report.generated_at) : "";
    }
  }

  function renderHealthCard(c) {
    var card = el("article", "card health-card");
    var head = el("div", "card-head");
    var pkg = el("div", "pkg");
    pkg.appendChild(el("span", "eco", c.eco || "—"));
    pkg.appendChild(el("span", "name", c.display || c.purl || "—"));
    head.appendChild(pkg);

    var badges = el("div", "badges");
    badges.appendChild(el("span", gradeClass(c.grade), c.grade + " · " + (c.level || "")));
    badges.appendChild(el("span", "count", (c.score != null ? c.score.toFixed(1) : "—") + " 分"));
    head.appendChild(badges);
    card.appendChild(head);

    var body = el("div", "health-body");
    if (c.archived) {
      body.appendChild(el("div", "health-alert",
        "⚠ 项目已归档 / 停止维护，社区支持基本中断，原则上不得引入。"));
    }

    var scoreBar = el("div", "score-bar sb-" + c.grade);
    var fill = el("i");
    fill.style.width = Math.max(0, Math.min(100, c.score || 0)) + "%";
    scoreBar.appendChild(fill);
    body.appendChild(scoreBar);

    var grid = el("div", "signals");
    var rows = [
      ["最近提交", fmtDays(c.last_commit_days)],
      ["近12月发布", c.releases_12m == null ? "未知" : (c.releases_12m + " 次")],
      ["维护者", c.maintainers == null ? "未知" : (c.maintainers + " 人")],
      ["背后组织", orgLabel(c.org_backing)],
      ["月下载量", fmtCount(c.monthly_downloads)]
    ];
    rows.forEach(function (kv) {
      var sig = el("div", "signal");
      sig.appendChild(el("span", "k", kv[0]));
      sig.appendChild(el("span", "v", kv[1]));
      grid.appendChild(sig);
    });
    body.appendChild(grid);

    var sources = c.sources || [];
    if (sources.length) {
      var srcBox = el("div", "health-sources");
      srcBox.appendChild(el("span", "health-sources-label", "数据来源"));
      sources.forEach(function (src) {
        srcBox.appendChild(el("span", "src", SOURCE_LABELS[src] || src));
      });
      body.appendChild(srcBox);
    }

    var missing = c.missing || [];
    if (missing.length) {
      body.appendChild(el("p", "health-missing",
        "缺失 " + missing.length + " 项信号（" + missing.join("、") + "）——按「未知即风险」已计入扣分。"));
    }

    if (c.advice) body.appendChild(el("p", "advice", c.advice));
    card.appendChild(body);
    return card;
  }

  function sortHealth(list) {
    list.sort(function (a, b) {
      var ca = a.component, cb = b.component;
      if (healthState.sort === "score") return (cb.score || 0) - (ca.score || 0);
      if (healthState.sort === "name") return String(ca.display).localeCompare(String(cb.display));
      var rank = { A: 0, B: 1, C: 2, D: 3 };
      var ra = rank[ca.grade] != null ? rank[ca.grade] : 9;
      var rb = rank[cb.grade] != null ? rank[cb.grade] : 9;
      if (ra !== rb) return ra - rb;
      return (cb.score || 0) - (ca.score || 0);
    });
    return list;
  }

  function renderHealth() {
    var report = healthState.data;
    if (!report) return;
    renderHealthKpis(report);

    var list, missing;
    if (healthState.queryMode) {
      list = healthState.matched.slice();
      missing = healthState.missing.slice();
    } else {
      list = (report.components || []).map(function (c) {
        return { component: c, entry: null, exactVersion: true, candidates: 1, duplicates: [] };
      });
      missing = [];
    }

    if (healthState.grade !== "ALL") {
      list = list.filter(function (m) { return m.component.grade === healthState.grade; });
    }
    var q = String(healthState.query || "").trim().toLowerCase();
    if (q) {
      list = list.filter(function (m) { return healthHay(m.component).indexOf(q) !== -1; });
      missing = missing.filter(function (m) {
        return healthEntryLine(m.entry).toLowerCase().indexOf(q) !== -1 ||
          String(m.reason || "").toLowerCase().indexOf(q) !== -1;
      });
    }
    sortHealth(list);

    var host = $("healthResults");
    host.textContent = "";
    if (!list.length && !missing.length) {
      var all = (report.components || []).length;
      host.appendChild(el("div", "empty", all
        ? "当前筛选条件下没有组件（已采集 " + all + " 个），试试清空搜索或切回「全部等级」。"
        : "报告中没有组件数据。"));
      return;
    }
    list.forEach(function (item) { host.appendChild(renderHealthMatchedCard(item)); });
    missing.forEach(function (item) { host.appendChild(renderHealthMissingCard(item)); });
  }

  function initHealthControls() {
    var sortSel = $("healthSort");
    if (sortSel) sortSel.addEventListener("change", function () { healthState.sort = this.value; renderHealth(); });
    var gradeSel = $("healthGrade");
    if (gradeSel) gradeSel.addEventListener("change", function () { healthState.grade = this.value; renderHealth(); });
    var search = $("healthSearch");
    if (search) search.addEventListener("input", function () { healthState.query = this.value; renderHealth(); });
    var refresh = $("healthRefresh");
    if (refresh) refresh.addEventListener("click", function () {
      // 允许重新拉取：数据文件可能在 CI 跑完后才出现
      healthState.attempted = false;
      healthState.data = null;
      loadHealth();
    });

    var runBtn = $("healthRun");
    if (runBtn) runBtn.addEventListener("click", runHealthQuery);
    var ta = $("healthQuery");
    if (ta) {
      ta.addEventListener("keydown", function (ev) {
        if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") runHealthQuery();
      });
    }
    var clearBtn = $("healthClear");
    if (clearBtn) clearBtn.addEventListener("click", function () {
      if (ta) ta.value = "";
      healthState.queryMode = false;
      healthState.matched = [];
      healthState.missing = [];
      healthState.pendingQuery = false;
      healthState.query = "";
      if ($("healthSearch")) $("healthSearch").value = "";
      var btn = $("healthCopyMissing");
      if (btn) btn.hidden = true;
      healthStatus("");
      renderHealth();
    });
    var copyBtn = $("healthCopyMissing");
    if (copyBtn) copyBtn.addEventListener("click", copyHealthMissing);
  }

  var tabsBound = false;

  function switchTab(name, opts) {
    var tabs = document.querySelectorAll(".tab");
    var found = false;
    for (var i = 0; i < tabs.length; i++) {
      var on = tabs[i].getAttribute("data-tab") === name;
      if (on) found = true;
      tabs[i].classList.toggle("active", on);
      tabs[i].setAttribute("aria-selected", on ? "true" : "false");
      tabs[i].tabIndex = on ? 0 : -1;
    }
    if (!found) return;

    var panes = document.querySelectorAll(".pane");
    for (var k = 0; k < panes.length; k++) {
      panes[k].hidden = panes[k].id !== ("pane-" + name);
    }

    // 写入 hash，便于分享与刷新后保持当前 tab（首次静默恢复时不改写）
    if (!(opts && opts.silent) && window.location.hash !== "#" + name) {
      try { history.replaceState(null, "", "#" + name); } catch (e) { /* 忽略 */ }
    }
    if (name === "health") loadHealth();
  }

  function initTabs() {
    if (tabsBound) return;
    tabsBound = true;

    // 事件委托而非逐个绑定：即使后续 DOM 变动或初始化中途出错，点击依然可用。
    document.addEventListener("click", function (ev) {
      var node = ev.target;
      while (node && node !== document &&
        !(node.classList && node.classList.contains("tab"))) {
        node = node.parentNode;
      }
      if (!node || !node.classList || !node.classList.contains("tab")) return;
      switchTab(node.getAttribute("data-tab"));
    });

    // 键盘可达性：焦点在 tab 上时左右方向键切换
    document.addEventListener("keydown", function (ev) {
      if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
      var active = document.querySelector(".tab.active");
      if (!active || document.activeElement !== active) return;
      var tabs = document.querySelectorAll(".tab");
      for (var i = 0; i < tabs.length; i++) {
        if (tabs[i] === active) {
          var idx = ev.key === "ArrowRight" ? i + 1 : i - 1;
          if (idx < 0) idx = tabs.length - 1;
          if (idx >= tabs.length) idx = 0;
          tabs[idx].focus();
          switchTab(tabs[idx].getAttribute("data-tab"));
          break;
        }
      }
    });

    // 支持 #health 深链 / 刷新后保持当前 tab
    var hash = String(window.location.hash || "").replace("#", "");
    if (hash === "health" || hash === "vuln") switchTab(hash, { silent: true });
  }

  /* --------------------------- 初始化 --------------------------- */
  function loadLocal() {
    return fetch(VULNS_URL, { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        var lm = r.headers.get("last-modified");
        return r.json().then(function (raw) { return { raw: raw, lastModified: lm }; });
      })
      .then(function (res) { buildIndex(res.raw); return res; })
      .catch(function () { localIndex = []; return null; });
  }

  function init() {
    // tab 切换是最基础的能力：最先挂载，并逐项做异常隔离，
    // 避免后续任一初始化报错（如元素缺失）把整个交互打死。
    try { initTabs(); } catch (e) {}
    try { initToolbar(); } catch (e) {}
    try { initHealthControls(); } catch (e) {}
    try { initPopularControls(); } catch (e) {}

    if (OFFLINE) {
      var wrap = $("forceLiveWrap");
      if (wrap) wrap.hidden = true;
      var tag = $("offlineTag");
      if (tag) tag.hidden = false;
    }

    $("run").addEventListener("click", run);
    $("clear").addEventListener("click", function () {
      $("query").value = "";
      $("results").textContent = "";
      $("toolbar").hidden = true;
      $("cveStats").textContent = "";
      // 一并重置过滤/排序条件，避免下次查询沿用旧条件导致结果为空
      state.results = [];
      state.filter = "";
      state.sev = "ALL";
      state.sort = "sev";
      state.view = "pkg";
      $("filter").value = "";
      $("sevFilter").value = "ALL";
      $("sortBy").value = "sev";
      syncViewSwitch();
      setStatus("", false);
    });
    $("query").addEventListener("keydown", function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") run();
    });

    loadChips();
    loadPopular();

    loadLocal().then(function (res) {
      if (res) {
        var pkgCount = localIndex.length;
        var vulnCount = 0, cveSet = {};
        localIndex.forEach(function (k) {
          recordItems(k.entry).forEach(function (it) {
            vulnCount++;
            collectCves(it.osv || {}, it.nvd || null).forEach(function (c) { cveSet[c] = 1; });
          });
        });
        var cveTotal = Object.keys(cveSet).length;
        var when = res.lastModified ? fmtDate(res.lastModified) : "";
        $("dataStamp").textContent = "本地漏洞库：" + pkgCount + " 组件 / " + vulnCount +
          " 条记录 / " + cveTotal + " 个 CVE" + (when ? "（更新于 " + when + "）" : "");
      } else {
        $("dataStamp").textContent = "本地 vulns.json 暂不可用，将直接实时查询 OSV";
      }
    });
  }

  /* 暴露少量纯函数，便于在控制台调试 / 自测 */
  if (typeof window !== "undefined") {
    window.ScaBase = {
      parseLine: parseLine,
      parseInput: parseInput,
      normalize: normalize,
      canonEco: canonEco,
      buildIndex: buildIndex,
      localLookup: localLookup,
      recordItems: recordItems,
      collectCves: collectCves,
      sortCves: sortCves,
      cveGroups: cveGroups,
      parseHealthPurl: parseHealthPurl,
      healthNameKeys: healthNameKeys,
      buildHealthIndex: buildHealthIndex,
      matchHealth: matchHealth
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

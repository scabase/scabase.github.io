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
  function renderChips(lines) {
    var wrap = $("exampleChips");
    wrap.textContent = "";
    lines.slice(0, 14).forEach(function (text) {
      var chip = el("button", "chip", text);
      chip.type = "button";
      chip.addEventListener("click", function () {
        var ta = $("query");
        ta.value = ta.value.trim() ? ta.value.replace(/\s*$/, "") + "\n" + text : text;
        ta.focus();
      });
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
    initToolbar();

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
      cveGroups: cveGroups
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

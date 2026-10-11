/* ScaBase · 漏洞查询前端
 *
 * 数据来源：
 *   1) 本地漏洞库  scabase-fetcher/data/vulns.json
 *      结构：{ "eco|pkg|ver": { "osv_raw": {vulns:[...]}, "enriched": [{osv, nvd}, ...] }, ... }
 *   2) 实时查询    https://api.osv.dev/v1/query
 *
 * 输入格式（每行一条，支持 # 注释、空行）：
 *   - pkg_list   ecosystem|package|version      （与 data/pkg_list.txt 一致）
 *   - GAV        groupId:artifactId[:version]   （Maven）
 *   - 简写       ecosystem:package[@version]
 */
(function () {
  "use strict";

  var VULNS_URL = "scabase-fetcher/data/vulns.json";
  var PKG_LIST_URL = "scabase-fetcher/data/pkg_list.txt";
  var OSV_API = "https://api.osv.dev/v1/query";
  var OSV_VULN = "https://osv.dev/vulnerability/";
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

  /* 生态别名 -> OSV 规范名 */
  function canonEco(raw) {
    var key = String(raw || "").trim();
    var lower = key.toLowerCase();
    if (ECO_LOOKUP[lower]) return ECO_LOOKUP[lower];
    if (ALIASES[lower]) return ALIASES[lower];
    return key;
  }

  /* --------------------------- 输入解析 --------------------------- */
  /* 返回 { ecosystem, name, version, kind } */
  function parseLine(line) {
    var text = line.trim();

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
    throw new Error("无法识别（需为 pkg_list / GAV / ecosystem:package@version）：" + text);
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

  /* item = { osv, nvd } */
  function normalize(item) {
    var v = item.osv || item || {};
    var nvd = item.nvd || null;
    var ns = nvdInfo(nvd);
    var os = osvSev(v);
    var aliases = Array.isArray(v.aliases) ? v.aliases : [];
    var cve = aliases.filter(function (a) { return /^CVE-/.test(a); })[0] ||
              (v.id && /^CVE-/.test(v.id) ? v.id : null);
    var refUrls = refs(v.references);
    if (nvd && nvd.references) refUrls = refUrls.concat(refs(nvd.references));
    return {
      id: v.id || cve || "(unknown)",
      cve: cve,
      summary: v.summary || ns.desc || "",
      details: (v.details || "").trim(),
      published: v.published || (nvd && nvd.published) || null,
      severityLabel: ns.label || os.label || "UNKNOWN",
      score: ns.score,
      vector: ns.vector || os.vector || null,
      cwe: ns.cwe,
      hasNvd: !!nvd,
      refs: refUrls.filter(function (u, i, a) { return a.indexOf(u) === i; })
    };
  }

  /* 从本地记录中取出 {osv,nvd} 列表 */
  function recordItems(rec) {
    var e = (rec && rec.entry) || {};
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

  /* --------------------------- 实时 OSV --------------------------- */
  function osvQuery(entry) {
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

  function renderVuln(v) {
    var box = el("div", "vuln");

    var top = el("div", "vuln-top");
    var link = el("a", "vid", v.id);
    link.href = OSV_VULN + encodeURIComponent(v.id);
    link.target = "_blank"; link.rel = "noopener";
    top.appendChild(link);

    var sevText = v.score != null ? v.severityLabel + " " + v.score : v.severityLabel;
    top.appendChild(el("span", sevClass(v.severityLabel), sevText));
    if (v.cve) top.appendChild(el("span", "cve", v.cve));
    if (v.hasNvd) top.appendChild(el("span", "src nvd", "NVD"));
    if (v.published) top.appendChild(el("span", "date", fmtDate(v.published)));
    box.appendChild(top);

    if (v.summary) box.appendChild(el("p", "summary", v.summary));

    var extras = [];
    if (v.vector) extras.push(v.vector);
    if (v.cwe.length) extras.push("CWE: " + v.cwe.join(", "));

    if (v.details || extras.length || v.refs.length) {
      var details = el("details", "detail");
      details.appendChild(el("summary", null, "详情与参考链接"));
      extras.forEach(function (t) { details.appendChild(el("div", "vector", t)); });
      if (v.details) details.appendChild(el("pre", null, v.details));
      if (v.refs.length) {
        var ul = el("ul", "refs");
        v.refs.slice(0, 12).forEach(function (url) {
          var li = el("li");
          var a = el("a", null, url);
          a.href = url; a.target = "_blank"; a.rel = "noopener";
          li.appendChild(a); ul.appendChild(li);
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
    badges.appendChild(el("span", "count", result.vulns.length + " 条"));
    head.appendChild(badges);
    card.appendChild(head);

    var body = el("div", "vulns");
    if (result.error) {
      body.appendChild(el("div", "empty", "查询失败：" + result.error));
    } else if (!result.vulns.length) {
      body.appendChild(el("div", "empty no-vuln", "✓ 未发现已知漏洞"));
    } else {
      result.vulns.forEach(function (v) { body.appendChild(renderVuln(v)); });
    }
    if (result.note) body.appendChild(el("div", "empty", result.note));
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

  /* --------------------------- 主流程 --------------------------- */
  var running = false;

  function dedupe(items) {
    var seen = {}, out = [];
    items.forEach(function (v) {
      var key = v.id;
      if (!seen[key]) { seen[key] = true; out.push(v); }
    });
    return out;
  }

  function run() {
    if (running) return;
    var parsed = parseInput($("query").value);
    var errors = parsed.errors.slice();
    if (!parsed.entries.length && !errors.length) {
      setStatus("请输入至少一个组件（pkg_list 或 GAV）。", true);
      return;
    }

    running = true;
    $("run").disabled = true;
    $("results").textContent = "";
    setStatus("正在查询 " + parsed.entries.length + " 个组件…", false, true);

    var forceLive = $("forceLive").checked;

    mapLimit(parsed.entries, CONCURRENCY, function (entry) {
      var rec = localLookup(entry);
      var cachedVulns = rec ? recordItems(rec).map(normalize) : null;

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
        return { entry: entry, localHit: false, usedLive: true, vulns: live, error: null };
      }).catch(function (err) {
        if (rec) {
          return {
            entry: entry, localHit: true, usedLive: false,
            vulns: cachedVulns, error: null, note: "实时 OSV 查询失败，已回退本地漏洞库：" + err.message
          };
        }
        return { entry: entry, localHit: false, usedLive: true, vulns: [], error: err.message };
      });
    }).then(function (results) {
      results.forEach(function (r) {
        if (r && r.__error) {
          $("results").appendChild(renderCard({
            entry: { ecosystem: "?", name: "(error)", version: null },
            vulns: [], error: r.__error.message
          }));
          return;
        }
        $("results").appendChild(renderCard(r));
      });

      var total = results.reduce(function (n, r) {
        return n + (r && r.vulns ? r.vulns.length : 0);
      }, 0);
      var msg = "完成：共 " + parsed.entries.length + " 个组件，" + total + " 条漏洞记录";
      if (errors.length) msg += "；" + errors.length + " 行无法解析（" + errors.join("；") + "）";
      setStatus(msg, false);
      running = false;
      $("run").disabled = false;
    });
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
    $("run").addEventListener("click", run);
    $("clear").addEventListener("click", function () {
      $("query").value = "";
      $("results").textContent = "";
      setStatus("", false);
    });
    $("query").addEventListener("keydown", function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") run();
    });

    loadChips();

    loadLocal().then(function (res) {
      if (res) {
        var pkgCount = localIndex.length;
        var vulnCount = localIndex.reduce(function (n, k) {
          return n + recordItems(k.entry).length;
        }, 0);
        var when = res.lastModified ? fmtDate(res.lastModified) : "";
        $("dataStamp").textContent = "本地漏洞库：" + pkgCount + " 组件 / " + vulnCount + " 条记录" +
          (when ? "（更新于 " + when + "）" : "");
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
      recordItems: recordItems
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

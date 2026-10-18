/* 前端冒烟自测（jsdom + 本地数据桩，不联网、不入版本管理的测试框架）.
 *
 * 用法：
 *   NODE_PATH=/Users/block/.workbuddy/binaries/node/workspace/node_modules \
 *     node /Users/block/code/scabase.github.io/tests/.tmp-frontend-smoke.js
 *
 * 覆盖：
 *   - 示例 chips（Top 清单按钮）点击后按 10/50/100 行填入对应输入框
 *   - 健康度 tab 支持 pkg_list / GAV / eco:pkg@ver 输入检索
 *   - 未收录组件单独成卡并可复制清单
 */
const fs = require("fs");
const path = require("path");
const { JSDOM, VirtualConsole } = require("jsdom");

const ROOT = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const appJs = fs.readFileSync(path.join(ROOT, "assets", "app.js"), "utf8");
const health = JSON.parse(
  fs.readFileSync(path.join(ROOT, "scabase-fetcher", "data", "community-support.json"), "utf8"));
const popular = JSON.parse(
  fs.readFileSync(path.join(ROOT, "scabase-fetcher", "data", "popular-packages.json"), "utf8"));
const softwareVulns = JSON.parse(
  fs.readFileSync(path.join(ROOT, "scabase-fetcher", "data", "software-vulns.json"), "utf8"));
const softwareSupport = JSON.parse(
  fs.readFileSync(path.join(ROOT, "scabase-fetcher", "data", "software-support.json"), "utf8"));

/* 模拟线上旧数据场景：只注入 sources，不注入 repo/deps_dev/registry 字段，
   验证前端能从 purl / repo-map 推导出可点击的来源链接（CI 尚未刷新数据时同样可点） */
(health.components || []).forEach(function (c) {
  c.sources = ["github", "deps.dev", "npm-registry", "pypi"];
});

/* 模拟「清单内但健康度尚未采集」：CI 首跑后 65 个软件的健康度可能全部有数据，
   此处从桩数据里摘掉 Apache Tomcat，回归「未采集」卡 + 仓库链接的渲染路径 */
const swSupportStripped = JSON.parse(JSON.stringify(softwareSupport));
swSupportStripped.components = (swSupportStripped.components || [])
  .filter(function (c) { return c.software !== "Apache Tomcat"; });

/* 未采集软件的期望个数从数据推导，避免 CI 采集进度变化后断言失效 */
const expectedDimChips = (softwareVulns.software || []).filter(function (s) {
  return !s.cve_count;
}).length;

const failures = [];
function check(name, cond, extra) {
  if (cond) { console.log("ok   -", name); return; }
  console.log("FAIL -", name, extra === undefined ? "" : JSON.stringify(extra));
  failures.push(name);
}

/* 本地数据桩：只拦截站点数据文件的 fetch */
const dom = new JSDOM(html, { runScripts: "outside-only", url: "https://example.invalid/" });
const { window } = dom;
window.fetch = function (url) {
  const to = String(url || "");
  if (to.indexOf("community-support.json") !== -1) {
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
      json: () => Promise.resolve(health) });
  }
  if (to.indexOf("popular-packages.json") !== -1) {
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
      json: () => Promise.resolve(popular) });
  }
  if (to.indexOf("software-vulns.json") !== -1) {
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
      json: () => Promise.resolve(softwareVulns) });
  }
  if (to.indexOf("software-support.json") !== -1) {
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
      json: () => Promise.resolve(swSupportStripped) });
  }
  if (to.indexOf("repo-map.json") !== -1) {
    return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
      json: () => Promise.resolve(JSON.parse(
        fs.readFileSync(path.join(ROOT, "scabase-fetcher", "data", "repo-map.json"), "utf8"))) });
  }
  return Promise.resolve({ ok: false, status: 404, headers: { get: () => null },
    text: () => Promise.resolve(""), json: () => Promise.reject(new Error("nope")) });
};
window.navigator.clipboard = { writeText: (t) => { window.__copied = t; return Promise.resolve(); } };

const virtualConsole = new VirtualConsole();
virtualConsole.on("jsdomError", (e) => console.log("jsdom error:", e.message));

window.eval(appJs);

setTimeout(() => {
  const $ = (id) => window.document.getElementById(id);

  /* ---------- 常用依赖 Top 清单面板 ---------- */
  check("Top 清单面板已显示", $("popularPanel").hidden === false);
  check("Top 清单面板默认折叠", $("popularPanel").open === false);
  // 布局回归：输入框置顶，选择项（Top 清单 / chips）在其下方
  check("查询框位于 Top 清单面板上方",
    ($("query").compareDocumentPosition($("popularPanel")) & 4) !== 0);
  // 健康度 tab：输入框同样置顶（标题/简介/KPI 在其之后）
  check("健康度查询框位于 KPI 上方",
    ($("healthQuery").compareDocumentPosition($("healthKpis")) & 4) !== 0);
  // 健康度 tab：快速填入 chips 必须位于帮助说明上方
  check("健康度快速填入位于帮助说明上方",
    ($("healthExamples").compareDocumentPosition(
      $("pane-health").querySelector("details.help")) & 4) !== 0);
  check("页脚提供 llms.txt 入口",
    Array.from(window.document.querySelectorAll(".site-footer a"))
      .some((a) => /llms\.txt$/.test(a.getAttribute("href") || "")));
  const tabs = $("popTabs").querySelectorAll(".pop-tab");
  check("渲染 4 个生态 tab", tabs.length === 4, tabs.length);
  check("默认选中 Maven", tabs[0].classList.contains("active"), tabs[0].textContent);
  check("tab 展示条数", /Maven 常用 Top 1000 · 1000/.test(tabs[0].textContent),
    tabs[0].textContent);
  check("排序依据有说明", $("popBasis").textContent.length > 5, $("popBasis").textContent);

  const rows = $("popList").querySelectorAll(".pop-row");
  check("首屏渲染 60 行", rows.length === 60, rows.length);
  check("行内含包名与版本", /@/.test(rows[0].querySelector(".pop-ver").textContent),
    rows[0].textContent.trim());

  // 点击行 -> 追加到查询框
  $("query").value = "";
  rows[0].click();
  check("点击行填入查询框", /^maven\|[^|]+\|[^|]+$/.test($("query").value.trim()),
    $("query").value);

  // 显示更多
  $("popMore").click();
  check("显示更多后渲染 120 行", $("popList").querySelectorAll(".pop-row").length === 120,
    $("popList").querySelectorAll(".pop-row").length);

  // 过滤
  $("popSearch").value = "jackson";
  $("popSearch").dispatchEvent(new window.Event("input"));
  const filtered = $("popList").querySelectorAll(".pop-row");
  check("按名称过滤生效", filtered.length > 0 && filtered.length < 60, filtered.length);
  check("过滤结果都含关键词",
    Array.from(filtered).every((r) => /jackson/i.test(r.textContent)), null);
  $("popSearch").value = "";
  $("popSearch").dispatchEvent(new window.Event("input"));

  // 填入前 N 条
  $("query").value = "";
  $("popFillN").value = "10";
  $("popFill").click();
  check("填入前 10 条", $("query").value.trim().split(/\n/).length === 10,
    $("query").value.trim().split(/\n/).length);

  // 切换生态
  tabs[1].click();  // npm
  check("切换 tab 后重新渲染", $("popList").querySelectorAll(".pop-row").length === 60,
    $("popList").querySelectorAll(".pop-row").length);
  $("query").value = "";
  $("popList").querySelectorAll(".pop-row")[0].click();
  check("NPM 行填入 npm 格式", /^npm\|/.test($("query").value.trim()), $("query").value);

  /* ---------- 软件维度：漏洞查询 ---------- */
  const swChipCount = $("softwareChips").querySelectorAll(".chip").length;
  check("软件 chips 渲染全量清单", swChipCount === 65, swChipCount);
  check("软件 chips 按分类分组",
    $("softwareChips").querySelectorAll(".chip-group").length >= 10,
    $("softwareChips").querySelectorAll(".chip-group").length);
  check("未采集软件为暗色 chips",
    $("softwareChips").querySelectorAll(".chip-dim").length === expectedDimChips,
    { got: $("softwareChips").querySelectorAll(".chip-dim").length, expect: expectedDimChips });
  check("软件示例区已展开", $("softwareExamples").hidden === false);
  // 两个页签共用同一份软件查询清单（统一查询清单）
  const healthChipTexts = Array.from(
    $("softwareHealthChips").querySelectorAll(".chip")).map((c) => c.textContent);
  const vulnChipTexts = Array.from(
    $("softwareChips").querySelectorAll(".chip")).map((c) => c.textContent);
  check("两个页签软件 chips 完全一致",
    vulnChipTexts.length === healthChipTexts.length &&
    vulnChipTexts.every((n, i) => n === healthChipTexts[i]), null);

  $("query").value = "nginx 1.24.0";
  $("run").click();
  const swBox = $("softwareResults");
  check("软件结果区已显示", swBox.hidden === false);
  const swCards = swBox.querySelectorAll(".software-card");
  check("渲染 1 张软件卡", swCards.length === 1, swCards.length);
  check("软件卡标注生态与 CVE 数",
    swCards[0].querySelector(".eco").textContent === "软件" &&
    /条 CVE/.test(swCards[0].textContent), swCards[0].textContent.slice(0, 80));
  const swCves = swCards[0].querySelectorAll(".sw-cve");
  check("nginx 1.24.0 命中受影响 CVE", swCves.length > 0, swCves.length);
  check("CVE 编号链接到 NVD 详情",
    Array.from(swCves).every((r) => /^https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-/.test(
      (r.querySelector(".sw-cve-id") || {}).getAttribute("href") || "")), null);
  check("影响版本区间有文本", /影响版本/.test(swCards[0].textContent));

  // 版本过滤：7-Zip 23.01 有受影响 CVE，虚构版本 99.99 应被 CPE 区间过滤掉大部分
  $("query").value = "7-Zip 23.01";
  $("run").click();
  const zipCves = $("softwareResults").querySelectorAll(".sw-cve");
  check("7-Zip 23.01 命中受影响 CVE", zipCves.length > 0, zipCves.length);
  $("query").value = "7-Zip 99.99";
  $("run").click();
  check("虚构版本 99.99 被 CPE 区间过滤",
    $("softwareResults").querySelectorAll(".sw-cve").length < 30 &&
    $("softwareResults").querySelectorAll(".sw-cve").length < zipCves.length,
    { v99: $("softwareResults").querySelectorAll(".sw-cve").length, v2301: zipCves.length });

  // 不带版本 -> 展示全部 CVE（zookeeper 共 15 条）
  $("query").value = "zookeeper";
  $("run").click();
  check("不带版本时展示全部 CVE",
    $("softwareResults").querySelectorAll(".sw-cve").length === 15,
    $("softwareResults").querySelectorAll(".sw-cve").length);

  // 清单内未采集软件（CI 采集进度外的占位项）：卡片 + 数据来源链接
  // （NVD / GitHub 均可点击人工核对）
  $("query").value = "containerd";
  $("run").click();
  const pendingCard = $("softwareResults").querySelector(".software-card");
  check("漏洞 tab 渲染未采集软件卡", !!pendingCard, null);
  check("软件卡带 NVD / GitHub 来源链接",
    !!pendingCard && pendingCard.querySelectorAll(".health-sources a").length === 2 &&
    /nvd\.nist\.gov/.test(pendingCard.querySelector(".health-sources a").getAttribute("href")),
    pendingCard && Array.from(pendingCard.querySelectorAll(".health-sources a"))
      .map((a) => a.getAttribute("href")));
  check("未采集空态说明采集节奏",
    !!pendingCard && /software-collect\.yml/.test(pendingCard.textContent),
    pendingCard && pendingCard.textContent.slice(0, 120));

  // 混合输入：软件 + 库（lodash 在本地 vulns.json 样本中，不发网络）；
  // 软件部分同步渲染，库部分走异步查询链（由后续用例覆盖渲染）
  $("query").value = "k8s\nnpm|lodash|4.17.20";
  $("run").click();
  check("混合查询时软件结果区仍渲染",
    $("softwareResults").hidden === false &&
    $("softwareResults").querySelectorAll(".software-card").length === 1, null);
  check("混合查询时库维度进入查询流程", /查询/.test($("status").textContent),
    $("status").textContent);

  const healthChips = $("healthExampleChips").querySelectorAll(".chip-list");
  check("健康度 tab 渲染 5 个清单 chip", healthChips.length === 5, healthChips.length);
  check("健康度示例区已展开", $("healthExamples").hidden === false);
  healthChips[0].click();
  check("健康度 chip 填入 Top 20",
    $("healthQuery").value.trim().split(/\n/).length === 20,
    $("healthQuery").value.trim().split(/\n/).length);

  /* ---------- 健康度查询 ---------- */
  const loadHealth = window.ScaBase && true;
  $("tab-health").click();

  setTimeout(() => {
    const input = [
      "# 注释行",
      "maven|com.alibaba:fastjson|1.2.24",
      "npm|lodash",                       // 不带版本
      "pypi:requests@2.31.0",             // 简写 + 版本未采集 -> 回退同名最高分
      "log4j:log4j",                      // GAV 无版本
      "npm|react",                        // 未收录
      "CVE-2021-44228",                   // CVE -> 提示需填组件
      "not a package line at all"         // 解析失败
    ].join("\n");
    $("healthQuery").value = input;
    $("healthRun").click();

    const status = $("healthStatus").textContent;
    check("查询汇总显示输入条数", /输入 6 条/.test(status), status);
    check("命中 4 个组件", /命中 4 个组件/.test(status), status);
    check("未收录 2 条（含 CVE 行）", /未收录 2 条/.test(status), status);
    check("解析失败 1 行有提示", /解析失败 1 行/.test(status), status);

    const cards = $("healthResults").querySelectorAll(".health-card");
    check("结果区渲染 6 张卡（4 命中 + 2 未收录）", cards.length === 6, cards.length);
    /* 来源徽章可点击（模拟线上旧数据：无 repo/deps_dev/registry 字段，
       链接由前端从 purl 与 repo-map 推导） */
    const badgesOf = (root) => Array.from(
      (root || $("healthResults")).querySelectorAll(".health-sources .src"));
    const cardOf = (namePart) => Array.from(cards).find((card) =>
      String((card.querySelector(".pkg .name") || {}).textContent).indexOf(namePart) !== -1);
    // repo-map 异步到位后会触发重渲染，先等 GitHub 徽章变成链接
    const waitRepoMap = (cb) => {
      let tries = 0;
      const tick = () => {
        if (badgesOf().some((b) => b.tagName === "A" &&
            /^https:\/\/github\.com\//.test(b.getAttribute("href") || "")) || ++tries > 50) {
          cb();
        } else {
          setTimeout(tick, 20);
        }
      };
      tick();
    };
    waitRepoMap(() => {
      const srcBadges = badgesOf();
      const srcLinks = srcBadges.filter((b) => b.tagName === "A");
      check("健康度卡片渲染数据来源徽章", srcBadges.length >= 2, srcBadges.length);
      check("来源徽章含 deps.dev",
        srcBadges.some((b) => b.textContent === "deps.dev"));
      check("无链接字段时徽章仍可点击（前端推导兜底）", srcLinks.length >= 8, srcLinks.length);
      check("来源链接均在新窗口打开且带 noopener",
        srcLinks.length > 0 &&
        srcLinks.every((b) => b.target === "_blank" && b.rel === "noopener"));

      const lodashCard = cardOf("lodash");
      check("查询结果含 lodash 卡片", !!lodashCard);
      if (lodashCard) {
        const hrefOf = (label) => {
          const b = badgesOf(lodashCard).find((x) => x.textContent === label);
          return b ? b.getAttribute("href") : null;
        };
        check("lodash 的 GitHub 徽章指向 repo-map 仓库",
          hrefOf("GitHub") === "https://github.com/lodash/lodash", hrefOf("GitHub"));
        check("lodash 的 deps.dev 徽章推导出包页面",
          hrefOf("deps.dev") === "https://deps.dev/npm/lodash", hrefOf("deps.dev"));
        check("lodash 的 npm registry 徽章指向 npmjs.com",
          hrefOf("npm registry") === "https://www.npmjs.com/package/lodash",
          hrefOf("npm registry"));
      }

      const fastjsonCard = cardOf("fastjson");
      check("查询结果含 fastjson 卡片", !!fastjsonCard);
      if (fastjsonCard) {
        const gh = badgesOf(fastjsonCard).find((x) => x.textContent === "GitHub");
        check("Maven 组件 GitHub 徽章指向 repo-map 仓库",
          !!gh && gh.tagName === "A" &&
          gh.getAttribute("href") === "https://github.com/alibaba/fastjson",
          gh && gh.getAttribute("href"));
        const dv = badgesOf(fastjsonCard).find((x) => x.textContent === "deps.dev");
        check("Maven 组件 deps.dev 徽章带冒号坐标",
          !!dv && dv.getAttribute("href") === "https://deps.dev/maven/com.alibaba:fastjson",
          dv && dv.getAttribute("href"));
      }

      const requestsCard = cardOf("requests");
      check("查询结果含 requests 卡片", !!requestsCard);
      if (requestsCard) {
        const dv = badgesOf(requestsCard).find((x) => x.textContent === "deps.dev");
        check("PyPI 组件 deps.dev 徽章推导出项目页",
          !!dv && dv.getAttribute("href") === "https://deps.dev/pypi/requests",
          dv && dv.getAttribute("href"));
        const rg = badgesOf(requestsCard).find((x) => x.textContent === "PyPI");
        check("PyPI 组件 registry 徽章指向 pypi.org",
          !!rg && rg.getAttribute("href") === "https://pypi.org/project/requests/",
          rg && rg.getAttribute("href"));
      }
    });
    const missed = $("healthResults").querySelectorAll(".health-miss");
    check("未收录卡片单独渲染", missed.length === 2, missed.length);

    const notes = Array.from($("healthResults").querySelectorAll(".health-querynote"))
      .map((n) => n.textContent);
    check("无版本匹配时标注报告版本", notes.some((t) => t.indexOf("未指定版本") !== -1), notes);
    check("版本不一致时给出提示", notes.some((t) => t.indexOf("报告实际评估版本") !== -1), notes);

    check("复制未收录清单按钮可见", $("healthCopyMissing").hidden === false);
    $("healthCopyMissing").click();
    setTimeout(() => {
      const copied = String(window.__copied || "").split(/\n/).filter(Boolean);
      check("复制内容含未收录条目", copied.indexOf("npm|react") !== -1, copied);

      /* ---------- 二次筛选（等级 + 搜索） ---------- */
      $("healthSearch").value = "lodash";
      $("healthSearch").dispatchEvent(new window.Event("input"));
      const filtered = $("healthResults").querySelectorAll(".health-card");
      check("搜索在查询结果内二次过滤", filtered.length === 1, filtered.length);
      $("healthSearch").value = "";
      $("healthSearch").dispatchEvent(new window.Event("input"));

      /* ---------- 软件维度：健康度查询 ---------- */
      $("healthQuery").value = "nginx\n7-Zip";
      $("healthRun").click();
      const swHealth = $("softwareHealth");
      check("软件健康度结果区已显示", swHealth.hidden === false);
      check("渲染 2 张软件健康度卡",
        swHealth.querySelectorAll(".health-card").length === 2,
        swHealth.querySelectorAll(".health-card").length);
      check("软件健康度卡带可点击 GitHub 来源徽章",
        Array.from(swHealth.querySelectorAll(".health-sources .src"))
          .some((b) => b.tagName === "A" &&
            /^https:\/\/github\.com\//.test(b.getAttribute("href") || "")), null);

      // 多词软件名与别名最长匹配（统一查询清单：怎么写都能查到）
      const swParseCases = [
        ["Apache HTTP Server", "Apache HTTP Server"],
        ["apache httpd 2.4.58", "Apache HTTP Server"],
        ["docker engine", "Docker Engine"],
        ["linux kernel 6.1", "Linux Kernel"],
        ["node.js 18", "Node.js"],
        ["7z 23.01", "7-Zip"],
        ["kube", "Kubernetes"],
        ["zk", "ZooKeeper"],
        ["nginx@1.24.0", "nginx"],
        ["nginx:1.24.0", "nginx"],
        ["nginx-1.24.0", "nginx"]
      ];
      swParseCases.forEach(function (pair) {
        $("healthQuery").value = pair[0];
        $("healthRun").click();
        const name = String((swHealth.querySelector(".pkg .name") || {}).textContent);
        check("健康度解析「" + pair[0] + "」→ " + pair[1],
          name.indexOf(pair[1]) === 0, name);
      });

      // 库坐标不能误判为软件（maven:group:artifact:version 不是 Apache Maven）
      $("healthQuery").value = "maven:org.springframework:spring-core:5.3.0";
      $("healthRun").click();
      check("GAV 行不误判为 Apache Maven",
        swHealth.hidden === true, swHealth.textContent.slice(0, 80));

      // 清单内未采集软件：未采集卡 + 仓库链接（数据来源可人工验证）
      $("healthQuery").value = "tomcat";
      $("healthRun").click();
      const missCard = swHealth.querySelector(".health-miss");
      check("清单内未采集软件渲染未采集卡",
        !!missCard && /未采集/.test(missCard.textContent),
        missCard && missCard.textContent.slice(0, 60));
      const missGh = missCard && missCard.querySelector(".health-sources a");
      check("未采集卡带 GitHub 仓库链接",
        !!missGh && missGh.getAttribute("href") === "https://github.com/apache/tomcat",
        missGh && missGh.getAttribute("href"));
      check("未采集卡说明采集节奏", /software-collect\.yml/.test(missCard.textContent), null);
      check("未采集时状态行区分未采集与未收录",
        /未采集 1 条/.test($("healthStatus").textContent), $("healthStatus").textContent);

      // 纯库查询：清掉上一次残留的软件结果
      $("healthQuery").value = "npm|lodash|4.17.20";
      $("healthRun").click();
      check("纯库查询清空软件健康度区（无残留）",
        swHealth.hidden === true && swHealth.textContent === "",
        swHealth.textContent.slice(0, 80));

      /* ---------- 清空回到全量浏览 ---------- */
      $("healthClear").click();
      check("清空后软件健康度区收起",
        $("softwareHealth").hidden === true &&
        $("softwareHealth").querySelectorAll(".health-card").length === 0, null);
      const all = $("healthResults").querySelectorAll(".health-card");
      check("清空后展示全部已采集组件", all.length === health.components.length,
        { got: all.length, expect: health.components.length });

      // 数据未带 repo 字段且 repo-map 未收录的组件：GitHub 徽章降级为纯文本，
      // deps.dev / 注册表仍可点（数据自 2026-10-18 CI 起自带 repo 字段，
      // 此处用真正无仓库的 go 组件回归降级路径）
      const r324 = Array.from(all).find((card) => {
        const name = String((card.querySelector(".pkg .name") || {}).textContent);
        return name.indexOf("go.uber.org/zap") !== -1;
      });
      check("全量浏览含 go.uber.org/zap 卡片", !!r324);
      if (r324) {
        const gh = Array.from(r324.querySelectorAll(".health-sources .src"))
          .find((x) => x.textContent === "GitHub");
        check("repo-map 未收录时 GitHub 徽章降级为纯文本",
          !!gh && gh.tagName === "SPAN");
        const dv = Array.from(r324.querySelectorAll(".health-sources .src"))
          .find((x) => x.textContent === "deps.dev");
        check("降级仅限 GitHub，deps.dev 徽章仍可点",
          !!dv && dv.tagName === "A" &&
          dv.getAttribute("href") === "https://deps.dev/go/go.uber.org/zap",
          dv && dv.getAttribute("href"));
      }

      /* ---------- 漏洞 tab：纯库查询清残留 ---------- */
      $("tab-vuln").click();
      $("query").value = "npm|lodash|4.17.20";
      $("run").click();
      check("纯库查询清空软件漏洞区（无残留）",
        $("softwareResults").hidden === true && $("softwareResults").textContent === "",
        $("softwareResults").textContent.slice(0, 80));

      /* ---------- 软件数据延迟到位的竞态回归 ----------
         数据未就绪时点查询：挂起 + 提示加载中，到位后自动补渲染，
         不能把「nginx」误报成无法识别 / 未收录（数据为空的观感） */
      raceRegression("vuln", () => raceRegression("health", () => {
        console.log(failures.length ? "\nFAILED: " + failures.join(" | ")
          : "\nALL PASSED (" + (loadHealth ? "health loaded" : "") + ")");
        process.exit(failures.length ? 1 : 0);
      }));
    }, 30);
  }, 60);
}, 60);

/* 竞态回归：新建一个软件数据延迟 700ms 到位的窗口，
   验证两个页签在数据未就绪时的挂起与自动补渲染（各用一个新窗口，
   保证点击发生时数据确实未到位）。 */
function raceRegression(pane, done) {
  const delayed = { "software-vulns.json": softwareVulns, "software-support.json": swSupportStripped };
  const dom = new JSDOM(html, { runScripts: "outside-only", url: "https://example.invalid/" });
  const { window } = dom;
  window.fetch = function (url) {
    const to = String(url || "");
    for (const key of Object.keys(delayed)) {
      if (to.indexOf(key) !== -1) {
        return new Promise((resolve) => setTimeout(() => resolve({
          ok: true, status: 200, headers: { get: () => null },
          json: () => Promise.resolve(delayed[key])
        }), 700));
      }
    }
    if (to.indexOf("community-support.json") !== -1) {
      return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
        json: () => Promise.resolve(health) });
    }
    if (to.indexOf("repo-map.json") !== -1) {
      return Promise.resolve({ ok: true, status: 200, headers: { get: () => null },
        json: () => Promise.resolve({}) });
    }
    return Promise.resolve({ ok: false, status: 404, headers: { get: () => null },
      text: () => Promise.resolve(""), json: () => Promise.reject(new Error("nope")) });
  };
  window.navigator.clipboard = { writeText: () => Promise.resolve() };
  window.eval(appJs);

  const isHealth = pane === "health";
  const runBtn = isHealth ? "healthRun" : "run";
  const ta = isHealth ? "healthQuery" : "query";
  const statusId = isHealth ? "healthStatus" : "status";
  const boxId = isHealth ? "softwareHealth" : "softwareResults";
  const cardSel = isHealth ? ".health-card" : ".software-card";

  setTimeout(() => {
    const $ = (id) => window.document.getElementById(id);
    if (isHealth) $("tab-health").click();
    $(ta).value = "nginx";
    $(runBtn).click();
    // 健康度数据（立即到位）加载完成后会补跑查询，此时应停在「软件数据加载中」
    setTimeout(() => {
      const status = $(statusId).textContent;
      check("竞态：" + pane + " 数据未到位时提示加载中",
        /正在加载软件数据/.test(status), status);
      check("竞态：" + pane + " 未把 nginx 误报为无法识别",
        !/无法识别/.test(status), status);

      setTimeout(() => {
        const cards = $(boxId).querySelectorAll(cardSel);
        check("竞态：" + pane + " 数据到位后自动补渲染", cards.length === 1 &&
          /nginx/.test(cards[0].textContent), cards.length);
        done();
      }, 900);
    }, 150);
  }, 80);
}

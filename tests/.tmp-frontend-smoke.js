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

      /* ---------- 清空回到全量浏览 ---------- */
      $("healthClear").click();
      const all = $("healthResults").querySelectorAll(".health-card");
      check("清空后展示全部已采集组件", all.length === health.components.length,
        { got: all.length, expect: health.components.length });

      console.log(failures.length ? "\nFAILED: " + failures.join(" | ")
        : "\nALL PASSED (" + (loadHealth ? "health loaded" : "") + ")");
      process.exit(failures.length ? 1 : 0);
    }, 30);
  }, 60);
}, 60);

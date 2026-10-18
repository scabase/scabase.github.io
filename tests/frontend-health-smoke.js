/* 临时前端冒烟：健康度默认态 + 查询后分页 + Star/Fork/Watch 展示
 * 运行：NODE_PATH=/Users/block/.workbuddy/binaries/node/workspace/node_modules \
 *       node tests/.tmp-health-smoke.js
 */
"use strict";
var fs = require("fs");
var path = require("path");
var JSDOM = require("jsdom").JSDOM;

var ROOT = path.resolve(__dirname, "..");
/* 去掉真实 script 标签：改为手工 eval，避免 script 未加载让 readyState 停在 loading */
var html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8")
  .replace(/<script src="assets\/app\.js"><\/script>/, "");
var appJs = fs.readFileSync(path.join(ROOT, "assets/app.js"), "utf8");

var COUNT = 45; // > 2 页（每页 20）
var GRADES = ["A", "B", "C", "D"];
var components = [];
for (var i = 0; i < COUNT; i++) {
  components.push({
    purl: "pkg:npm/comp" + i + "@1.0.0",
    display: "comp" + i,
    eco: "npm",
    grade: GRADES[i % 4],
    level: "强",
    score: 90 - (i % 40),
    last_commit_days: i % 30,
    releases_12m: 3,
    maintainers: 5,
    contributors: 20,
    monthly_downloads: 1234567,
    stars: 123456,
    forks: 12345,
    watchers: 1234,
    org_backing: "org",
    sources: ["github", "npm-registry"],
    repo: "org/comp" + i
  });
}
/* 软件维度：25 个软件（> 1 页） */
var SW_COUNT = 25;
var swList = [];
var swComps = [];
for (var s = 0; s < SW_COUNT; s++) {
  swList.push({
    name: "sw" + s, category: "测试类", cves: [], repo: "org/sw" + s,
    aliases: [], collected: true
  });
  swComps.push({
    software: "sw" + s, eco: "软件", display: "sw" + s,
    grade: GRADES[s % 4], level: "强", score: 80 - (s % 30),
    last_commit_days: s, releases_12m: 2, maintainers: 3,
    monthly_downloads: null, stars: 45678, forks: 5678, watchers: 678,
    org_backing: "org", sources: ["github"], repo: "org/sw" + s,
    version: "1.0." + s
  });
}
var swVulnsDoc = { software: swList };
var swSupportDoc = { components: swComps };

var healthDoc = {
  generated_at: "2026-10-18T00:00:00Z",
  component_count: COUNT,
  grade_counts: { A: 12, B: 11, C: 11, D: 11 },
  components: components,
  source_counts: { github: COUNT, "npm-registry": COUNT }
};

var dom = new JSDOM(html, {
  url: "https://scabase.test/",
  pretendToBeVisual: true,
  runScripts: "outside-only"
});
var window = dom.window;
var document = window.document;

function jsonResponse(obj) {
  return Promise.resolve({
    ok: true, status: 200,
    json: function () { return Promise.resolve(obj); },
    text: function () { return Promise.resolve(JSON.stringify(obj)); }
  });
}
window.fetch = function (url) {
  var u = String(url);
  if (u.indexOf("community-support.json") !== -1) return jsonResponse(healthDoc);
  if (u.indexOf("software-support.json") !== -1) return jsonResponse(swSupportDoc);
  if (u.indexOf("software-vulns.json") !== -1) return jsonResponse(swVulnsDoc);
  if (u.indexOf("popular-packages.json") !== -1) return jsonResponse({ lists: [] });
  if (u.indexOf("repo-map.json") !== -1) return jsonResponse({});
  if (u.indexOf("vulns.json") !== -1) return jsonResponse({});
  return Promise.resolve({ ok: false, status: 404, json: function () { return Promise.resolve(null); }, text: function () { return Promise.resolve(""); } });
};

var failures = [];
function check(name, cond, extra) {
  if (cond) { console.log("  ok   " + name); }
  else { failures.push(name + (extra ? " → " + extra : "")); console.log("  FAIL " + name + (extra ? " → " + extra : "")); }
}

// eval 前先让 document 处于可交互状态：app.js 在 readyState != loading 时直接 init()
window.eval(appJs);

function q(sel) { return document.querySelector(sel); }
function qa(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

function tick(n) {
  return new Promise(function (resolve) { setTimeout(resolve, 0); }).then(function () {
    return n > 1 ? tick(n - 1) : null;
  });
}

function waitHealth() {
  return new Promise(function (resolve) {
    var tries = 0;
    (function loop() {
      if (q("#healthKpis").children.length || tries > 60) { resolve(); return; }
      tries++;
      setTimeout(loop, 10);
    })();
  });
}

function signalValue(card, label) {
  var sigs = Array.prototype.slice.call(card.querySelectorAll(".signal"));
  for (var i = 0; i < sigs.length; i++) {
    if (sigs[i].querySelector(".k").textContent === label) return sigs[i].querySelector(".v").textContent;
  }
  return null;
}

function waitReady() {
  return new Promise(function (resolve) {
    if (document.readyState !== "loading") { resolve(); return; }
    // 后注册 → app.js 的 DOMContentLoaded 处理器（含 init）先跑完
    document.addEventListener("DOMContentLoaded", function () { resolve(); });
    setTimeout(resolve, 2000);
  });
}

// 健康度数据是切到该页签时才懒加载的
waitReady().then(function () {
  q("#tab-health").click();
  return waitHealth();
}).then(function () {
  console.log("\n[1] 默认态：不铺开全量列表");
  var host = q("#healthResults");
  check("KPI 已渲染", q("#healthKpis").children.length === 5, q("#healthKpis").children.length + " 张");
  check("显示查询引导", !!q("#healthResults .health-guide"));
  check("未渲染组件卡", qa("#healthResults .health-card").length === 0,
    qa("#healthResults .health-card").length + " 张");
  check("未出现翻页控件", qa("#healthResults .pager").length === 0);
  check("默认态隐藏二次筛选控件",
    q("#healthSearch").hidden && q("#healthSort").hidden && q("#healthGrade").hidden);

  console.log("\n[2] 查询 45 条 → 按页展示");
  var lines = [];
  for (var i = 0; i < COUNT; i++) lines.push("npm|comp" + i + "|1.0.0");
  q("#healthQuery").value = lines.join("\n");
  q("#healthRun").click();

  return tick(3).then(function () {
    var cards = qa("#healthResults .health-card");
    check("第 1 页 20 张卡", cards.length === 20, cards.length + " 张");
    var pager = q("#healthResults .pager");
    check("出现翻页控件", !!pager);
    check("页码信息正确", pager && /第 1 \/ 3 页 · 共 45 条/.test(pager.querySelector(".pager-info").textContent),
      pager ? pager.querySelector(".pager-info").textContent : "无");
    var prev = pager.querySelectorAll(".pager-btn")[0];
    check("第 1 页上一页禁用", prev.disabled === true);
    check("查询后显示二次筛选控件",
      !q("#healthSearch").hidden && !q("#healthSort").hidden && !q("#healthGrade").hidden);

    // 活跃度三件套 + 千分位
    var c0 = cards[0];
    check("卡片含 GitHub Star", signalValue(c0, "GitHub Star") === "123,456", signalValue(c0, "GitHub Star"));
    check("卡片含 GitHub Fork", signalValue(c0, "GitHub Fork") === "12,345", signalValue(c0, "GitHub Fork"));
    check("卡片含 GitHub Watch", signalValue(c0, "GitHub Watch") === "1,234", signalValue(c0, "GitHub Watch"));
    check("月下载量仍缩写", signalValue(c0, "月下载量") === "1.2M", signalValue(c0, "月下载量"));
    check("来源徽章可点击", c0.querySelectorAll(".health-sources a.src-link").length === 2,
      c0.querySelectorAll(".health-sources a.src-link").length + " 个");

    // 翻到第 2 页
    pager.querySelectorAll(".pager-btn")[1].click();
    return tick(2).then(function () {
      var p2 = qa("#healthResults .health-card");
      check("第 2 页 20 张卡", p2.length === 20, p2.length + " 张");
      check("页码更新为 2/3", /第 2 \/ 3 页/.test(q("#healthResults .pager-info").textContent),
        q("#healthResults .pager-info").textContent);
      var first2 = p2[0].querySelector(".name").textContent;
      check("第 2 页内容与第 1 页不同", first2 !== "comp0", first2);

      // 翻到末页
      q("#healthResults .pager").querySelectorAll(".pager-btn")[1].click();
      return tick(2).then(function () {
        var p3 = qa("#healthResults .health-card");
        check("末页 5 张卡", p3.length === 5, p3.length + " 张");
        var next = q("#healthResults .pager").querySelectorAll(".pager-btn")[1];
        check("末页下一页禁用", next.disabled === true);

        // 上一页回退
        q("#healthResults .pager").querySelectorAll(".pager-btn")[0].click();
        return tick(2).then(function () {
          check("回退到第 2 页", /第 2 \/ 3 页/.test(q("#healthResults .pager-info").textContent),
            q("#healthResults .pager-info").textContent);

          console.log("\n[3] 清空 → 回到引导态");
          q("#healthClear").click();
          return tick(2).then(function () {
            check("恢复查询引导", !!q("#healthResults .health-guide"));
            check("清空后无卡片", qa("#healthResults .health-card").length === 0,
              qa("#healthResults .health-card").length + " 张");

            console.log("\n[4] 单条查询结果不出现翻页控件");
            q("#healthQuery").value = "npm|comp7|1.0.0";
            q("#healthRun").click();
            return tick(3).then(function () {
              check("渲染 1 张卡", qa("#healthResults .health-card").length === 1,
                qa("#healthResults .health-card").length + " 张");
              check("无翻页控件", qa("#healthResults .pager").length === 0);

              console.log("\n[5] 软件维度 25 条 → 同样按页展示");
              var swLines = [];
              for (var s = 0; s < SW_COUNT; s++) swLines.push("sw" + s);
              q("#healthQuery").value = swLines.join("\n");
              q("#healthRun").click();
              return tick(3);
            });
          }).then(function () {
            var swBox = q("#softwareHealth");
            check("软件结果框可见", swBox && swBox.hidden === false);
            var swCards = qa("#softwareHealth .health-card");
            check("软件第 1 页 20 张卡", swCards.length === 20, swCards.length + " 张");
            var swPager = q("#softwareHealth .pager");
            check("软件区出现翻页控件", !!swPager);
            check("软件页码信息正确", swPager &&
              /第 1 \/ 2 页 · 共 25 条/.test(swPager.querySelector(".pager-info").textContent),
              swPager ? swPager.querySelector(".pager-info").textContent : "无");
            check("软件卡含 Star/Fork/Watch",
              signalValue(swCards[0], "GitHub Star") === "45,678" &&
              signalValue(swCards[0], "GitHub Fork") === "5,678" &&
              signalValue(swCards[0], "GitHub Watch") === "678",
              signalValue(swCards[0], "GitHub Star"));

            swPager.querySelectorAll(".pager-btn")[1].click();
            return tick(2);
          }).then(function () {
            var p2 = qa("#softwareHealth .health-card");
            check("软件第 2 页 5 张卡", p2.length === 5, p2.length + " 张");
            check("软件末页下一页禁用",
              q("#softwareHealth .pager").querySelectorAll(".pager-btn")[1].disabled === true);
          });
        });
      });
    });
  });
}).then(function () {
  console.log("");
  if (failures.length) {
    console.log("FAILED: " + failures.length);
    failures.forEach(function (f) { console.log(" - " + f); });
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}).catch(function (e) {
  console.error("ERROR", e);
  process.exitCode = 1;
});

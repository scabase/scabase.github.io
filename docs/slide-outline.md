# Slide Outline

## Meta
- Topic: ScaBase 开源软件成分分析（SCA）平台项目宣讲
- Scenario: 面向金融科技 / 行业客户的技术宣讲汇报（正式、结构化、偏方案介绍，约 40 分钟专场）
- Content Source: provided（仓库 readme_zh_cn.md、docs/oss-intake.md、llms.txt、openspec/）
- Research: skip — 项目资料完整，无需联网补充
- Style: 工行红（ICBC Red）— 主色企业正红 #C7000B / 深红 #A0000A，辅色金箔 #C9A063，底色深炭灰 #1A1C20 与米白 #F5F2EC；字体思源黑体体系（Bold/Regular 两档）；装饰母题为「盾形网格 + 数据折线 + 金色细描边」，整体稳重、克制、有金融级质感
- Slide Count: 20
- Generated At: 2026-10-17T23:35:00+08:00

## Source Materials
1. `readme_zh_cn.md` — 项目定位、四生态支持、部署方式、环境变量、包注册表发布、仓库自身依赖面
2. `docs/oss-intake.md` — 开源引入评估体系：双区架构、PURL 事实层、评分模型四维权重、社区支持力度采集源、基线目录 32 条、巡检工单、工具链对接、常用依赖 Top 清单、机器可读数据
3. `llms.txt` — 站点功能与数据集说明（漏洞查询 / 支持力度 / Top 清单）
4. `.workbuddy/memory/MEMORY.md` — 项目长期约定（DEPINFO / sreops 命名、零第三方依赖、页面布局约定）

## Slide-by-Slide Outline
1. **Slide 1 — Cover** — ScaBase：开源软件成分分析平台，让每一次开源引入都有据可依 | L02 | Image: yes | Chart: no
2. **Slide 2 — 议程** — 四段：形势、能力、架构、落地 | L19 | no | no
3. **Slide 3 — 形势** — 软件供应链成为第一攻击面：4 生态 / 2 数据源 / 每日更新 | L11 三 KPI | no | no
4. **Slide 4 — 三大现实问题** — 查不全 / 判不准 / 落不地 | L07 三支柱 | no | no
5. **Slide 5 — 方案对比** — ScaBase vs 传统商业 SCA：离线可用、可解释、可对接 | L08 双栏对比 | no | no
6. **Slide 6 — Section Break 一** — 第一部分 · 平台能力 | L03 | no | no
7. **Slide 7 — 定位** — 以 PURL 为主键，把漏洞、健康度、许可、资产挂到同一事实层 | L04 | no | no
8. **Slide 8 — 能力一** — 多生态漏洞查询：Maven / npm / PyPI / Go，OSV + NVD 双源，CVE 为主标识 | L16 图标行 | no | no
9. **Slide 9 — 能力二** — 开源引入评估：从原生依赖文件直接归一为 PURL，无需先产 SBOM | L05 概念+视觉 | no | no
10. **Slide 10 — 评分模型详解** — 四维权重 V35 / M25 / L20 / B20 + 四类硬阻断 | L17 | no | Chart: yes（权重条）
11. **Slide 11 — 能力三** — 社区支持力度：0-100 分 A/B/C/D，缺失信号「未知即风险」 | L17 | no | Chart: yes（等级分布柱图）
12. **Slide 12 — 数据来源覆盖** — GitHub / deps.dev / npm registry / PyPI / repo-map 五源归因 | L16 图标行 | no | no
13. **Slide 13 — 能力四** — 安全配置基线 32 条 + AI 脚本生成（三目标 + 90% 准确率回归） | L13 流程 | no | no
14. **Slide 14 — 能力五** — 漏洞影响范围巡检：按应用聚合、工单定级、增量闭环 | L17 | no | Chart: yes（整改期限条）
15. **Slide 15 — 案例演示** — fastjson 1.2.24 一次门禁的完整链路与结论 | L08 对比 | no | no
16. **Slide 16 — Section Break 二** — 第二部分 · 架构与工程自律 | L03 | no | no
17. **Slide 17 — 双区离线摆渡** — Zone A 采集签名 → 单向摆渡 → Zone B 验签导入，内网零公网请求 | L13 流程 | no | no
18. **Slide 18 — 部署与分发** — GitHub Pages / Docker 内网 / GitHub Packages 三通道 | L15 四宫格 | no | no
19. **Slide 19 — 工程自律与接入三步** — 零第三方依赖、仓库自扫描、机器可读数据；scan → gate → patrol | L19 列表 | no | no
20. **Slide 20 — Closing** — 让开源引入这件事，从凭经验变成看数据 | L20 | Image: yes | Chart: no

## Visual Rhythm Notes
- Chart-bearing slides at positions: 10, 11, 14
- Dark accent slides at positions: 1（封面深红）、6、16（章节页深炭灰）、20（结语深红）
- 幻灯片在大屏 / 投影下观看，小字不可读：所有文本需充分放大并填满容器，不留空洞浮字
- 画面需有层次与装饰，不能像把文字贴在矩形上；SVG 图表比纯文字数字有效得多
- 金色 #C9A063 仅用于强调（数字、分割线、章节编号），不铺大面积

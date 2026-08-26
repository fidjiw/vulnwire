# 漏讯 VulnWire

实时漏洞 / POC 情报站。零服务器、零成本:静态单页 + GitHub Actions 每小时采集公开情报源,数据以 JSON 提交进仓库,由 GitHub Pages 直接分发。

**在线访问:<https://fidjiw.github.io/vulnwire/>**

## 数据流水线

```
GitHub Actions(每小时 :15,scripts/collect.py)
  ├─ NVD API 2.0     近 72 小时新披露 CVE(描述 / CVSS / CWE / CPE / 参考链接)
  ├─ GitHub Search   近 7 天有推送的 CVE-* POC 仓库
  ├─ CISA KEV        在野利用清单 → exploited 标记
  ├─ OSV api.osv.dev NVD 未收录 CPE 时补全影响版本范围 + 生态标签
  ├─ AI 中文摘要      GLM 生成(标题+摘要),失败兜底 DeepL 机翻
  └─ RSS             根目录 rss.xml(≤30 条)
        ↓
  data/data.json(页面加载)+ data/history.json(搜索档案,≤3000 条)+ rss.xml
        ↓
  GitHub Pages(前端每 5 分钟静默自动刷新)
```

各数据源独立重试、独立降级:任一源失败不影响其余;全部失败时保留旧数据并向订阅渠道推送「采集失败」告警。

## 前端功能

- **实时情报流**:近 72 小时新 CVE,严重度 / POC / 在野利用筛选,页面停留期间每 5 分钟静默同步新数据(新增条目动画高亮,不打断搜索)
- **POC 仓库库表**:GitHub 公开 POC 仓库,语言 / 类型 / star / KEV 状态筛选
- **详情弹窗**:点击任意漏洞或 POC 行 — NVD 原文描述、影响版本(NVD CPE + OSV 补全)、处置建议(规则生成,非厂商官方)、公开 POC 仓库、相关参考(带「补丁 / 厂商公告 / Exploit」官方标记)
- **历史搜索**:输入关键词自动检索历史档案(≈3000 条),覆盖远超 72 小时窗口
- **AI 中文摘要**:GLM 生成(标注「AI 生成」),DeepL 兜底(如实标注「DeepL 机翻」)
- **数据滞留告警**:数据超 3 小时未更新,页面顶部显示黄色提示
- **订阅推送**:新增高危 / 在野利用漏洞 → Telegram Bot + 飞书 webhook
- **深色 / 浅色主题**,站点更新时弹「本次更新内容」公告
- **RSS 订阅**:<https://fidjiw.github.io/vulnwire/rss.xml>

## 仓库结构

```
vulnwire-demo.html     前端单页(部署时 cp 为 index.html)
scripts/collect.py     采集脚本(Python 3 标准库,无第三方依赖)
scripts/test_urls.py   Base URL 解析单测(8 例)
.github/workflows/collect.yml  每小时定时采集
data/data.json         当前情报(采集产物)
data/history.json      历史档案(采集产物)
rss.xml                RSS 输出(采集产物)
```

## 配置(Secrets / Variables,全部可选)

不配置任何密钥时站点照常运行(中文摘要 / 推送功能处于停用状态,页面如实标注)。

| 名称 | 类型 | 作用 |
|---|---|---|
| `GLM_API_KEY` | Secret | GLM 中文摘要([智谱开放平台](https://open.bigmodel.cn/)) |
| `GLM_BASE_URL` | Variable | GLM 端点覆盖,支持任意 OpenAI 兼容中转(默认官方地址) |
| `GLM_MODEL` | Variable | 摘要模型,默认 `glm-4-flash` |
| `DEEPL_KEY` | Secret | DeepL 翻译兜底(free 版 key 以 `:fx` 结尾) |
| `DEEPL_BASE_URL` | Variable | DeepL 端点覆盖(自建代理) |
| `TG_BOT_TOKEN` + `TG_CHAT_ID` | Secret | Telegram Bot 推送 |
| `FEISHU_WEBHOOK` | Secret | 飞书机器人 webhook 推送 |

`GITHUB_TOKEN` 由 Actions 内置,无需配置。

## 本地运行

```bash
python3 scripts/collect.py          # 采集 → data/*.json + rss.xml
python3 scripts/test_urls.py        # Base URL 解析单测
python3 -m http.server 8931         # 本地预览(直接 file:// 打开无法读取数据)
```

## 部署

`main` 分支即线上:采集 workflow 每小时自动提交数据;功能改动时 `cp vulnwire-demo.html index.html` 后提交。改前端时记得同步更新 `SITE_VERSION` 与 `CHANGELOG`(回访用户会收到更新公告)。

## 诚实性约定

- 无数据 / 加载失败如实展示,不回退演示数据
- 「处置建议」为规则模板生成,标注「非厂商官方」
- AI 摘要区分「AI 生成」与「DeepL 机翻」
- 未配置密钥的功能标注「配置后生效」,不假装在工作

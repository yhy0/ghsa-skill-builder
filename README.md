# GHSA Skill Builder

> 让 Claude 自动将 GitHub 公开漏洞数据库和 HackerOne Bug Bounty 报告转化为代码审计/渗透测试专用的结构化安全技能（Skills）

## 起因

我前段时间做了一个叫[纯钧（ChunJun）](https://github.com/yhy0/ChunJun)的 AI 代码审计系统。系统架构上做了不少工作——预扫描、CodeQL、Agent 多阶段验证、对抗反思——但审计效果始终不够理想。

反思了一下，猜测一个可能的原因：**我给 Agent 的只是通用的代码审计思路，它可能还需要一份更具体的漏洞模式知识作为技能。**

比如 SQL 注入，Agent 能依赖的大概就是通用认知——「`cursor.execute()` 使用 f-string 拼接用户输入」。但翻一翻 GitHub Advisory Database 就会发现，真实世界中开发者踩的坑远比这复杂得多：

- asyncmy 通过 dict keys 注入——库只转义 value 不转义 key（[CVE-2025-65896](https://github.com/advisories/GHSA-qhqw-rrw9-25rm)）
- ormar 通过 ORM 聚合函数 `min()`/`max()` 注入——开发者以为 ORM 就是安全的（[CVE-2026-26198](https://github.com/advisories/GHSA-xxh2-68g9-8jqr)）
- LLM 框架直接拼接用户 prompt 进 SQL——AI 时代的新攻击面（[CVE-2024-12909](https://github.com/advisories/GHSA-x48g-hm9c-ww42)）

这些是**开发者真实会犯的错误**，也是**安全研究人员发现的巧妙绕过思路**。它们被记录在 GitHub Advisory Database 和 HackerOne Hacktivity 里，大部分都包含了根因分析、修复 commit、CWE 分类等完整信息。

光 Python 生态，CRITICAL + HIGH 级别就有 **3,777 条**，其中 CVSS >= 8.0 的有 **946 条**。HackerOne 公开报告中 critical/high 级别有数千条。

让人一条条去看、分析、提炼？不现实。

所以想法很简单：**让 Claude 来干这件事——自动拉取、分析、结构化，生成 Agent 能用的安全技能。**

## 这个 repo 包含什么

本 repo 是一个 **Claude Code Marketplace**，包含两个可独立安装的 plugin：

| Plugin | 说明 | 适用人群 |
|--------|------|----------|
| **vuln-skills** | 26 个安全漏洞审计/渗透测试 Skills | 直接用来做代码审计或渗透测试的人 |
| **ghsa-skill-builder** | Skill 生成器（从 GHSA/H1 拉取数据生成 skills） | 想自己拉数据、定制生成 skills 的人 |

### 26 个 Skills 覆盖范围

**Python 代码审计（6 个）**：injection、path-traversal、auth-bypass、deserialization、ssrf、xss

**Go 代码审计（7 个）**：auth-bypass、path-traversal、injection、dos、info-disclosure、crypto-tls、ssrf-requestforgery

**Web 渗透测试（13 个，基于 HackerOne 真实报告）**：sqli、xss、ssrf、idor、access-control、path-traversal、command-injection、auth-bypass、info-disclosure、memory-corruption、request-forgery、business-logic、deserialization-xxe

## 安装

### 方式 1：安装审计 Skills（推荐大多数用户）

```bash
/plugin install vuln-skills@yhy0/ghsa-skill-builder
```

安装后 Claude 会自动获得 26 个安全审计 Skills，在代码审计或渗透测试时自动触发。

### 方式 2：安装 Skill 生成器

```bash
/plugin install ghsa-skill-builder@yhy0/ghsa-skill-builder
```

安装后可以让 Claude 从 GHSA/HackerOne 拉取最新漏洞数据，自动生成或更新 Skills。

### 方式 3：两个都装

```bash
/plugin install vuln-skills@yhy0/ghsa-skill-builder
/plugin install ghsa-skill-builder@yhy0/ghsa-skill-builder
```

### 前置条件

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- 安装生成器还需要：[GitHub CLI](https://cli.github.com/)（`gh`，已认证）、Python 3.9+

## 生成的 Skill 长什么样

每个 Skill 分两层，渐进式加载：

**第一层：Detection Strategy（检测策略）**——Agent 审计时首先加载，定义这类漏洞的通用检测模型。

```markdown
## Detection Strategy

Sources（用户输入入口）：
- request.args, request.json, request.form
- tool_call.arguments（MCP/Agent 场景）
- 配置文件中用户可控的字段

Sinks（危险函数）：
- cursor.execute(), engine.execute()
- Model.objects.extra(where=...), Model.objects.raw()
- asyncmy/PyMySQL 的 dict 参数传递

Sanitization（安全屏障）：
- 参数化查询 (cursor.execute(sql, params))
- ORM 标准查询方法（filter/exclude/get）

检测路径：
1. 搜索 sink 调用
2. 回溯数据流，检查参数是否来自 source
3. 验证路径上是否存在有效 sanitization
4. 无 sanitization → 标记为候选漏洞
```

**第二层：Real-World Cases（真实案例）**——Agent 需要深入验证时按需加载。每个 Case 从真实 GHSA/CVE 或 HackerOne 报告中提炼，包含完整的攻击链分析：

```markdown
### Case N: [package] — [漏洞模式] (CVE-xxxx-yyyy, CVSS x.x)

Root Cause: [一句话根因]

Source → Sink 路径:
- Source: request.form["package"]
- Sink: os.path.join() + open()
- Sanitization Gap: replace() 不处理 ".." 序列

Vulnerable Code Pattern (affected-file.py):
  # 5-15 行真实漏洞代码

Attack Path:
  1. 攻击者通过 [source] 注入 [payload]
  2. 数据经过 [中间处理]
  3. 到达 [sink]，触发 [危害]

Why Standard Scanners Miss It:
- CodeQL: [具体原因]
- Bandit: [具体原因]
```

这种两层结构让 Agent 审计时**先用轻量的检测策略快速扫一遍，发现可疑点再加载具体案例深入确认**——而不是把几千条漏洞全塞进上下文。

## 使用

### 直接审计（安装 vuln-skills 后）

Skills 会根据上下文自动触发，也可以用 slash command 手动调用：

```
审计这段代码有没有注入漏洞
检查这个 Go 项目的认证绕过风险
对这个 Web 应用做一次 SSRF 渗透测试
```

### 生成/更新 Skills（安装 ghsa-skill-builder 后）

```
拉取最近三年 Python 高危漏洞，生成代码审计 skills

拉取 Go 生态 CVSS >= 9 的漏洞，生成审计 skills

从 HackerOne 拉取 SSRF 报告做渗透测试 skill

帮我检查一下漏洞 skills 是否需要更新

分析 GHSA-qhqw-rrw9-25rm 并加到对应的 skill 中
```

生成器支持两个数据源：

| 数据源 | 生成的 Skill 类型 | 特点 |
|--------|-------------------|------|
| **GHSA**（GitHub Advisory Database） | `vuln-patterns-*`, `go-vuln-*` 代码审计 | 有 patch diff，可提取精确的漏洞代码模式 |
| **HackerOne Hacktivity** | `pentest-*` 渗透测试 | 有攻击步骤和 PoC，侧重实战渗透手法 |

脚本也可以独立使用：

```bash
# GHSA: 全量拉取 Python 生态索引
python3 scripts/fetch_ghsa.py PIP --since 3y

# GHSA: 拉取注入类漏洞的完整详情
python3 scripts/fetch_details.py data/pip.json --cwe "77|78|89|94"

# GHSA: 增量检查
python3 scripts/fetch_ghsa.py PIP --diff

# HackerOne: 拉取公开 Hacktivity 报告
python3 scripts/fetch_h1_hacktivity.py --severity critical

# HackerOne: 按 CWE 过滤并补充 NVD 描述
python3 scripts/fetch_h1_details.py data/h1_hacktivity.json --cwe "79|89|94"

# 支持 7 种生态: PIP | GO | NPM | MAVEN | NUGET | RUBYGEMS | RUST
```

## 项目结构

```
ghsa-skill-builder/                     # Marketplace repo
├── .claude-plugin/
│   └── marketplace.json               # 定义两个 plugin
├── vuln-skills/                       # Plugin 1: 26 个安全审计 Skills
│   ├── .claude-plugin/
│   │   └── plugin.json
│   └── skills/
│       ├── vuln-patterns-injection/   # Python 注入审计
│       ├── go-vuln-auth-bypass/       # Go 认证绕过审计
│       ├── pentest-sqli/              # SQL 注入渗透测试
│       └── ... (共 26 个)
├── ghsa-skill-builder/                # Plugin 2: Skill 生成器
│   ├── .claude-plugin/
│   │   └── plugin.json
│   └── skills/
│       └── ghsa-skill-builder/
│           ├── SKILL.md               # 生成器完整工作手册
│           └── references/
├── scripts/                           # 数据拉取和测试脚本
│   ├── fetch_ghsa.py                  # GHSA 全量拉取（GraphQL）
│   ├── fetch_details.py               # GHSA 详情拉取（REST API）
│   ├── fetch_h1_hacktivity.py         # HackerOne Hacktivity 拉取（GraphQL）
│   ├── fetch_h1_details.py            # H1 详情 + NVD 补充
│   ├── check_existing_skills.py       # Skills 覆盖状态校验
│   ├── test_vuln_patterns_skills.py   # Python 审计 skills 测试
│   ├── test_go_vuln_skills.py         # Go 审计 skills 测试
│   └── test_pentest_skills.py         # 渗透测试 skills 测试
├── references/                        # 生成规范
│   ├── skill-structure.md
│   └── case-template.md
└── data/                              # 漏洞数据缓存
```

## 数据洞察

拉取数据后的一些发现：

**Python 生态 946 条高危漏洞 CWE Top 5：** 代码注入（CWE-94）107 条、反序列化（CWE-502）86 条、路径遍历（CWE-22）81 条、输入验证（CWE-20）59 条、命令注入（CWE-78）46 条。

**AI/LLM 框架漏洞正在爆发。** langchain、vllm、smolagents、langflow、bentoml 等 AI 框架贡献了大量 CVSS 10.0 的漏洞——MCP 工具命令注入（`terminal-controller`，CVSS 10.0）、Agent 沙箱逃逸（`smolagents`，CVSS 9.9）、AI 框架反序列化（`vllm`，CVSS 10.0）。

**HackerOne 数据补充了"实战视角"。** GHSA 侧重代码层面的漏洞模式，H1 报告则包含了更完整的攻击链——如何发现、如何利用、实际影响。两个数据源互补，让生成的 Skills 既有代码级精度，又有实战渗透深度。

## 局限性

- **依赖 Claude 的分析质量** — 生成的 Skill 质量取决于 Claude 对 patch diff 的理解能力，建议人工抽查验证
- **Skill 需要持续更新** — 新漏洞不断出现，建议定期执行增量检查
- **HackerOne 数据受限** — H1 公开报告仅包含 AI 摘要和部分 CVE 信息，无法获取报告全文（需登录）

> 以及最主要的当前生成的各种 Skills 真实效果未知，需要测试

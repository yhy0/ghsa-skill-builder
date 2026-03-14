---
name: ghsa-skill-builder
description: "Use when building or updating vulnerability pattern Skills from multiple sources: GitHub Security Advisories (GHSA), HackerOne Hacktivity, or NVD. Triggers on keywords: GHSA, CVE, vulnerability skill, vuln pattern, update skills, security advisory, HackerOne, H1, hacktivity, pentest skill, bug bounty, check for updates."
---

# Vulnerability Pattern Skill Builder

从多个数据源拉取高危漏洞，分析模式，自动生成/更新审计 Skills：
- **GHSA**（GitHub Advisory Database）→ 按语言生态分类的代码审计 skills（`vuln-patterns-*`, `go-vuln-*`）
- **HackerOne Hacktivity**（公开 Bug Bounty 报告）→ 按漏洞类型分类的渗透测试 skills（`pentest-*`）

## 前置检查

开始工作前，检查以下依赖：

1. **GitHub 认证**: 脚本会自动检查，未认证会提示
2. **writing-skills**: 生成 Skill 时需要遵循质量规范。检查 superpowers 插件是否已安装：

```bash
ls ~/.claude/plugins/cache/*/superpowers/*/skills/writing-skills/SKILL.md 2>/dev/null
```

如果不存在，提示用户安装：
> superpowers 插件未安装。建议先执行 `/plugin install superpowers@superpowers-marketplace` 安装，其中的 writing-skills 技能可确保生成的 Skills 符合质量规范。也可以跳过，但生成的 Skill 质量可能不稳定。

如果已安装，在 Step 3 生成 Skill 文件时，同时参考 writing-skills 的规范（frontmatter 格式、Progressive Disclosure、CSO 关键词优化、目录结构）。

## 使用场景

| 用户说 | 操作模式 |
|--------|----------|
| "拉取最近三年 Python 高危漏洞，生成审计 skills" | **模式 A：GHSA 全量构建** |
| "帮我更新一下漏洞 skills" / "看看有没有新漏洞" | **模式 B：增量检查** |
| "分析 GHSA-xxxx-yyyy-zzzz 加到 skills 里" | **模式 C：单条分析** |
| "拉取 Go 生态的注入类漏洞做成 skill" | **模式 A：按条件构建** |
| "从 HackerOne 拉取 SSRF 报告做 skill" | **模式 D：H1 Hacktivity 构建** |
| "用 H1 bug bounty 报告生成渗透测试 skills" | **模式 D：H1 Hacktivity 构建** |
| "更新 pentest skills" / "补充 H1 数据" | **模式 D：H1 增量更新** |

---

## 模式 A：全量构建

### Step 1: 拉取数据

**阶段 1 — 批量拉取索引**（快速，几分钟）：

```bash
python3 scripts/fetch_ghsa.py PIP --since 3y
python3 scripts/fetch_ghsa.py GO --since 3y
python3 scripts/fetch_ghsa.py NPM --since 3y
```

保存到 `data/{ecosystem}.json`（索引级：GHSA ID、CVSS、CWE、summary）。参数：`--min-cvss`(默认8), `--severity`(默认CRITICAL,HIGH), `--since`(如3y/1y/6m/30d)。

**阶段 2 — 按 CWE 拉取完整详情**（逐条 REST API）：

```bash
# 注入类全量详情
python3 scripts/fetch_details.py data/pip.json --cwe "77|78|89|94"

# 路径遍历类
python3 scripts/fetch_details.py data/pip.json --cwe "22|23|73"

# 反序列化类
python3 scripts/fetch_details.py data/pip.json --cwe "502"

# 认证绕过类
python3 scripts/fetch_details.py data/pip.json --cwe "287|288|306"

# 不过滤 CWE，全量拉取所有详情
python3 scripts/fetch_details.py data/pip.json

# 只想快速测试可以加 --top 限制
python3 scripts/fetch_details.py data/pip.json --cwe "77|78|89|94" --top 10
```

保存到 `data/{ecosystem}_details_{cwe}.json`（含完整 description、patch commit URL）。

### Step 2: 分析候选

读取 `data/*_details_*.json`，对每个候选：

1. 读 `description` 提取漏洞根因和攻击路径
2. 如果有 `patch_urls`，用 `gh api repos/{owner}/{repo}/commits/{sha} -H "Accept: application/vnd.github.diff"` 获取 diff
3. 从 description + diff 中提取结构化信息：
   - **Source**: 用户输入的具体入口
   - **Sink**: 触发危害的具体函数
   - **Sanitization Gap**: 为什么 source→sink 路径上没有有效防护
   - **漏洞代码**: 关键的危险代码模式
   - **为什么扫描器会漏掉**: CodeQL/Bandit/Gosec 漏检的具体原因
   - **检测方法**: 如何在未知代码中发现此类漏洞

**筛选标准：**
1. 根因模式独特、常规扫描器会漏掉的优先
2. description 中有具体代码/PoC 的优先
3. AI/LLM/MCP/Agent 相关漏洞优先
4. 同一根因模式只保留最典型的 1-2 个代表

**跳过：** 纯 DoS (CWE-400)、内存损坏无代码模式、description 为空或过短。

**CWE 到 Skill 映射：**

| CWE | Target Skill |
|---|---|
| CWE-77, 78, 89, 94 | `vuln-patterns-injection` |
| CWE-22, 23, 73 | `vuln-patterns-path-traversal` |
| CWE-287, 288, 306 | `vuln-patterns-auth-bypass` |
| CWE-502 | `vuln-patterns-deserialization` |
| CWE-918 | `vuln-patterns-ssrf` |
| CWE-79, 116 | `vuln-patterns-xss` |
| CWE-327, 328, 330 | `vuln-patterns-crypto` |

### Step 3: 生成 Skill 文件

对每个 CWE 分组生成 `vuln-skills/skills/vuln-patterns-{category}/SKILL.md` + `vuln-skills/skills/vuln-patterns-{category}/references/cases.md`。

**生成顺序——先写组级策略，再填 Case：**

**第一步：Detection Strategy（组级通用检测模型）**

从该组所有候选中归纳通用的 Sources、Sinks、Sanitization 列表和检测路径。这是 Skill 的核心——Agent 审计时首先依据此策略定位候选漏洞点。

**第二步：3-8 个 Case 写入 references/cases.md**

每个 Case 代表一种**独特的漏洞变体模式**。选择标准：
- 每个 Case 的 source→sink 路径应不同于其他 Case
- 优先选择通用规则难以覆盖的边缘情况
- 同根因模式的多个 CVE 用 `**Similar Vulnerabilities**` 聚合

**第三步：Detection Checklist + False Positive Exclusion Guide**

从 Cases 中提炼可操作的检查项和误报排除条件。

遵循 [references/skill-structure.md](references/skill-structure.md) 和 [references/case-template.md](references/case-template.md)。

**约束：**
- SKILL.md 放检测策略 + Checklist + 误报指南（核心内容）
- Cases 拆到 references/cases.md（按需加载）
- 每个 Case 聚焦于**如何发现**此类漏洞，而非如何修复
- 每个 Case 必须包含 Source → Sink 路径 和 "Why Standard Scanners Miss It"
- Detection Strategy 不可省略

### Step 4: 校验

```bash
# GHSA ID 去重 + Case 数量检查
python3 scripts/check_existing_skills.py --skills-dir .

# vuln-patterns-* skills 静态测试（frontmatter、结构）
python3 scripts/test_vuln_patterns_skills.py

# go-vuln-* skills 静态测试 + 场景定义
python3 scripts/test_go_vuln_skills.py
```

详见下方「测试脚本说明」章节。

---

## 模式 B：增量检查

```bash
# 对比已有数据，检查新增漏洞
python3 scripts/fetch_ghsa.py PIP --diff
python3 scripts/fetch_ghsa.py GO --diff
```

如果有新增：
1. 对新增漏洞按 CWE 分类，拉取详情：`python3 scripts/fetch_details.py data/pip.json --cwe "..." --top 10`
2. 判断是否值得加入现有 Skill
3. 按 Step 2-3 分析并更新
4. 全量拉取更新本地缓存：`python3 scripts/fetch_ghsa.py PIP`

---

## 模式 C：单条分析

```bash
gh api /advisories/{GHSA_ID} --jq '.'
```

分析后按 CWE 归入对应 Skill，按 Step 2-3 处理。

---

## 补充：覆盖未发布到包管理器的项目

```bash
gh api repos/{owner}/{repo}/security-advisories \
  --jq '.[] | "\(.ghsa_id) | \(.severity) | \(.cvss.score) | \(.summary)"'
```

---

## 模式 D：HackerOne Hacktivity 构建

从 HackerOne 公开的 Bug Bounty 报告中提取漏洞模式，生成渗透测试 Skills（`pentest-*`）。

### Step 1: 拉取 Hacktivity 索引

```bash
# 拉取全部 critical/high 公开报告（默认最近 3 年，最多 3000 条）
python3 scripts/fetch_h1_hacktivity.py

# 按严重度过滤
python3 scripts/fetch_h1_hacktivity.py --severity critical

# 按 CWE/漏洞类型关键词过滤
python3 scripts/fetch_h1_hacktivity.py --cwe "SQL Injection"
python3 scripts/fetch_h1_hacktivity.py --cwe "SSRF"

# 按时间范围
python3 scripts/fetch_h1_hacktivity.py --since 1y

# 组合过滤
python3 scripts/fetch_h1_hacktivity.py --severity critical --cwe "XSS" --max 200
```

保存到 `data/h1_hacktivity.json`（索引级：标题、CWE、严重度、CVE ID、bounty、报告 URL）。无需认证，使用 HackerOne 公开 GraphQL API。

### Step 2: 补充报告详情

```bash
# 按 CWE 过滤并从 NVD 获取 CVE 描述
python3 scripts/fetch_h1_details.py data/h1_hacktivity.json --cwe "79|89|94"

# 只取前 N 条（按 bounty 降序）
python3 scripts/fetch_h1_details.py data/h1_hacktivity.json --top 30

# 可选：启用 Playwright 抓取报告全文（需要 pip install playwright）
python3 scripts/fetch_h1_details.py data/h1_hacktivity.json --cwe "918" --scrape
```

保存到 `data/h1_hacktivity_details_{cwe}.json`。有 CVE ID 的报告会从 NVD 补充漏洞描述和参考链接。

### Step 3: 按分类拆分

将详情数据按漏洞类型归入分类文件：

```bash
ls data/h1_by_category/
# access-control.json  auth-bypass.json  business-logic.json
# command-injection.json  deserialization-xxe.json  idor.json
# info-disclosure.json  memory-corruption.json  path-traversal.json
# request-forgery.json  sqli.json  ssrf.json  xss.json
```

**H1 分类到 Skill 映射：**

| H1 分类文件 | Target Skill |
|---|---|
| `sqli.json` | `pentest-sqli` |
| `xss.json` | `pentest-xss` |
| `ssrf.json` | `pentest-ssrf` |
| `command-injection.json` | `pentest-command-injection` |
| `path-traversal.json` | `pentest-path-traversal` |
| `auth-bypass.json` | `pentest-auth-bypass` |
| `idor.json` | `pentest-idor` |
| `info-disclosure.json` | `pentest-info-disclosure` |
| `access-control.json` | `pentest-access-control` |
| `business-logic.json` | `pentest-business-logic` |
| `deserialization-xxe.json` | `pentest-deserialization-xxe` |
| `request-forgery.json` | `pentest-request-forgery` |
| `memory-corruption.json` | `pentest-memory-corruption` |

### Step 4: 分析并生成 Skill

对每个分类的数据，按模式 A 的 Step 2-3 相同流程处理：
1. 从 `hacktivity_summary` + `nvd_description` 提取漏洞根因和攻击路径
2. 归纳 Detection Strategy（Sources → Sinks → Sanitization）
3. 写入 `vuln-skills/skills/pentest-{category}/SKILL.md` + `references/cases.md`

**H1 数据特点（与 GHSA 的区别）：**
- H1 报告通常包含更详细的攻击步骤和 PoC
- `hacktivity_summary` 是 AI 生成的摘要，可能不完整，需结合 NVD 描述
- Bounty 金额可用于评估漏洞严重程度和影响力
- 部分报告无 CVE ID，仅有 H1 报告链接

### Step 5: 校验

```bash
python3 scripts/test_pentest_skills.py
```

详见下方「测试脚本说明」章节。

---

## 测试脚本说明

生成 Skill 后需要运行测试确保质量。测试分两层：
- **静态测试**（`python3` 直接运行）：frontmatter 合规、章节结构完整性
- **子代理场景测试**（通过 Agent 工具执行）：Retrieval / Application / Gap 真实场景验证

### 三套测试脚本

| 脚本 | 测试对象 | 静态测试 | 场景测试 |
|------|---------|---------|---------|
| `scripts/test_vuln_patterns_skills.py` | `vuln-skills/skills/vuln-patterns-*/SKILL.md`（6 个 Python 审计 skills） | frontmatter + 结构 | 18 个子代理场景定义 |
| `scripts/test_go_vuln_skills.py` | `vuln-skills/skills/go-vuln-*/SKILL.md`（7 个 Go 审计 skills） | frontmatter + 结构 | 21 个子代理场景定义 |
| `scripts/test_pentest_skills.py` | `vuln-skills/skills/pentest-*/SKILL.md`（13 个渗透测试 skills） | frontmatter + 结构 | 39 个子代理场景定义 |

### 用法

```bash
# 运行静态测试（全部可直接执行）
python3 scripts/test_vuln_patterns_skills.py
python3 scripts/test_go_vuln_skills.py
python3 scripts/test_pentest_skills.py

# 查看 go-vuln 子代理场景定义（人类可读）
python3 scripts/test_go_vuln_skills.py --scenes

# 导出场景定义为 JSON（供程序消费）
python3 scripts/test_go_vuln_skills.py --json-scenes
```

### 子代理场景测试执行方式（go-vuln）

`test_go_vuln_skills.py` 的 `SCENARIOS` 列表定义了 21 个场景（每 skill 3 个：retrieval + application + gap）。每个场景包含：
- `skill`: 对应的 skill 名称
- `type`: 测试类型（retrieval / application / gap）
- `scenario`: 给子代理的场景描述（含 Go 代码片段）
- `expected`: 子代理输出应包含的关键点列表

执行方式：在主对话中读取 skill 内容 + 场景定义，通过 Agent 工具启动子代理，将 skill 内容注入 prompt，让子代理产出审计分析，然后评估输出是否满足 `expected` 中的各期望点。

### 静态测试检查项

所有三套脚本的静态测试均检查：
- **Compliance**: frontmatter 存在、大小 ≤1024B、仅 name + description 字段、name 格式合法、description 以 "Use when" 开头且 ≤500 字符
- **Structure**: Detection Strategy / Detection Checklist / False Positive 章节存在、Sources/Sinks/Sanitization 模型、grep 代码块、checklist 条目 ≥5、cases.md 存在且 ≥5 个 case

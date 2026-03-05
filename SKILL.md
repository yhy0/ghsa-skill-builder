---
name: ghsa-skill-builder
description: Build and update ChunJun vulnerability pattern Skills from GitHub Security Advisories (GHSA). This skill should be used when asked to update vuln-pattern skills, fetch latest CVEs for Python/Go/TS, analyze a specific GHSA/CVE and merge into existing skills, or periodically refresh the vulnerability knowledge base. Triggers on keywords like GHSA, CVE, vulnerability skill, vuln pattern, update skills, security advisory, check for updates.
---

# GHSA Vulnerability Pattern Skill Builder

从 GitHub Advisory Database 拉取高危漏洞，分析模式，自动生成/更新 `vuln-patterns-*/SKILL.md`。

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
| "拉取最近三年 Python 高危漏洞，生成审计 skills" | **全量构建** |
| "帮我更新一下漏洞 skills" / "看看有没有新漏洞" | **增量检查** |
| "分析 GHSA-xxxx-yyyy-zzzz 加到 skills 里" | **单条分析** |
| "拉取 Go 生态的注入类漏洞做成 skill" | **按条件构建** |

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

对每个 CWE 分组生成 `vuln-patterns-{category}/SKILL.md` + `vuln-patterns-{category}/references/cases.md`。

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
python3 scripts/check_existing_skills.py --skills-dir .
```

确认：GHSA ID 无跨文件重复、每个文件 3-8 个 Case。

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

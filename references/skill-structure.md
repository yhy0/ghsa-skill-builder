# Vulnerability Pattern Skill Structure Specification

## Directory Naming

`vuln-patterns-{category}/SKILL.md`

category values: `injection`, `path-traversal`, `auth-bypass`, `ssrf`, `xss`, `crypto`, `deserialization`

## CWE to Directory Mapping

| CWE | Directory | Description |
|---|---|---|
| CWE-77, 78, 89, 94 | vuln-patterns-injection | Command/SQL/Code injection |
| CWE-22, 23, 73 | vuln-patterns-path-traversal | Path traversal, file inclusion |
| CWE-287, 288, 306 | vuln-patterns-auth-bypass | Auth bypass, missing auth |
| CWE-502 | vuln-patterns-deserialization | Unsafe deserialization |
| CWE-918 | vuln-patterns-ssrf | Server-side request forgery |
| CWE-79, 116 | vuln-patterns-xss | Cross-site scripting |
| CWE-327, 328, 330 | vuln-patterns-crypto | Weak crypto, insecure random |

## SKILL.md Structure

采用渐进式披露（Progressive Disclosure）：SKILL.md 放核心检测策略，Cases 拆到 references/cases.md。

```markdown
---
name: vuln-patterns-{category}
description: [comprehensive description + trigger conditions]
---

# [Category] Vulnerability Patterns (CWE-xxx/yyy)

[一句话：什么情况下 Agent 应加载此 Skill]

## Detection Strategy

通用检测模型，适用于此类漏洞的所有变体。

**Sources（用户输入入口）：**
- [列出此类漏洞常见的 source，如 request.args, request.json, os.environ]

**Sinks（危险函数/操作）：**
- [列出此类漏洞的 sink，如 cursor.execute(), subprocess.run()]

**Sanitization（安全屏障）：**
- [列出能阻断攻击链的措施，如 parameterized query, shlex.quote()]

**检测路径：**
1. 搜索 sink 调用
2. 回溯数据流，检查参数是否来自 source
3. 验证 source→sink 路径上是否存在有效 sanitization
4. 若无 sanitization 或 sanitization 不完整 → 标记为候选漏洞

## Detection Checklist
- [ ] 可操作的检查项（基于 Detection Strategy 细化）

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- [安全模式] — [原因]

以下模式**需要深入检查**：
- [可疑模式] — [原因]

## Real-World Cases

详见 [references/cases.md](references/cases.md)（3-8 个真实案例，需要时加载）。
```

### references/cases.md Structure

```markdown
# [Category] Real-World Case Library

### Case 1: ...
### Case 2: ...
（3-8 cases，遵循 case-template.md）
```

## Constraints

- SKILL.md body 控制在合理长度，核心检测策略优先
- Cases 拆到 references/cases.md，按需加载
- 每个 Skill 3-8 个 Case
- Case 必须使用真实代码，不可用伪代码
- 每个 Case 必须有 Source → Sink 路径 和 "Why Standard Scanners Miss It"
- Detection Strategy 是必须的，它定义了此类漏洞的通用检测模型
- YAML frontmatter 必须包含 name + description

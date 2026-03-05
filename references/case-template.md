# Vulnerability Case Template

每个 Case 代表一种**独特的漏洞变体模式**（不是一个 CVE），从真实 GHSA/CVE 中提炼。
核心目标：教会 Agent **如何在未知代码中发现此类漏洞**。

---

### Case N: [package-name] — [漏洞模式概述] (CVE-xxxx-yyyy, CVSS x.x)

**Root Cause**: [一句话根因]

**Source → Sink 路径**:
- **Source**: [具体的用户输入入口，如 `request.args.get("path")`, `tool_call.arguments`]
- **Sink**: [具体的危险函数，如 `cursor.execute()`, `subprocess.run()`]
- **Sanitization Gap**: [为什么 source 到 sink 之间没有有效防护]

**Vulnerable Code Pattern** (`affected-file-path`):
```python
# 5-15 行关键漏洞代码模式，必须是真实代码
```

**Attack Path**:
1. 攻击者通过 [source] 注入 [payload 类型]
2. 数据经过 [中间处理，如无过滤直接传递 / wrapper 函数转发]
3. 到达 [sink]，触发 [危害，如任意命令执行 / SQL 查询篡改]

**Why Standard Scanners Miss It**:
- CodeQL: [具体原因，如"标准 query 不覆盖 Django .extra() 方法的 SQL sink"]
- Bandit/Gosec: [具体原因，如"只检查 subprocess.call 不检查 os.popen"]

**How to Detect（如何发现此类漏洞）**:
1. **定位 Sink**: Grep `search-pattern` — 找到可疑代码位置
2. **回溯 Source**: 从 sink 参数向上追踪，确认数据是否来自用户输入
3. **验证 Sanitization**: 检查路径上是否有 [具体的安全措施，如参数化查询]
4. **CodeQL 自定义查询方向**: [简要描述]

**Similar Vulnerabilities**: [同模式的其他 CVE/GHSA，2-3 个典型]

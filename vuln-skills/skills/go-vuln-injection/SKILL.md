---
name: go-vuln-injection
description: "Use when auditing Go code involving OS command execution, SQL queries, template rendering, or child command invocation. Covers CWE-78/89/77/94/88. Keywords: command injection, SQL injection, exec.Command, os/exec, database/sql, text/template, html/template, argument injection, shell injection, Gogs, Grafana, MCP stdio"
---

# Go Injection Vulnerability Patterns (CWE-78/89/77/94/88)

当审计 Go 代码中涉及命令执行、SQL 查询、模板渲染、外部进程调用时加载此 Skill。

## Detection Strategy

**Sources（攻击入口）：**
- HTTP 请求参数（query params, form values, JSON body）
- gRPC 请求字段
- Git 仓库内容（commit message, branch name, file content）
- MCP tool 输入参数
- 用户提交的配置值（Helm values, Kustomize patches）
- AI/LLM 生成的 SQL 查询

**Sinks（危险操作）：**
- `exec.Command("sh", "-c", userInput)` -- OS 命令注入
- `exec.Command("bash", "-c", userInput)` -- 同上
- `exec.Command(binary, "--flag=" + userInput)` -- 参数注入 (CWE-88)
- `exec.CommandContext(ctx, "git", "--upload-pack=evil", ...)` -- Git argument injection
- `db.Query("SELECT * FROM t WHERE id=" + userInput)` -- SQL 注入
- `db.Exec(fmt.Sprintf("INSERT INTO t VALUES ('%s')", userInput))` -- SQL 注入
- `template.New("").Parse(userInput)` (`text/template`) -- 模板注入
- `template.HTML(userInput)` -- XSS（绕过 `html/template` 自动转义）

**Sanitization（安全屏障）：**
- `exec.Command(binary, arg1, arg2)` -- 不经过 shell，每个参数独立传递
- `db.Query(sql, args...)` / `db.Exec(sql, args...)` -- 参数化查询
- `html/template`（非 `text/template`）-- 自动 HTML 转义
- `shellescape` / `shlex` 包 -- shell 参数转义
- 输入白名单验证（正则匹配允许的字符）

**检测路径：**

```bash
# OS 命令执行
grep -rn "exec.Command\|exec.CommandContext\|os.StartProcess" --include="*.go"
# Shell 调用
grep -rn '"sh".*"-c"\|"bash".*"-c"\|"cmd".*"/c"' --include="*.go"
# SQL 拼接
grep -rn 'fmt.Sprintf.*SELECT\|fmt.Sprintf.*INSERT\|fmt.Sprintf.*UPDATE\|fmt.Sprintf.*DELETE' --include="*.go"
grep -rn 'Sprintf.*WHERE\|"+.*WHERE\|`.*%s.*FROM' --include="*.go"
# 模板注入
grep -rn "text/template\|template.New\|template.Must" --include="*.go"
# 参数化查询（安全模式）
grep -rn "db.Query.*,\|db.Exec.*,\|db.QueryRow.*," --include="*.go"
# Argument injection — Git
grep -rn '"git".*"--upload-pack\|"git".*"--exec-path\|"git".*"--config"' --include="*.go"
```

1. 定位命令执行/SQL 查询/模板渲染的 Sink 函数
2. 回溯参数来源，确认是否包含用户输入
3. 验证是否有安全屏障：
   - `exec.Command` 是否通过 shell（`sh -c`）执行？直接传参不经过 shell 通常安全
   - SQL 是否使用参数化查询（`?` 占位符）？`fmt.Sprintf` 拼接 SQL 是危险信号
   - 模板是否使用 `html/template`（安全）而非 `text/template`（不安全）？
   - Git 命令是否允许用户控制 `--upload-pack`、`--config` 等可执行的参数？
4. 若无安全屏障或屏障可被绕过 -> 标记为候选漏洞

## Detection Checklist

- [ ] **`exec.Command` Shell 调用审计** (CWE-78)：是否使用 `exec.Command("sh", "-c", input)` 或 `exec.Command("bash", "-c", input)` 执行用户输入？Go 中 `exec.Command` 默认不经过 shell，但显式调用 shell 时存在注入风险。
- [ ] **Git Argument Injection 审计** (CWE-88)：`exec.Command("git", userArgs...)` 是否允许用户注入 `--upload-pack`、`--exec-path`、`--config=core.sshCommand=evil` 等可执行参数？Gogs 的 SSH argument injection 是经典案例。
- [ ] **SQL 字符串拼接审计** (CWE-89)：是否使用 `fmt.Sprintf` 或字符串连接构造 SQL？应使用 `db.Query(sql, args...)` 的参数化形式。特别注意 `ORDER BY`、`LIMIT` 等不能用参数化的子句。
- [ ] **AI/LLM 生成 SQL 审计** (CWE-89)：AI 数据库查询工具（如 WeKnora）生成的 SQL 是否经过安全过滤？LLM 输出不可信，必须有 SQL 白名单或 AST 解析验证。
- [ ] **`text/template` 用于 HTML 审计** (CWE-94)：是否误用 `text/template` 生成 HTML 输出？应使用 `html/template` 以获得自动转义。检查 import 路径。
- [ ] **Helm/Kustomize 模板注入审计** (CWE-94)：用户提交的 Helm values 是否被直接注入模板？`{{` 语法是否能执行任意 Go 模板函数？Flux helm-controller 曾因此导致 RCE。
- [ ] **MCP Stdio 命令注入审计** (CWE-78)：MCP server 的 stdio transport 配置中的 `command` 字段是否经过验证？WeKnora 的 MCP stdio test 功能曾允许注入任意命令。
- [ ] **`os.StartProcess` 参数审计** (CWE-78)：低层级的 `os.StartProcess` 调用是否正确隔离了参数？参数数组中是否有用户控制的元素？

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **`exec.Command("git", "--version")`** -- 无用户输入的硬编码命令
- **`exec.Command(binary, fixedArgs...)`** -- 参数完全硬编码，无用户输入
- **`db.Query("SELECT * FROM t WHERE id = ?", userID)`** -- 参数化查询是安全的
- **`html/template` 渲染用户输入** -- 自动转义会处理 XSS（除非使用 `template.HTML()` 类型转换）
- **`fmt.Sprintf` 用于日志而非 SQL** -- 拼接字符串用于 log 而非数据库查询

以下模式**需要深入检查**：
- **`exec.Command("git", userProvidedRepoURL)`** -- URL 中可能包含 `--upload-pack` 参数
- **`db.Exec("CREATE TABLE " + tableName)`** -- DDL 语句中标识符不能用 `?` 参数化
- **`text/template` 用于非 HTML 输出** -- 如生成 YAML/JSON，可能导致结构注入
- **`strings.Replace(input, "'", "''", -1)`** -- 手工 SQL 转义极易遗漏边缘情况

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

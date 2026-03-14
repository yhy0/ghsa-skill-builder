---
name: go-vuln-ssrf-requestforgery
description: "Use when auditing Go code involving HTTP client requests, webhook callbacks, URL handling, HTML template rendering in Go web frameworks, or CSRF protection. Covers CWE-918/352/79. Keywords: SSRF, server-side request forgery, XSS, cross-site scripting, CSRF, http.Get, http.Client, template.HTML, Gin, Echo, Fiber, webhook, Kyverno, DNS rebinding"
---

# Go SSRF / XSS / CSRF Vulnerability Patterns (CWE-918/352/79)

当审计 Go 代码中涉及 HTTP 客户端请求、webhook 回调、URL 处理、HTML 模板渲染、CSRF 防护时加载此 Skill。

## Detection Strategy

### SSRF (CWE-918)

**Sources（攻击入口）：**
- 用户提供的 URL（webhook callback URL、image URL、import URL）
- Kyverno policy 中的 `apiCall` URL
- Redirect URL 参数
- Git 仓库 URL
- Proxy 目标 URL

**Sinks（HTTP 请求发起点）：**
- `http.Get(userURL)` / `http.Post(userURL, ...)`
- `http.Client{}.Do(req)` 其中 `req.URL` 来自用户
- `net.Dial(userHost + ":" + port)`
- `grpc.Dial(userAddr)`
- `url.Parse(userURL)` -> `http.NewRequest("GET", parsedURL, nil)`

**Sanitization（SSRF 防护）：**
- URL allowlist（白名单匹配协议 + 主机）
- IP blocklist（禁止 `127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`, `::1`）
- DNS resolution 后再检查 IP（防止 DNS rebinding）
- 禁用 HTTP redirect following（`CheckRedirect` 返回错误）
- `ssrf` 防护库（如 `github.com/trufflesecurity/of-ssrf`）
- `http.Client{Timeout: 10 * time.Second}` -- 设置请求超时防止 hang（默认无超时）

### XSS (CWE-79)

**Sources（攻击入口）：**
- 用户输入通过 Go API 传递到前端
- 用户输入在 Go 模板中渲染

**Sinks（XSS 注入点）：**
- `template.HTML(userInput)` -- 类型转换绕过 `html/template` 自动转义
- `template.JS(userInput)` / `template.CSS(userInput)` -- 同上
- `c.HTML(200, template)` (Gin) + `text/template` 而非 `html/template`
- `c.String(200, userInput)` with `Content-Type: text/html`
- `w.Write([]byte(userInput))` with `text/html` Content-Type

**Sanitization：**
- `html/template` 自动转义（但 `template.HTML()` 类型转换会绕过）
- `bluemonday` HTML sanitizer
- `html.EscapeString(userInput)`
- 正确的 `Content-Type` header（`application/json` 而非 `text/html`）

### CSRF (CWE-352)

**Sources（攻击入口）：**
- 跨站 POST/PUT/DELETE 请求

**Sinks（状态修改端点）：**
- 无 CSRF token 的 POST handler
- Cookie-based auth 的 API 端点

**Sanitization：**
- `gorilla/csrf` 中间件
- `SameSite=Strict` / `SameSite=Lax` cookie 属性
- 自定义 CSRF token（`X-CSRF-Token` header）
- Double-submit cookie pattern

**检测路径：**

```bash
# SSRF — HTTP 客户端调用
grep -rn "http.Get\|http.Post\|http.Client\|http.NewRequest" --include="*.go"
# URL 解析
grep -rn "url.Parse\|url.PathEscape\|net.Dial\|grpc.Dial" --include="*.go"
# XSS — template.HTML 类型转换
grep -rn "template.HTML\|template.JS\|template.CSS" --include="*.go"
# text/template 用于 HTML
grep -rn '"text/template"' --include="*.go"
# CSRF 中间件
grep -rn "csrf\|gorilla/csrf\|SameSite\|csrfToken" --include="*.go"
# Webhook 回调
grep -rn "webhook\|callback.*url\|notify.*url" --include="*.go"
# DNS rebinding 防护
grep -rn "net.LookupIP\|net.ResolveIPAddr\|IsPrivate\|IsLoopback" --include="*.go"
```

1. **SSRF**: 搜索 HTTP 客户端调用，追踪 URL 来源是否来自用户输入，验证是否有 URL 白名单或 IP 黑名单
2. **XSS**: 搜索 `template.HTML()` 类型转换和 `text/template` 使用，确认用户输入是否绕过了 auto-escaping
3. **CSRF**: 检查状态修改端点是否有 CSRF 保护中间件，cookie 是否设置了 `SameSite` 属性

## Detection Checklist

- [ ] **`http.Get(userURL)` SSRF 审计** (CWE-918)：HTTP 客户端是否使用用户提供的 URL？是否验证了目标 URL 不指向内网地址（`127.0.0.1`, `10.x.x.x`, `169.254.169.254`）？
- [ ] **Kyverno `apiCall` 跨 Namespace SSRF 审计** (CWE-918)：Kyverno policy 的 `apiCall` 是否使用了 ServiceAccount 的集群权限访问其他 namespace 的 API？低权限用户是否能通过 policy 间接发起请求？
- [ ] **Webhook 回调 URL 白名单审计** (CWE-918)：Webhook callback URL 是否来自用户配置？是否限制了允许的目标域名？是否检查了 DNS 解析结果不指向内网？
- [ ] **DNS Rebinding 防护审计** (CWE-918)：SSRF 防护是否在 DNS 解析后检查 IP？攻击者可通过 DNS rebinding 让域名先解析为公网 IP（通过检查）再解析为内网 IP（实际请求）。
- [ ] **`template.HTML()` 类型转换审计** (CWE-79)：是否将用户输入通过 `template.HTML(userInput)` 类型转换？这会绕过 `html/template` 的自动转义，等同于直接输出原始 HTML。
- [ ] **Go Web 框架 XSS 审计** (CWE-79)：Gin/Echo/Fiber 的 handler 是否以 `text/html` Content-Type 返回未转义的用户输入？`c.HTML()` 是否使用 `html/template`？
- [ ] **CSRF 保护中间件审计** (CWE-352)：所有状态修改的 POST/PUT/DELETE 端点是否有 CSRF 保护？`gorilla/csrf` 中间件是否正确注册？
- [ ] **Cookie SameSite 属性审计** (CWE-352)：认证 cookie 是否设置了 `SameSite=Lax` 或 `SameSite=Strict`？`SameSite=None` 需要 `Secure` 标志且仅在 HTTPS 下使用。

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **SSRF: HTTP 客户端访问硬编码 URL** -- 如 `http.Get("https://api.github.com/...")` 无用户控制
- **SSRF: 服务间内部通信** -- 如 gRPC 调用已知的内部服务地址
- **XSS: `template.HTML` 用于静态内容** -- 如硬编码的 HTML 片段
- **CSRF: 纯 API token 认证** -- 不使用 cookie 认证的 API 不受 CSRF 影响

以下模式**需要深入检查**：
- **SSRF: URL 来自数据库配置** -- 配置值是否可被低权限用户修改？
- **SSRF: `http.Client` 默认跟随重定向** -- 第一跳是合法 URL，但重定向到内网
- **XSS: `html/template` + 自定义 FuncMap** -- FuncMap 中的函数是否返回 `template.HTML` 类型？
- **CSRF: SPA 前端 + Cookie auth** -- 即使 SPA 不使用表单提交，cookie 仍会被浏览器自动发送

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

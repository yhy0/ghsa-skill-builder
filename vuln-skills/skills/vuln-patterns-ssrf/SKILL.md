---
name: vuln-patterns-ssrf
description: "Use when auditing Python code involving HTTP client calls (requests, httpx, urllib, aiohttp), webhook endpoints, proxy forwarding, file/model downloads, or SVG/XML external resource loading. Covers CWE-918. Keywords: SSRF, server-side request forgery, requests.get, urllib, httpx, aiohttp, webhook, proxy, redirect, url fetch, file download, gethostbyname, is_private_url, DNS rebinding, cloud metadata"
---

# SSRF Vulnerability Patterns (CWE-918)

当审计 Python 代码中涉及外部 URL 请求、HTTP 客户端调用、文件下载、资源代理等操作时加载此 Skill。

## Detection Strategy

**Sources（用户可控 URL 来源）：**
- HTTP 请求参数（query string、form data、JSON body 中的 URL 字段）
- 文件上传时的 URL 引用（multipart form 中传递 URL 而非文件内容）
- AI/ML 框架的 message history 中嵌入的 URL（`ImageUrl`、`AudioUrl`、`DocumentUrl`）
- XML/SVG 文档中的外部资源引用（`xlink:href`、`@import url()`、`<use href=>`）
- 配置参数中的模型下载 URL、数据源 URL
- Web 爬虫/监控工具中用户提交的目标 URL
- 代理/搜索引擎中的资源元素 URL（image、script、stylesheet proxy）

**Sinks（发起请求的函数/操作）：**
- `requests.get(url)` / `requests.post(url)` / `session.request(method, url)`
- `httpx.AsyncClient().get(url)` / `httpx.Client().stream("GET", url)`
- `urllib.request.urlopen(url)` / `urllib.request.Request(url)`
- `aiohttp.ClientSession().get(url)`
- `SimpleWebPageReader().load_data([url])`（LlamaIndex 等 LLM 框架）
- SVG/图像处理库的 URL fetcher（如 CairoSVG 的 `url_fetcher`）
- `socket.create_connection()` / 底层 TCP 连接

**Sanitization（URL 验证/限制）：**
- **协议白名单**：仅允许 `http://` 和 `https://`，拒绝 `file://`、`gopher://`、`ftp://` 等
- **IP 地址验证**：解析 hostname 后使用 Python `ipaddress` 模块检查，推荐 `ipaddress.ip_address(ip).is_private` 或 `is_reserved` 或 `is_loopback`。需覆盖 RFC 1918 私有地址、环回地址、链路本地地址及 IPv6 对应段
- **云元数据端点阻断**：显式阻断 AWS/Azure/GCP 的实例元数据服务 IP（IPv4 和 IPv6）、`metadata.google.internal` 等 DNS 名称
- **DNS 解析后验证**：先 `socket.getaddrinfo()` 解析再检查 IP，防止 DNS rebinding
- **重定向验证**：每个 redirect hop 都重新验证目标 IP，使用 `allow_redirects=False` 手动跟踪
- **域名白名单**：`validators.domain()` 验证或 `allowed_urls` 配置

**检测路径：**

搜索 SSRF sink 的 Grep 模式：
```bash
# HTTP 客户端调用
grep -rn "requests\.\(get\|post\|put\|delete\|head\)" --include="*.py"
grep -rn "httpx\.\|AsyncClient\|Client()" --include="*.py"
grep -rn "urlopen\|urllib\.request" --include="*.py"
grep -rn "aiohttp.*\.get\|ClientSession" --include="*.py"
# URL 验证函数
grep -rn "is_private\|is_reserved\|is_loopback\|gethostbyname" --include="*.py"
grep -rn "allow_redirects\|follow_redirects" --include="*.py"
# SVG/XML 外部资源
grep -rn "xlink\|url_fetcher\|external_resource" --include="*.py"
```

1. 搜索 HTTP 请求发起函数（`requests.get`、`httpx.get`、`urlopen`、`session.request` 等）
2. 回溯 URL 参数来源，检查是否直接或间接来自用户输入
3. 验证是否存在以下防护措施：
   - URL 协议白名单检查
   - DNS 解析后的 IP 地址私有性检查
   - 云元数据端点显式阻断
4. 检查是否有 DNS rebinding 防护（解析与请求之间是否存在 TOCTOU 窗口）
5. 检查重定向跟踪是否验证每一跳的目标地址

## Detection Checklist

- [ ] **直接 URL 传递**：用户提供的 URL 是否未经验证直接传入 HTTP 客户端？
- [ ] **仅 scheme 检查**：是否只验证了 `http/https` 协议而未检查目标 IP？（如 `is_http_url()` 只检查 scheme）
- [ ] **DNS rebinding 窗口**：`gethostbyname()` 验证与实际 HTTP 请求之间是否存在时间窗口？
- [ ] **重定向绕过**：是否使用 `follow_redirects=True`/`allow_redirects=True` 而未验证重定向目标？
- [ ] **XML/SVG 外部资源**：XML/SVG 解析器是否默认加载外部资源（`xlink:href`、CSS `@import`）？
- [ ] **框架自动下载**：ML/AI 框架是否自动从用户提供的 URL 下载模型/数据/文件？
- [ ] **代理端点**：代理/转发端点是否验证目标域名和 IP？
- [ ] **`allowed_urls` 默认值**：URL 白名单的默认值是否过于宽松（如 `.*`）？
- [ ] **IPv6 绕过**：是否考虑了 IPv6 地址（`::1`、`::ffff:127.0.0.1`、IPv4-mapped IPv6）？
- [ ] **URL 编码绕过**：是否考虑了 URL 编码、Unicode 编码等绕过手法？
- [ ] **Blind SSRF 检测**：即使响应不回显，是否仍可通过响应时间差异、DNS 日志、带外通道（如 Burp Collaborator）探测内网服务？

## False Positive Exclusion Guide

以下情况通常**不是** SSRF 漏洞：
1. **硬编码 URL**：代码中固定的外部 API 端点（如 `requests.get("https://api.github.com/...")`）
2. **内部服务间调用**：微服务架构中的服务发现 URL（但需确认不受用户控制）
3. **显式 `unsafe=True` 模式**：如 CairoSVG 的 `unsafe` 参数，用户明确选择允许外部资源
4. **仅限管理员访问的端点**：需要管理员权限的配置接口（但仍需评估权限提升风险）
5. **本地文件操作**：`open(path)` 读取本地文件不属于 SSRF（但可能是路径遍历）
6. **环境变量控制的 URL**：从 `os.getenv()` 获取的 URL 通常由运维人员配置

## Real-World Cases

详见 [references/cases.md](references/cases.md)

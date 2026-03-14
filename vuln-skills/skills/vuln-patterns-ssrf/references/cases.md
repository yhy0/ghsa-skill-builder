# SSRF 漏洞真实案例 (CWE-918)

> 以下案例均来自公开披露的 Python 包漏洞，代码片段提取自真实的 patch diff。

---

### Case 1: bentoml — ML 服务框架文件上传自动下载无 URL 验证 (CVE-2025-54381, CVSS 9.9)

**Root Cause**: BentoML 的序列化处理器在接收文件上传时，自动将用户提供的 URL 字符串作为下载地址发起 HTTP 请求，MultipartSerde 路径完全没有 URL 验证，JSONSerde 路径仅检查 scheme。

**Source -> Sink 路径**:
- **Source**: HTTP multipart form field 值或 JSON request body 中的 URL 字符串
- **Sink**: `httpx.AsyncClient().get(obj)` — 直接 HTTP GET 请求
- **Sanitization Gap**: MultipartSerde 路径零验证；JSONSerde 路径仅调用 `is_http_url()` 检查 scheme 是否为 http/https，未检查目标 IP 是否为内网地址

**Vulnerable Code Pattern** (`src/_bentoml_impl/serde.py`):
```python
# MultipartSerde.ensure_file() — 零验证路径
async def ensure_file(obj: str | UploadFile) -> UploadFile:
    if isinstance(obj, UploadFile):
        return obj
    async with httpx.AsyncClient() as client:
        obj = obj.strip("\"'")  # The url may be JSON encoded
        logger.debug("Request with URL, downloading file from %s", obj)
        resp = await client.get(obj)  # SSRF: 用户可控 URL 直接请求
        body = io.BytesIO(await resp.aread())
        parsed = urlparse(obj)
        return UploadFile(body, size=len(body.getvalue()),
                          filename=os.path.basename(parsed.path))

# JSONSerde.parse_request() — 仅 scheme 检查路径
body = await request.body()
if issubclass(cls, IORootModel) and cls.multipart_fields:
    if is_http_url(url := body.decode("utf-8", "ignore")):  # 仅检查 http/https
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)  # SSRF: 内网地址未阻断
```

**Attack Path**:
1. 创建带 `Path` 或 `PIL.Image.Image` 参数的 BentoML service endpoint
2. 发送 multipart form 请求，将文件字段值设为 `http://169.254.169.254/latest/meta-data/`
3. 服务端自动发起 HTTP 请求到 AWS 元数据端点，返回 IAM 凭证

**Why Standard Scanners Miss It**:
- **CodeQL**: 默认 SSRF source 不覆盖 multipart form field 值被当作 URL 的场景；`ensure_file()` 中 `obj` 参数类型是 `str | UploadFile`，类型联合使污点追踪中断
- **Bandit**: 无法检测 `httpx.AsyncClient().get()` 的 SSRF 风险，且不追踪 URL 来自 form field 值

**How to Detect**:
1. 搜索 `httpx.AsyncClient().get(` 或 `httpx.get(` 调用
2. 检查 URL 参数是否来自 HTTP 请求的 form field 或 body
3. 确认请求前是否调用了 IP 地址验证函数（不仅仅是 scheme 检查）
4. 特别关注框架的序列化/反序列化层（serde）中的自动下载逻辑

**Similar Vulnerabilities**: CVE-2024-4325 (Gradio save_url_to_cache), CVE-2025-65958 (Open WebUI process/web)

---

### Case 2: CairoSVG — SVG 外部资源加载导致 SSRF (CVE-2023-27586, CVSS 9.9)

**Root Cause**: CairoSVG 在解析 SVG 文件时默认加载外部资源（`<image xlink:href>`、CSS `@import url()`、`<use href>`），攻击者可构造恶意 SVG 触发服务端向任意 URL 发起请求。

**Source -> Sink 路径**:
- **Source**: SVG 文件中的 `xlink:href`、`href`、CSS `@import url()` 属性值
- **Sink**: CairoSVG 内部的 `url_fetcher` 函数（默认使用 urllib 发起 HTTP 请求）
- **Sanitization Gap**: 默认模式下未限制外部资源加载，`unsafe` 参数仅控制 XXE 和文件大小限制，不控制外部请求

**Vulnerable Code Pattern** (`cairosvg/parser.py`):
```python
class Tree(Element):
    def __init__(self, **kwargs):
        # ...
        tree = ElementTree.fromstring(
            bytestring, forbid_entities=not unsafe,
            forbid_external=not unsafe)
        # 修复前：无论 unsafe 是否为 True，都使用默认 url_fetcher 加载外部资源
        # 修复后：非 unsafe 模式下替换 url_fetcher 为空 SVG 返回
        self.xml_tree = tree
```

**Patch** (`cairosvg/parser.py`):
```python
# 修复：非 unsafe 模式下禁止外部资源获取
if 'url_fetcher' not in kwargs and not unsafe:
    self.url_fetcher = (
        lambda *args, **kwargs: b'<svg width="1" height="1"></svg>')
```

**Attack Path**:
1. 构造包含外部资源引用的 SVG 文件：`<image xlink:href="http://169.254.169.254/latest/meta-data/" />`
2. 上传到使用 CairoSVG 转换的 Web 服务（如 SVG 转 PNG）
3. CairoSVG 自动请求外部 URL，攻击者通过 DNS/HTTP 日志获取内网信息

**Why Standard Scanners Miss It**:
- **CodeQL**: SSRF sink 通常定义为 `requests.get()`/`urllib.urlopen()` 等显式调用，而 CairoSVG 的 URL fetch 发生在 XML 解析器内部，属于库间接调用
- **Bandit**: 仅检查 `urllib.urlopen()` 等直接调用，不分析 SVG/XML 解析器的外部资源加载行为

**How to Detect**:
1. 搜索 SVG/XML 处理库的使用（`cairosvg`、`lxml`、`xml.etree`、`svglib`）
2. 检查是否禁用了外部资源加载（`url_fetcher=None`、`forbid_external=True`）
3. 确认用户上传的 SVG/XML 内容是否经过外部引用清理

**Similar Vulnerabilities**: CVE-2021-21236 (CairoSVG SSRF), Pillow SVG plugin 外部资源加载

---

### Case 3: mindsdb — DNS Rebinding 绕过 SSRF 保护 (CVE-2024-24759, CVSS 9.3)

**Root Cause**: MindsDB 的 `is_private_url()` 函数在验证 URL 时先通过 `socket.gethostbyname()` 解析 DNS 获取 IP 并检查是否为私有地址，但实际 HTTP 请求在此之后才发起。攻击者利用 DNS rebinding 使首次解析返回公网 IP（通过验证），第二次解析（HTTP 请求时）返回内网 IP。

**Source -> Sink 路径**:
- **Source**: 用户提供的 `source_url_link` 参数
- **Sink**: `SimpleWebPageReader(html_to_text=True).load_data([url])`
- **Sanitization Gap**: `is_private_url()` 中 DNS 解析与 HTTP 请求之间存在 TOCTOU（Time-of-Check-Time-of-Use）竞态窗口

**Vulnerable Code Pattern** (`mindsdb/utilities/security.py` + handler):
```python
def is_private_url(url: str):
    hostname = urlparse(url).hostname
    if not hostname:
        return True
    ip = socket.gethostbyname(hostname)  # 第一次 DNS 解析：返回公网 IP
    return ipaddress.ip_address(ip).is_private

# handler 中的使用
url = args['using']['source_url_link']
config = Config()
is_cloud = config.get("cloud", False)
if is_cloud and is_private_url(url):       # 检查通过（公网 IP）
    raise Exception(f'URL is private: {url}')
reader = SimpleWebPageReader(html_to_text=True).load_data([url])
# 第二次 DNS 解析（HTTP 请求时）：返回 127.0.0.1  ← DNS rebinding!
```

**Attack Path**:
1. 设置 DNS rebinding 域名：`make-190.119.176.214-rebind-127.0.0.1-rr.1u.ms`
2. 首次 DNS 查询返回 `190.119.176.214`（公网 IP），通过 `is_private_url()` 检查
3. HTTP 请求时第二次 DNS 查询返回 `127.0.0.1`，成功访问内网服务

**Why Standard Scanners Miss It**:
- **CodeQL**: 从代码静态分析角度，`is_private_url()` 作为 sanitizer 已经检查了 IP 是否为私有地址，CodeQL 会认为数据已被净化
- **Bandit**: 无 DNS rebinding 检测规则，不理解 TOCTOU 问题

**How to Detect**:
1. 搜索 `gethostbyname()` 或 `getaddrinfo()` 调用
2. 检查 DNS 解析结果是否用于后续 HTTP 请求的 IP 直连（而非仅用于验证）
3. 确认是否存在 "解析-验证-请求" 中解析与请求使用同一已解析 IP 的机制
4. 正确修复应将 DNS 解析的 IP 地址直接用于 HTTP 连接（pin IP），或在请求时重新验证

**Similar Vulnerabilities**: CVE-2024-22205 (Whoogle DNS rebinding potential), 大量 Web 应用的 SSRF 保护绕过

---

### Case 4: gradio — save_url_to_cache 文件缓存 SSRF (CVE-2024-4325, CVSS 8.6)

**Root Cause**: Gradio 的 `/queue/join` 端点调用 `save_url_to_cache()` 函数下载用户提供的 URL 内容到本地缓存，该函数未验证 URL 指向的 IP 地址，且使用 `follow_redirects=True` 允许重定向绕过。

**Source -> Sink 路径**:
- **Source**: `/queue/join` 端点中用户提交的 `path` 值（预期为 URL）
- **Sink**: `httpx.Client().stream("GET", url, follow_redirects=True)` — 带重定向跟踪的 HTTP 流式请求
- **Sanitization Gap**: 无 IP 地址验证，且 `follow_redirects=True` 允许通过公网 URL 重定向到内网地址

**Vulnerable Code Pattern** (`gradio/processing_utils.py`):
```python
def save_url_to_cache(url: str, cache_dir: str) -> str:
    # 修复前：无 URL 安全性验证
    temp_dir = hash_url(url)
    temp_dir = Path(cache_dir) / temp_dir
    temp_dir.mkdir(exist_ok=True, parents=True)
    name = Path(url).name
    full_temp_file_path = str(abspath(temp_dir / name))

    if not Path(full_temp_file_path).exists():
        with sync_client.stream("GET", url, follow_redirects=True) as r, open(
            full_temp_file_path, "wb"
        ) as f:
            for chunk in r.iter_raw():
                f.write(chunk)
    return full_temp_file_path
```

**Patch** (`gradio/processing_utils.py` + `gradio_client/utils.py`):
```python
# 新增 is_safe_url 函数
def is_safe_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    if parsed_url.scheme not in ('http', 'https'):
        return False
    resolve = socket.gethostbyname(domain)
    ip = ipaddress.ip_address(resolve)
    if ip.is_private or ip.is_multicast:
        return False
    return True

# 修复：添加 URL 验证 + 禁用 follow_redirects
def save_url_to_cache(url: str, cache_dir: str) -> str:
    if not client_utils.is_safe_url(url):
        raise ValueError("URL is not safe or violates security policy.")
    # ...
    with sync_client.stream("GET", url) as r, open(...) as f:  # 移除 follow_redirects=True
```

**Attack Path**:
1. 向 Gradio 应用的 `/queue/join` 端点发送包含内网 URL 的请求
2. `save_url_to_cache()` 将内网资源内容下载到本地缓存目录
3. 通过后续请求读取缓存内容，获取内网敏感信息

**Why Standard Scanners Miss It**:
- **CodeQL**: `httpx.Client().stream()` 不在默认 SSRF sink 列表中（通常只覆盖 `requests.get`/`urllib.urlopen`）
- **Bandit**: 不检测 `httpx` 库的 SSRF 风险

**How to Detect**:
1. 搜索 `httpx.Client().stream(` 或 `httpx.AsyncClient().stream(` 调用
2. 检查是否有 `follow_redirects=True` 参数（允许重定向绕过）
3. 确认 URL 来源是否为用户可控输入
4. 检查下载内容是否可被用户后续读取（非 blind SSRF）

**Similar Vulnerabilities**: CVE-2025-54381 (BentoML file upload SSRF), CVE-2025-65958 (Open WebUI retrieval SSRF)

---

### Case 5: whoogle-search — 元素代理端点缺少域名验证 (CVE-2024-22203, CVSS 9.1)

**Root Cause**: Whoogle Search 的 `/element` 和 `/window` 端点从请求参数中获取 URL，未验证域名合法性即通过内部 HTTP 客户端发起请求，可被用于代理任意内部/外部资源。

**Source -> Sink 路径**:
- **Source**: `request.args.get('url')` — query string 中的 URL 参数
- **Sink**: `g.user_request.send(base_url=src_url)` — 内部 HTTP 请求方法
- **Sanitization Gap**: 未验证 `src_url` 的域名和 IP 地址

**Vulnerable Code Pattern** (`app/routes.py`):
```python
@app.route('/element')
@session_required
@auth_required
def element():
    element_url = src_url = request.args.get('url')
    if element_url.startswith('gAAAAA'):
        try:
            src_url = Fernet(session['key']).decrypt(element_url.encode()).decode()
        except Exception:
            return render_template('error.html', error_message='Invalid URL'), 400

    src_type = request.args.get('type')
    # 修复前：无域名验证，直接发起请求
    try:
        file_data = g.user_request.send(base_url=src_url).content  # SSRF
        # ...
```

**Patch** (`app/routes.py`):
```python
def element():
    empty_gif = base64.b64decode(
        'R0lGODlhAQABAIAAAP///////yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==')
    element_url = src_url = request.args.get('url')
    # ...
    src_type = request.args.get('type')

    # 修复：验证域名合法性
    domain = urlparse.urlparse(src_url).netloc
    if not validators.domain(domain):
        return send_file(io.BytesIO(empty_gif), mimetype='image/gif')
```

**Attack Path**:
1. 构造请求 `GET /element?url=http://169.254.169.254/latest/meta-data/&type=text`
2. Whoogle 服务端代理该请求，访问 AWS 元数据端点
3. 响应内容返回给攻击者

**Why Standard Scanners Miss It**:
- **CodeQL**: `g.user_request.send()` 是自定义方法，不在标准 SSRF sink 定义中，需要自定义 sink 建模
- **Bandit**: 不分析自定义 HTTP 客户端包装方法

**How to Detect**:
1. 搜索代理/转发类端点（route 名称包含 `element`、`proxy`、`fetch`、`window`）
2. 检查端点是否从请求参数获取 URL 并发起 HTTP 请求
3. 确认是否验证了目标 URL 的域名和 IP 地址
4. 注意 Fernet 加密的 URL 解密后也需要验证

**Similar Vulnerabilities**: CVE-2024-22205 (Whoogle /window endpoint SSRF)

---

### Case 6: changedetection.io — URL 监控工具缺少 IP 地址验证 (CVE-2026-27696, CVSS 8.6)

**Root Cause**: changedetection.io 的 `is_safe_valid_url()` 函数仅验证 URL 协议和格式，未对 hostname 进行 DNS 解析和 IP 地址检查。HTTP fetcher 直接请求用户提供的 URL，且使用 `allow_redirects` 未验证重定向目标。更严重的是，获取的内容会被存储并可通过 Web UI 查看，构成非盲 SSRF。

**Source -> Sink 路径**:
- **Source**: Web UI 或 REST API 提交的 watch URL（`/api/v1/watch`）
- **Sink**: `session.request(method, url, ..., verify=False)` — 带内容存储的 HTTP 请求
- **Sanitization Gap**: `is_safe_valid_url()` 不检查 IP 地址；fetcher 不验证重定向目标

**Vulnerable Code Pattern** (`changedetectionio/validate_url.py` + `content_fetchers/requests.py`):
```python
# validate_url.py — 仅检查协议和格式
@lru_cache(maxsize=10000)
def is_safe_valid_url(test_url):
    safe_protocol_regex = '^(http|https|ftp):'
    pattern = re.compile(os.getenv('SAFE_PROTOCOL_REGEX', safe_protocol_regex), re.IGNORECASE)
    if not pattern.match(test_url.strip()):
        return False
    if not validators.url(test_url, simple_host=True):
        return False
    return True  # 无 IP 地址验证!

# content_fetchers/requests.py — 直接请求并存储内容
r = session.request(method=request_method,
                    url=url,            # 用户提供的 URL，无 IP 验证
                    headers=request_headers,
                    timeout=timeout,
                    proxies=proxies,
                    verify=False)
self.content = r.text     # 内容被存储
self.raw_content = r.content  # 原始字节被存储
```

**Patch** (`changedetectionio/validate_url.py` + `content_fetchers/requests.py`):
```python
# 新增 is_private_hostname 函数
def is_private_hostname(hostname):
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
    except socket.gaierror:
        return True  # 无法解析的 hostname 也阻断
    return False

# fetcher 中添加请求时 DNS 验证 + 重定向逐跳验证
if not allow_iana_restricted:
    parsed_initial = urlparse(url)
    if parsed_initial.hostname and is_private_hostname(parsed_initial.hostname):
        raise Exception(f"Fetch blocked: resolves to private IP")

r = session.request(..., allow_redirects=False)  # 禁用自动重定向
for _ in range(10):  # 手动跟踪重定向
    if not r.is_redirect:
        break
    redirect_url = urljoin(current_url, r.headers.get('Location', ''))
    if not allow_iana_restricted:
        parsed_redirect = urlparse(redirect_url)
        if parsed_redirect.hostname and is_private_hostname(parsed_redirect.hostname):
            raise Exception(f"Redirect blocked: resolves to private IP")
```

**Attack Path**:
1. 在 changedetection.io UI 中添加监控 URL：`http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. 服务端定期请求该 URL 并存储响应内容
3. 通过 Web UI 的 "Preview" 功能查看 AWS IAM 凭证

**Why Standard Scanners Miss It**:
- **CodeQL**: `session.request()` 是 SSRF sink，但 `is_safe_valid_url()` 可能被误识别为 sanitizer（实际上不检查 IP）
- **Bandit**: `requests.Session().request()` 不在默认检测规则中

**How to Detect**:
1. 搜索 URL 验证函数（`is_safe_valid_url`、`validate_url`）
2. 检查验证逻辑是否包含 DNS 解析和 IP 地址私有性检查
3. 确认 HTTP fetcher 是否在请求时重新验证 DNS（防止 rebinding）
4. 检查重定向是否逐跳验证（`allow_redirects=False` + 手动跟踪）

**Similar Vulnerabilities**: CVE-2024-24759 (MindsDB DNS rebinding), CVE-2024-4325 (Gradio SSRF)

---

### Case 7: pydantic-ai — AI 框架 Message History URL 下载 SSRF (CVE-2026-25580, CVSS 8.6)

**Root Cause**: Pydantic AI 的多个模型集成（OpenAI、Anthropic、Google 等）在处理用户提交的 message history 时，自动下载其中嵌入的 `ImageUrl`、`AudioUrl`、`DocumentUrl` 等 URL 内容，`download_item()` 函数未验证 URL 目标是否为私有地址。通过 `Agent.to_web`、`VercelAIAdapter`、`AGUIAdapter` 等接口暴露给外部用户。

**Source -> Sink 路径**:
- **Source**: 用户提交的 message history 中的 URL（`ImageUrl.url`、`AudioUrl.url` 等）
- **Sink**: `httpx.AsyncClient().get(url)` — 下载 URL 内容用于模型推理
- **Sanitization Gap**: `download_item()` 未检查 URL 协议、目标 IP 和重定向目标

**Vulnerable Code Pattern**（漏洞存在于多个 model integration 中的 download 路径）:
```python
# 多个 model provider 中的 URL 下载（如 OpenAI、Google 等）
# download_item() 或类似函数直接使用 httpx 下载用户提供的 URL
async def download_item(url: str) -> bytes:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)  # SSRF: 未验证目标 IP
        return response.content

# 攻击者通过 chat message 注入恶意 URL
{
    "role": "user",
    "parts": [
        {"type": "file", "mediaType": "image/png",
         "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    ]
}
```

**Patch**（新增 `_ssrf.py` 模块，核心防护逻辑）:
```python
# pydantic_ai_slim/pydantic_ai/_ssrf.py
_PRIVATE_NETWORKS = (
    ipaddress.IPv4Network('127.0.0.0/8'),    # Loopback
    ipaddress.IPv4Network('10.0.0.0/8'),      # Private
    ipaddress.IPv4Network('172.16.0.0/12'),  # Private
    ipaddress.IPv4Network('192.168.0.0/16'),  # Private
    ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local (cloud metadata)
    ipaddress.IPv4Network('100.64.0.0/10'),   # CGNAT (Alibaba Cloud metadata)
    # IPv6 ranges...
)

_CLOUD_METADATA_IPS = frozenset({
    '169.254.169.254', 'fd00:ec2::254', '100.100.100.200',
})

async def resolve_hostname(hostname: str) -> list[str]:
    results = await run_in_executor(
        socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    # 提取去重的 IP 列表
    return ips

async def safe_download(url: str, *, allow_local: bool = False) -> bytes:
    # 1. 协议验证（仅 http/https）
    # 2. DNS 解析到 IP
    # 3. 检查 IP 是否为私有/云元数据
    # 4. 使用解析后的 IP 直连（防止 DNS rebinding）
    # 5. 验证每个重定向目标（最多 10 跳）
```

**Attack Path**:
1. 通过 `Agent.to_web` 或 `VercelAIAdapter` 暴露的聊天接口提交消息
2. 消息中嵌入指向内网的文件 URL（如 AWS 元数据端点）
3. 服务端在处理消息时自动下载 URL 内容发送给 AI 模型
4. 模型响应中可能包含下载内容的摘要/分析，间接泄露内网信息

**Why Standard Scanners Miss It**:
- **CodeQL**: URL 来自反序列化的 message history 对象属性（如 `ImageUrl.url`），属于深层数据流，标准 source 定义未覆盖
- **Bandit**: 不分析 AI/ML 框架的 message history 处理流程

**How to Detect**:
1. 搜索 AI/ML 框架中的 URL 下载函数（`download_item`、`download_url`、`fetch_content`）
2. 检查 URL 是否来自用户提交的 message history 或 chat content
3. 确认是否有完整的 SSRF 防护：协议验证 + DNS 解析后 IP 检查 + 云元数据阻断 + 重定向验证
4. 特别关注 AI 框架中 `ImageUrl`、`AudioUrl`、`DocumentUrl` 等类型的 `url` 字段

**Similar Vulnerabilities**: CVE-2025-54381 (BentoML file upload SSRF), CVE-2025-65958 (Open WebUI retrieval SSRF)

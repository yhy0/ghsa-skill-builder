# Auth Bypass — Real-World Cases

7 个真实认证绕过漏洞案例，每个代表一种独特的绕过模式。

---

### Case 1: cobbler -- 异常处理返回可预测 fallback 导致共享密钥绕过 (CVE-2024-47533, CVSS 9.8)

**Root Cause**: `open()` 函数参数错误（binary mode 不接受 encoding 参数）导致始终抛出异常，`except` 块返回固定值 `-1` 作为共享密钥，攻击者可用 `-1` 作为密码登录。

**Source -> Sink 路径**:
- **Source**: XML-RPC `login(username, password)` 方法的 `login_password` 参数
- **Sink**: `self.__make_token("<DIRECT>")` -- 生成拥有完整权限的认证 token
- **Sanitization Gap**: `get_shared_secret()` 应返回随机密钥用于比对，但因 `open("file", "rb", encoding="utf-8")` 的参数冲突导致始终抛异常，返回固定值 `-1`。攻击者传入 `password=-1` 即可通过 `login_password == self.shared_secret` 校验。

**Vulnerable Code Pattern** (`cobbler/utils/__init__.py` + `cobbler/remote.py`):
```python
# cobbler/utils/__init__.py
def get_shared_secret() -> Union[str, int]:
    try:
        # BUG: "rb" (binary mode) 不接受 encoding 参数，始终抛出 TypeError
        with open("/var/lib/cobbler/web.ss", "rb", encoding="utf-8") as fd:
            data = fd.read()
    except Exception:
        return -1  # 始终执行此分支，返回可预测的固定值
    return str(data).strip()

# cobbler/remote.py
def login(self, login_user: str, login_password: str) -> str:
    if login_user == "":
        # self.shared_secret 始终为 -1，攻击者传入 password=-1 即可匹配
        if login_password == self.shared_secret:
            return self.__make_token("<DIRECT>")  # 获得完整管理权限
```

**Attack Path**:
1. 攻击者发现 cobbler XML-RPC 服务（默认端口 443/80）
2. 发送 `login("", -1)` 请求，空用户名触发 shared secret 认证路径
3. 由于 `get_shared_secret()` 始终返回 `-1`，密码比对通过
4. 获得完整管理权限的 token，可任意修改 cobbler 配置

**Why Standard Scanners Miss It**:
- CodeQL: 标准 taint 分析关注用户输入到危险函数的流向，不会追踪「函数返回值因异常而退化为固定值」这种语义 bug。异常处理中的 fallback 值不在标准 source 定义中。
- Bandit: 只会标记宽泛的 `except Exception` (B110)，但不会分析返回值的安全影响。不理解 fallback 值 `-1` 与后续认证比对的关联。

**How to Detect**:
1. **定位 Sink**: Grep `make_token|create_session|login_success|authenticate` -- 找到认证成功的关键函数
2. **回溯 Source**: 从认证比对 (`password == secret`) 向上追踪 secret 的来源函数
3. **验证 Sanitization**: 检查 secret 获取函数中的异常处理路径，确认 fallback 值是否可预测（`-1`, `None`, `""`, `0`）
4. **CodeQL 自定义查询方向**: 编写查询匹配「`except` 块中返回字面量 + 该返回值用于 `==` 比较」的模式

**Similar Vulnerabilities**: GHSA-5824-cm3x-3c38 (vyper nonreentrant lock), CVE-2019-5418 (Rails file content disclosure via exception handling)

---

### Case 2: sentry -- SAML SSO 身份确认逻辑缺陷导致用户冒充 (CVE-2025-22146, CVSS 9.1)

**Root Cause**: SAML SSO 身份关联时，`if op == "confirm" and self.user.is_authenticated` 检查的是「当前用户是否已认证」而非「当前用户是否就是待关联的目标用户」。由于 `and` 优先级高于 `or`，条件逻辑实际为 `(op == "confirm" and self.user.is_authenticated) or is_account_verified`，任何已认证用户都能将 SAML 身份关联到别人的账户。

**Source -> Sink 路径**:
- **Source**: SAML IdP 返回的身份断言 + POST 请求中的 `op` 参数
- **Sink**: `self.handle_attach_identity()` -- 将 SAML 身份绑定到目标用户
- **Sanitization Gap**: 仅检查 `self.user.is_authenticated`（当前 session 用户已登录），未验证 `self.user.id == self.request.user.id`（当前用户是否就是目标用户本人）

**Vulnerable Code Pattern** (`src/sentry/auth/helper.py`):
```python
def handle_unknown_identity(self, ...):
    # ...
    # BUG: is_authenticated 只证明"有人登录了"，不证明"登录的是目标用户"
    # 且因运算符优先级: (op == "confirm" and self.user.is_authenticated) or is_account_verified
    if op == "confirm" and self.user.is_authenticated or is_account_verified:
        auth_identity = self.handle_attach_identity()  # 将 SAML 身份绑定到 self.user

# 修复后:
    if op == "confirm" and (self.request.user.id == self.user.id) or is_account_verified:
        auth_identity = self.handle_attach_identity()
```

**Attack Path**:
1. 攻击者在同一 Sentry 实例上拥有自己的组织，并配置恶意 SAML IdP
2. 攻击者以自己的账户登录 Sentry（获得 `is_authenticated` 状态）
3. 通过恶意 IdP 发起 SAML 认证流程，目标指向受害者的 email 地址
4. 提交 `op=confirm`，由于 `self.user.is_authenticated` 为 True，身份关联操作执行
5. 攻击者的 SAML 身份被绑定到受害者账户，实现账户接管

**Why Standard Scanners Miss It**:
- CodeQL: 无法理解 `is_authenticated` 与「身份一致性验证」的语义差异。标准 auth check query 会认为 `is_authenticated` 已经是有效的认证检查。
- Bandit: 不检查业务逻辑错误，也不理解运算符优先级在认证条件中的安全影响。

**How to Detect**:
1. **定位 Sink**: Grep `attach_identity|link_identity|bind_account|associate_identity` -- 找到身份关联操作
2. **回溯 Source**: 检查触发条件中是否有 `is_authenticated` 检查
3. **验证 Sanitization**: 确认是否验证了「当前登录用户 == 待操作的目标用户」（`request.user.id == target_user.id`），而不仅仅是「有用户登录」
4. **CodeQL 自定义查询方向**: 匹配「`is_authenticated` check + identity binding 操作」但缺少「user identity equality check」的模式

**Similar Vulnerabilities**: CVE-2024-25128 (Flask-AppBuilder OpenID), CVE-2023-45683 (SAML account takeover in similar pattern)

---

### Case 3: modoboa -- Django REST Framework 视图缺失 permission_classes 导致未授权访问 (CVE-2023-2227, CVSS 9.1)

**Root Cause**: Django REST Framework 的 `APIView` 和 `ViewSet` 未显式声明 `permission_classes`，且项目的 `DEFAULT_PERMISSION_CLASSES` 配置允许未认证访问。敏感端点（系统参数、组件信息）对匿名用户完全开放。

**Source -> Sink 路径**:
- **Source**: 未认证的 HTTP GET 请求 `GET /api/v2/parameters/core/`
- **Sink**: `ParametersViewSet` / `ComponentsInformationAPIView` 返回的系统配置和敏感信息
- **Sanitization Gap**: 视图类未声明 `permission_classes`，DRF 使用全局默认设置，该项目默认允许未认证访问

**Vulnerable Code Pattern** (`modoboa/parameters/api/v2/viewsets.py` + `modoboa/core/api/v2/views.py`):
```python
# BEFORE (vulnerable) - modoboa/parameters/api/v2/viewsets.py
class ParametersViewSet(GetThrottleViewsetMixin, viewsets.ViewSet):
    """Parameter viewset."""
    lookup_value_regex = r"\w+"
    # BUG: 没有 permission_classes 声明，任何人都能访问
    serializer_class = None

# BEFORE (vulnerable) - modoboa/core/api/v2/views.py
class ComponentsInformationAPIView(APIView):
    """Retrieve information about installed components."""
    # BUG: 没有 permission_classes，暴露系统组件信息
    throttle_classes = [UserLesserDdosUser]

# AFTER (fixed)
class ParametersViewSet(GetThrottleViewsetMixin, viewsets.ViewSet):
    lookup_value_regex = r"\w+"
    permission_classes = [permissions.IsAuthenticated, IsSuperUser]  # 修复：要求认证 + 超级用户
```

**Attack Path**:
1. 攻击者发送 `GET /api/v2/parameters/core/` 到 modoboa 服务器
2. 无需任何认证，DRF 使用默认权限（AllowAny）
3. 服务器返回完整的系统参数配置，包含敏感信息
4. 攻击者利用泄露的配置信息进行进一步攻击

**Why Standard Scanners Miss It**:
- CodeQL: 标准 Django/DRF query 不检查「缺失 permission_classes」的情况，因为需要理解 DRF 的权限继承机制和项目级默认配置。
- Bandit: 不理解 DRF 框架的权限模型，无法识别「缺失声明」类型的漏洞（这是 omission 而非 commission）。

**How to Detect**:
1. **定位 Sink**: Grep `class.*APIView|class.*ViewSet|class.*GenericAPIView` -- 找到所有 DRF 视图
2. **检查认证声明**: 确认每个视图是否显式声明了 `permission_classes`
3. **验证全局配置**: 检查 `settings.py` 中 `REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']` 的值
4. **CodeQL 自定义查询方向**: 匹配继承 `APIView`/`ViewSet` 但未定义 `permission_classes` 属性的类，结合项目配置分析默认权限

**Similar Vulnerabilities**: CVE-2024-7039 (Open WebUI admin deletion via unprotected API), CVE-2023-36457 (similar DRF permission missing pattern)

---

### Case 4: Flask-AppBuilder -- OpenID Provider URL 未经白名单校验导致认证伪造 (CVE-2024-25128, CVSS 9.1)

**Root Cause**: OpenID 登录时，用户提交的表单中的 `openid` 字段被直接作为 Identity Provider URL 传给 `oid.try_login()`，未验证该 URL 是否属于预配置的合法 OpenID Provider 列表。攻击者可指定自己部署的恶意 IdP。

**Source -> Sink 路径**:
- **Source**: POST 表单字段 `form.openid.data`（用户提交的 OpenID provider URL）
- **Sink**: `self.appbuilder.sm.oid.try_login(form.openid.data, ...)` -- 使用用户指定的 URL 发起 OpenID 认证
- **Sanitization Gap**: 无白名单校验。表单中的 URL 直接传入 `try_login()`，攻击者可提交任意 IdP URL

**Vulnerable Code Pattern** (`flask_appbuilder/security/views.py`):
```python
# BEFORE (vulnerable)
def login_handler(self):
    form = LoginForm_oid()
    if form.validate_on_submit():
        session["remember_me"] = form.remember_me.data
        # BUG: form.openid.data 是用户直接提交的 URL，未经白名单校验
        return self.appbuilder.sm.oid.try_login(
            form.openid.data,  # 攻击者可提交恶意 IdP URL
            ask_for=self.oid_ask_for,
            ask_for_optional=self.oid_ask_for_optional,
        )

# AFTER (fixed)
def login_handler(self):
    form = LoginForm_oid()
    if form.validate_on_submit():
        session["remember_me"] = form.remember_me.data
        # 修复：通过 provider name 查找预配置的 URL
        identity_url = self.appbuilder.sm.get_oid_identity_url(form.openid.data)
        if identity_url is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        return self.appbuilder.sm.oid.try_login(
            identity_url,  # 使用白名单中的 URL
            ask_for=self.oid_ask_for,
            ask_for_optional=self.oid_ask_for_optional,
        )
```

**Attack Path**:
1. 攻击者部署一个恶意 OpenID Provider 服务
2. 向目标 Flask-AppBuilder 应用提交登录表单，`openid` 字段设为恶意 IdP 的 URL
3. 应用向恶意 IdP 发起 OpenID 认证请求
4. 恶意 IdP 返回伪造的身份断言（声称用户是管理员）
5. 应用信任该断言，授予攻击者管理员权限

**Why Standard Scanners Miss It**:
- CodeQL: 标准 SSRF query 可能标记 URL 使用，但 OpenID 认证流程中「使用外部 URL」是预期行为，难以区分合法与恶意使用。需要理解「白名单校验」的语义。
- Bandit: 不分析 OpenID/OAuth 认证流程的安全性，也不理解表单数据到 IdP URL 的数据流。

**How to Detect**:
1. **定位 Sink**: Grep `try_login|authorize_redirect|fetch_access_token` -- 找到 OAuth/OpenID 认证发起点
2. **回溯 Source**: 检查传入的 provider URL / redirect_uri 是否来自用户输入
3. **验证 Sanitization**: 确认 URL 是否经过白名单校验（与预配置的 provider 列表比对）
4. **CodeQL 自定义查询方向**: 匹配「form input -> OAuth/OpenID try_login URL 参数」但中间无白名单查找操作的数据流

**Similar Vulnerabilities**: CVE-2024-37300 (oauthenticator identity_provider bypass), CVE-2023-45683 (OAuth redirect_uri manipulation)

---

### Case 5: salt -- 事件总线缺失标签过滤允许 Minion 注入任意事件 (CVE-2025-22239, CVSS 8.1)

**Root Cause**: Salt Master 的 `_minion_event` 方法接受已认证 Minion 发送的事件并直接转发到 Master 事件总线，但未对事件标签（tag）进行任何过滤。Minion 可以伪造 `salt/job/*/publish` 等高权限事件标签，在其他 Minion 上执行任务。

**Source -> Sink 路径**:
- **Source**: 已认证 Minion 通过 `_minion_event` 方法提交的 `load["events"]` 列表
- **Sink**: `self.event.fire_event(event_data, event["tag"])` -- 将事件发布到 Master 事件总线
- **Sanitization Gap**: 事件标签未经任何黑名单/白名单校验，Minion 可以使用 `salt/job/*/publish` 等保留标签

**Vulnerable Code Pattern** (`salt/daemons/masterapi.py`):
```python
# BEFORE (vulnerable)
def _minion_event(self, load):
    # ... 验证 minion 身份后 ...
    for event in load.get("events", []):
        if "data" in event:
            event_data = event["data"]
        else:
            event_data = event
        # BUG: 直接将事件发布到总线，未检查 tag 是否为保留/高权限标签
        self.event.fire_event(event_data, event["tag"])

# AFTER (fixed)
MINION_EVENT_BLACKLIST = (
    "salt/job/*/publish",
    "salt/job/*/new",
    "salt/job/*/return",
    "salt/key",
    "salt/cloud/*",
    "salt/run/*",
    "salt/cluster/*",
    "salt/wheel/*/new",
    "salt/wheel/*/return",
)

def _minion_event(self, load):
    for event in load.get("events", []):
        if not valid_minion_tag(event["tag"]):
            log.warning("Filtering blacklisted event tag %s", event["tag"])
            continue
        self.event.fire_event(event_data, event["tag"])
```

**Attack Path**:
1. 攻击者获得一个合法 Minion 的密钥（或控制一个 Minion）
2. 构造事件列表，使用 `salt/job/{jid}/publish` 标签
3. 通过 `_minion_event` 方法发送到 Master
4. Master 将事件原样发布到事件总线
5. 其他 Minion 收到伪造的 job publish 事件，执行攻击者指定的命令

**Why Standard Scanners Miss It**:
- CodeQL: 消息总线/事件系统的标签伪造不在标准安全 query 覆盖范围内。需要理解事件标签的权限语义。
- Bandit: 不分析消息总线安全性，也不理解事件标签的权限含义。

**How to Detect**:
1. **定位 Sink**: Grep `fire_event|publish_event|emit|dispatch` -- 找到事件发布函数
2. **回溯 Source**: 检查事件的 tag/type/topic 是否来自外部输入（如 API 参数、消息负载）
3. **验证 Sanitization**: 确认事件标签是否经过白名单/黑名单过滤，低权限实体是否能发布高权限标签
4. **CodeQL 自定义查询方向**: 匹配「external input -> event tag -> fire_event()」但中间无标签校验的数据流

**Similar Vulnerabilities**: CVE-2025-22236 (Salt minion event bus authorization bypass), CVE-2020-11651 (Salt unauthenticated access to salt-master event bus)

---

### Case 6: litellm -- 路由权限映射过于宽泛导致权限提升 (CVE-2025-0628, CVSS 8.1)

**Root Cause**: `internal_user_viewer` 角色的路由权限列表中包含 `/user` 前缀路由，该前缀意外匹配了 `/users/list` 和 `/users/get_users` 等管理员端点。低权限用户获得的 API Key 可以访问所有管理功能。

**Source -> Sink 路径**:
- **Source**: `internal_user_viewer` 角色用户登录后获得的 API Key
- **Sink**: `/users/list`, `/users/get_users` 等管理员端点
- **Sanitization Gap**: 路由权限列表中 `/user` 路由过于宽泛，作为前缀匹配了所有用户管理端点。同时 `/user/filter/ui` 等端点未被正确归类到低权限路由中

**Vulnerable Code Pattern** (`litellm/proxy/_types.py`):
```python
class LiteLLMRoutes(enum.Enum):
    # 低权限用户（internal_user_viewer）可访问的路由
    openai_routes = [
        "/model_group/info",
        "/health",
        "/key/list",
        # 修复后增加: "/user/filter/ui",
    ]

    # 需要管理员权限的路由
    management_routes = [
        "/key/info",
        "/config",
        "/spend",
        "/user",       # BUG: 此路由被错误归类，且前缀匹配导致 /users/* 也被覆盖
        "/model/info",
        "/v2/model/info",
        "/v2/key/info",
    ]
```

**Attack Path**:
1. 攻击者以 `internal_user_viewer` 角色登录 LiteLLM Proxy
2. 获得该角色对应的 API Key
3. 发现 API Key 可以访问 `/users/list` 和 `/users/get_users` 等管理端点
4. 获取所有用户信息，包括管理员的敏感数据
5. 利用泄露信息进一步提升权限至 PROXY ADMIN

**Why Standard Scanners Miss It**:
- CodeQL: 路由到角色的映射关系通常以数据结构（enum、dict、list）形式定义，标准 query 不分析路由权限配置的正确性。
- Bandit: 不理解 RBAC 路由配置的语义，无法判断路由分组是否正确。

**How to Detect**:
1. **定位 Sink**: Grep `routes|permissions|allowed_paths|role_routes` -- 找到路由权限映射定义
2. **回溯 Source**: 检查不同角色可访问的路由列表
3. **验证 Sanitization**: 确认是否存在路由前缀重叠（如 `/user` 和 `/users`），低权限角色的路由是否意外包含高权限端点
4. **CodeQL 自定义查询方向**: 编写静态分析规则检查路由权限定义中的前缀重叠和角色分组不当

**Similar Vulnerabilities**: CVE-2024-7039 (Open WebUI admin deletion via API), CVE-2023-2227 (modoboa missing permission_classes)

---

### Case 7: oauthenticator -- 框架升级导致配置项优先级变化绕过身份提供者限制 (CVE-2024-37300, CVSS 8.1)

**Root Cause**: JupyterHub 5.0 改变了 `allow_all` 和 `identity_provider` 配置项的优先级关系。在 5.0 之前，`identity_provider` 的限制优先于 `allow_all`；升级后，`allow_all=True` 直接覆盖 `identity_provider` 的域名限制，导致任何身份提供者的用户都能登录。

**Source -> Sink 路径**:
- **Source**: 任意 Globus 身份提供者的用户认证请求
- **Sink**: `check_allowed()` 返回 `True`，允许用户登录 JupyterHub
- **Sanitization Gap**: `identity_provider` 域名检查原本在 `check_allowed()` 的早期执行，但 JupyterHub 5.0 将 `allow_all` 的检查提前（在父类 `super().check_allowed()` 中），导致域名限制被跳过

**Vulnerable Code Pattern** (`oauthenticator/globus.py`):
```python
# BEFORE (vulnerable - JupyterHub 5.0+ 下的行为)
async def check_allowed(self, username, auth_model):
    if auth_model is None:
        return True
    # identity_provider 检查在最前面...
    if self.identity_provider:
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        user_domain = user_info.get(self.username_claim).split('@', 1)[-1]
        if user_domain != self.identity_provider:
            raise web.HTTPError(403, message)
    # ...但 super().check_allowed() 在 JupyterHub 5.0 中当 allow_all=True 时直接返回 True
    # 导致 identity_provider 限制被绕过
    if await super().check_allowed(username, auth_model):
        return True

# AFTER (fixed) - 将 identity_provider 检查移到 check_blocked_users() 中
async def check_blocked_users(self, username, authentication):
    """在 allow 检查之前执行 block 检查"""
    if self.identity_provider:
        user_info = authentication["auth_state"][self.user_auth_state_key]
        user_domain = user_info.get(self.username_claim).split('@', 1)[-1]
        if user_domain != self.identity_provider:
            raise web.HTTPError(403, message)
    return super().check_blocked_users(username, authentication)

async def check_allowed(self, username, auth_model):
    if auth_model is None:
        return True
    if await super().check_allowed(username, auth_model):
        return True
    # ...
```

**Attack Path**:
1. 目标 JupyterHub 配置了 `identity_provider = "university.edu"` + `allow_all = True`
2. JupyterHub 从 4.x 升级到 5.0
3. 攻击者使用非 `university.edu` 的 Globus 账户尝试登录
4. `check_allowed()` 中 `super().check_allowed()` 因 `allow_all=True` 直接返回 True
5. `identity_provider` 的域名限制被跳过，攻击者成功登录

**Why Standard Scanners Miss It**:
- CodeQL: 无法检测框架版本升级导致的语义变化。`check_allowed` 方法的调用链跨越子类和父类，需要理解继承和方法覆盖的语义。
- Bandit: 不分析 OAuth/SSO 配置项的优先级关系，也不跟踪框架升级带来的行为变更。

**How to Detect**:
1. **定位 Sink**: Grep `check_allowed|check_authorization|is_authorized` -- 找到权限检查函数
2. **回溯 Source**: 检查是否有多个配置项共同控制访问（如 `allow_all` + `identity_provider`）
3. **验证 Sanitization**: 确认限制性配置（deny/restrict）是否在允许性配置（allow）**之前**执行；检查父类方法的行为是否因升级而改变
4. **CodeQL 自定义查询方向**: 分析认证方法中 `super()` 调用的位置，检查限制条件是否在 `super()` 调用之后（可能被跳过）

**Similar Vulnerabilities**: CVE-2024-25128 (Flask-AppBuilder OpenID provider bypass), CVE-2020-15233 (OAuthenticator redirect_uri validation bypass)

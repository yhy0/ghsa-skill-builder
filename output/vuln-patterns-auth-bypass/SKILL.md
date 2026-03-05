---
name: vuln-patterns-auth-bypass
description: "Use when auditing Python code involving authentication flows, permission checks, access control logic, JWT/token validation, decorator-based protection, or SSO/OAuth identity binding. Covers CWE-285/287/863. Keywords: authentication bypass, authorization bypass, access control, permission check, JWT verification, token validation, decorator, middleware auth, privilege escalation, permission_classes, SAML, OpenID"
---

# Auth Bypass Vulnerability Patterns (CWE-285/287/863)

当审计 Python 代码中涉及认证流程、权限检查、访问控制逻辑时加载此 Skill。

## Detection Strategy

通用检测模型，适用于此类漏洞的所有变体。

**Sources（攻击入口）：**
- HTTP 请求参数/头部（用户名、密码、token）
- SAML/OAuth/OpenID 响应中的身份断言
- API Key / Session Cookie
- 消息总线事件（如 Salt minion 事件）
- SSO IdP 返回的用户标识

**Sinks（受保护资源/操作）：**
- 管理面板 API 端点（用户管理、系统配置）
- XML-RPC / REST API 的特权操作
- 系统参数/配置信息读取接口
- 身份关联操作（account linking, identity binding）
- 事件总线上的任务发布/执行

**Sanitization（认证/授权屏障）：**
- 认证装饰器（`@login_required`, `@permission_required`）
- Django REST Framework `permission_classes`（`IsAuthenticated`, `IsAdminUser`）
- 共享密钥校验（shared secret comparison）
- SAML 签名验证 + 身份确认逻辑
- OpenID Provider URL 白名单校验
- RBAC 角色/权限检查中间件
- 事件标签黑名单/白名单过滤
- CSRF Token 校验（尤其在 SSO/OAuth 身份关联场景中防止跨站身份绑定）

**检测路径：**
1. 搜索受保护的资源/操作端点（API view、RPC method、event handler）
2. 检查是否有认证/授权屏障保护（装饰器、permission_classes、手动校验）
3. 验证屏障是否可被绕过：
   - 异常处理中的 fallback 值是否可预测？
   - 条件判断逻辑是否存在运算符优先级/短路求值问题？
   - 视图类是否遗漏了 permission_classes 声明？
   - 用户输入是否直接作为身份提供者 URL 使用？
   - 配置优先级变更是否导致限制条件失效？
   - 路由权限映射是否过于宽泛？
   - 事件/消息总线是否缺少标签/类型过滤？
4. 若无屏障或屏障可被绕过 -> 标记为候选漏洞

## Detection Checklist

- [ ] **异常处理返回值审计** (CWE-287)：`except` 块中是否返回可预测的 fallback 值（如 `-1`, `None`, `""`），且该值可被攻击者用于绕过后续校验？
- [ ] **条件表达式优先级审计** (CWE-287)：`if A and B or C` 类型的复合条件是否因缺少括号导致逻辑与预期不符？（`and` 优先级高于 `or`）
- [ ] **DRF 视图 permission_classes 审计** (CWE-285)：所有 `APIView`/`ViewSet` 是否显式声明了 `permission_classes`？未声明时 DRF 默认使用 `DEFAULT_PERMISSION_CLASSES`，可能为 `AllowAny`。
- [ ] **SSO/OAuth identity binding 审计** (CWE-287)：身份关联操作是否验证了「当前登录用户 == 待关联用户」？`is_authenticated` 不等于「是本人」。
- [ ] **OpenID/OAuth Provider URL 白名单审计** (CWE-863)：身份提供者 URL 是否来自预配置白名单？用户是否能直接提交任意 IdP URL？
- [ ] **路由权限映射审计** (CWE-285)：API 路由到角色的映射是否使用前缀匹配（如 `/user` 匹配 `/user/admin`）？低权限角色的路由列表是否包含高权限端点？
- [ ] **配置优先级审计** (CWE-863)：当多个配置项共同控制访问时（如 `allow_all` + `identity_provider`），升级框架版本后优先级是否发生变化？
- [ ] **事件总线标签过滤审计** (CWE-285)：消息/事件处理器是否校验事件标签/类型？已认证的低权限实体是否能注入高权限事件？

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **异常处理返回 fallback 但后续有二次校验** -- 如果 fallback 值在被使用前经过了额外的有效性检查（如 `if secret != -1 and secret == input`），则不是漏洞
- **视图未设 permission_classes 但项目级 DEFAULT_PERMISSION_CLASSES 已配置为 IsAuthenticated** -- 需要检查 settings.py 中的 REST_FRAMEWORK 配置
- **内部 API 仅绑定 localhost** -- 如果端点仅监听 127.0.0.1 且无代理转发，风险较低
- **测试/开发环境的认证豁免** -- 如 `DEBUG=True` 时跳过认证，需确认生产环境不受影响

以下模式**需要深入检查**：
- **`except Exception: return default_value`** -- 宽泛异常捕获 + 返回默认值是高危模式，必须追踪 default_value 的使用方式
- **`if user.is_authenticated`** -- 仅检查认证状态而不验证身份（是否是正确的用户），在 account linking 场景中可能导致冒充
- **`permission_classes = []` 或 `permission_classes = [AllowAny]`** -- 显式移除权限检查，需确认是否为公开接口
- **框架版本升级后的行为变更** -- `allow_all` 等配置项的语义可能因框架升级而改变
- **前缀路由匹配** -- `/user` 路由权限是否意外覆盖了 `/user/admin` 等子路径

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

# Go Auth Bypass — Real-World Cases

7 个真实 Go 认证/授权绕过漏洞案例，每个代表一种独特的绕过模式。

---

### Case 1: Rancher -- Proxy API 绕过云凭证访问控制 (CVE-2021-25320, CVSS 10.0)

**Root Cause**: Rancher 的 proxy API (`/v3/clusters/:id/proxy`) 允许已认证用户通过代理转发请求访问下游集群的 cloud credential，而未验证用户对该 cloud credential 的访问权限。

**Source -> Sink 路径**:
- **Source**: 已认证用户通过 Rancher proxy API 发送的 HTTP 请求
- **Sink**: 下游集群的 cloud credential（AWS/GCP/Azure 密钥）
- **Sanitization Gap**: Proxy 层仅验证用户对集群的访问权限，未验证对 cloud credential 资源的细粒度权限

**Vulnerable Code Pattern**:
```go
// proxy handler 仅检查集群访问权限
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    clusterID := mux.Vars(r)["clusterID"]
    // 仅验证用户有权访问该集群
    if !h.canAccessCluster(r.Context(), clusterID) {
        http.Error(w, "forbidden", 403)
        return
    }
    // BUG: 直接转发请求到下游，未检查用户对目标资源的权限
    h.proxy.ServeHTTP(w, r)
}
```

**Attack Path**:
1. 攻击者拥有对某个 Rancher 管理集群的低权限访问
2. 通过 proxy API 转发请求到下游集群的 cloud credential API
3. 获取 AWS/GCP/Azure 密钥，实现特权提升

**How to Detect**:
1. Grep `proxy.*handler\|proxyRequest\|ServeHTTP` 找到代理处理函数
2. 检查代理层是否仅验证了粗粒度权限（集群级）而非细粒度权限（资源级）
3. 确认代理是否透传了用户的 `Authorization` header 还是使用了服务端 credential

---

### Case 2: Kyverno -- Policy apiCall 跨 Namespace 权限提升 (CVE-2026-22039, CVSS 10.0)

**Root Cause**: Kyverno 策略引擎的 `apiCall` 功能使用 Kyverno ServiceAccount 的集群级权限执行 API 调用，而非使用触发策略的用户权限。低权限 namespace 用户可以通过创建含 `apiCall` 的 policy 访问其他 namespace 的资源。

**Source -> Sink 路径**:
- **Source**: 用户在自己的 namespace 创建的 Kyverno ClusterPolicy/Policy
- **Sink**: Kubernetes API 调用（使用 Kyverno SA 的 cluster-admin 权限）
- **Sanitization Gap**: `apiCall` 未限制可访问的 API 路径和 namespace

**Vulnerable Code Pattern**:
```go
// Kyverno apiCall 使用自身的 ServiceAccount 执行
func (e *engine) executeAPICall(ctx context.Context, call kyverno.APICall) (interface{}, error) {
    // BUG: 使用 Kyverno 的 cluster-admin SA，而非用户的权限
    client := e.client // Kyverno 的高权限 client
    result, err := client.Resource(call.URLPath).Get(ctx, metav1.GetOptions{})
    return result, err
}
```

**Attack Path**:
1. 低权限用户在自己的 namespace 创建 Kyverno Policy
2. Policy 包含 `apiCall` 引用其他 namespace 的 Secret
3. Kyverno 使用自身的 cluster-admin 权限执行 API 调用
4. Secret 内容通过 policy context 变量泄露给攻击者

**How to Detect**:
1. Grep `apiCall\|APICall\|serviceAccountName` 查找策略引擎的外部调用
2. 检查 API 调用是否使用了策略引擎的 SA 而非用户的 SA
3. 确认是否有 namespace/resource 范围限制

---

### Case 3: Mattermost -- OAuth State Token 验证缺失导致认证绕过 (CVSS 10.0)

**Root Cause**: Mattermost 在 OpenID Connect 认证流程中未正确验证 OAuth state token，攻击者可以伪造 state 参数劫持认证回调。

**Source -> Sink 路径**:
- **Source**: OAuth 回调 URL 中的 `state` 和 `code` 参数
- **Sink**: 用户 session 创建（`createSession()`）
- **Sanitization Gap**: `state` 参数未与 session 中存储的值进行比较，或比较逻辑存在缺陷

**Vulnerable Code Pattern**:
```go
func (a *App) completeOAuthLogin(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")
    code := r.URL.Query().Get("code")

    // BUG: state token 验证不完整
    // 未正确验证 state 与 session 中存储的 CSRF token 匹配
    oauthState, err := a.GetOAuthStateToken(state)
    if err != nil {
        // 错误处理不当，可能 fallthrough
    }

    token, err := a.exchangeCode(code)
    // ... 创建 session
}
```

**Attack Path**:
1. 攻击者发起 OAuth 流程获取自己的 `state` token
2. 诱导受害者访问包含攻击者 `state` 的 OAuth 回调 URL
3. 由于 state 验证不完整，受害者的认证 code 与攻击者的 state 关联
4. 攻击者使用该关联完成认证，获取受害者的 session

**How to Detect**:
1. Grep `oauth.*state\|state.*token\|csrf.*token` 查找 OAuth state 处理
2. 验证 state 是否与 session 中的随机值严格比较
3. 检查 state 验证失败时是否正确拒绝请求（而非 fallthrough）

---

### Case 4: Grafana -- Incorrect Privilege Assignment 导致权限提升 (CVE-2022-31107, CVSS 10.0)

**Root Cause**: Grafana 的 OAuth 身份关联逻辑错误，当外部 OAuth 账户的 email 与 Grafana 内部账户匹配时，OAuth 登录自动获得内部账户的权限，包括 admin 权限。

**Source -> Sink 路径**:
- **Source**: OAuth IdP 返回的 email claim
- **Sink**: Grafana 内部用户的角色/权限分配
- **Sanitization Gap**: 仅通过 email 匹配就继承完整权限，未验证 OAuth 身份与内部账户的绑定关系

**Vulnerable Code Pattern**:
```go
func (s *SocialService) lookupUser(ctx context.Context, info *social.BasicUserInfo) (*user.User, error) {
    // 通过 email 查找内部用户
    existingUser, err := s.userService.GetByEmail(ctx, info.Email)
    if err == nil {
        // BUG: 直接返回内部用户，继承其所有权限
        // 未验证 OAuth 身份是否已与该用户绑定
        return existingUser, nil
    }
    // 创建新用户...
}
```

**Attack Path**:
1. 攻击者在 OAuth IdP 中注册，使用与 Grafana admin 相同的 email
2. 通过 OAuth 登录 Grafana
3. Grafana 通过 email 匹配找到 admin 内部账户
4. 攻击者获得 admin 完整权限

**How to Detect**:
1. Grep `GetByEmail\|lookupUser\|findUser.*email` 查找基于 email 的用户查找
2. 检查 OAuth 登录后是否有额外的身份绑定验证
3. 确认是否区分了「已绑定 OAuth」和「仅 email 匹配」

---

### Case 5: Rancher -- Webhook 升级期间被删除导致 Admission 绕过 (CVSS 10.0)

**Root Cause**: Rancher 升级过程中，admission webhook 被临时删除再重建。在此窗口期内，所有需要 webhook 验证的操作都会被放行，包括特权提升操作。

**Source -> Sink 路径**:
- **Source**: 升级窗口期内的 Kubernetes API 请求
- **Sink**: 绕过 webhook 直接执行的特权操作（如 `ClusterRoleBinding` 创建）
- **Sanitization Gap**: 升级脚本先删除旧 webhook 再部署新版本，中间无替代验证

**Vulnerable Code Pattern**:
```go
// 升级脚本
func upgrade(ctx context.Context) error {
    // Step 1: 删除旧 webhook
    err := client.Delete(ctx, "rancher-webhook", metav1.DeleteOptions{})
    // BUG: 此时到 Step 3 之间，webhook 不存在，所有请求被放行

    // Step 2: 部署新版本（可能需要数分钟）
    err = deployNewVersion(ctx)

    // Step 3: 新 webhook 注册
    err = registerWebhook(ctx)
    return err
}
```

**Attack Path**:
1. 监控 Rancher 集群的升级窗口
2. 在 webhook 被删除后、新版本部署前发送特权操作请求
3. 请求绕过 admission webhook 直接被 API server 执行
4. 获取 cluster-admin 权限

**How to Detect**:
1. Grep `Delete.*webhook\|deleteWebhook\|removeAdmission` 查找 webhook 删除操作
2. 检查升级流程是否存在 webhook 空窗期
3. 确认是否有 failClose 策略（webhook 不存在时拒绝所有请求）

---

### Case 6: Authelia -- URI 解析差异导致认证绕过 (CVSS 10.0)

**Root Cause**: Authelia 与 nginx 在解析 malformed request URI 时存在行为差异。nginx 转发的 URI 经过规范化，但 Authelia 使用原始 URI 进行权限判断，导致路径不匹配，绕过认证。

**Source -> Sink 路径**:
- **Source**: 畸形 HTTP 请求 URI（包含双斜杠、编码字符等）
- **Sink**: 未经认证的后端资源访问
- **Sanitization Gap**: Authelia 与 nginx 对 URI 规范化的不一致

**Vulnerable Code Pattern**:
```go
func (p *AuthzProvider) Authorize(r *http.Request) (bool, error) {
    // 使用 X-Original-URL header 中的原始 URI
    originalURL := r.Header.Get("X-Original-URL")

    // BUG: 使用未规范化的 URI 匹配 ACL 规则
    // nginx 可能已规范化了实际路径，但 Authelia 看到的是原始路径
    for _, rule := range p.rules {
        if rule.Match(originalURL) {
            return rule.Policy == "allow", nil
        }
    }
    return false, nil
}
```

**Attack Path**:
1. 构造畸形 URI（如 `//protected/resource` 或 `/%2e%2e/protected`）
2. nginx 规范化后转发到后端的 `/protected/resource`
3. 但 Authelia 收到的 `X-Original-URL` 是原始畸形 URI
4. 畸形 URI 不匹配保护规则，Authelia 放行

**How to Detect**:
1. Grep `X-Original-URL\|X-Forwarded-URI\|OriginalURL` 查找 URI 转发
2. 检查认证代理是否使用规范化后的 URI 进行匹配
3. 测试双斜杠、编码字符、大小写变体是否产生不同的认证结果

---

### Case 7: KubeVirt -- 特权提升允许容器逃逸 (CVSS 10.0)

**Root Cause**: KubeVirt 的 `virt-handler` 组件以特权模式运行，且未正确限制用户对 VMI（VirtualMachineInstance）的操作权限。攻击者可利用 VMI 的 `hostDisk` 或 `hostPCI` 功能逃逸到宿主机。

**Source -> Sink 路径**:
- **Source**: 用户创建的 VMI spec（包含 `hostDisk`、`hostPCI` 等特权配置）
- **Sink**: 宿主机资源的直接访问
- **Sanitization Gap**: Admission webhook 未正确限制 `hostDisk`/`hostPCI` 的使用，或 RBAC 未限制创建此类 VMI 的权限

**Vulnerable Code Pattern**:
```go
// VMI admission webhook 未拒绝特权配置
func (v *VMIAdmitter) Admit(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
    vmi := &v1.VirtualMachineInstance{}
    json.Unmarshal(ar.Request.Object.Raw, vmi)

    // BUG: 未检查 hostDisk/hostPCI 等特权配置
    // 任何有权创建 VMI 的用户都能使用这些功能
    return &admissionv1.AdmissionResponse{Allowed: true}
}
```

**Attack Path**:
1. 攻击者有权在 namespace 中创建 VMI
2. 创建 VMI spec 包含 `hostDisk: {path: "/", type: DiskOrCreate}`
3. VM 启动后挂载宿主机根文件系统
4. 在 VM 中修改宿主机文件实现逃逸

**How to Detect**:
1. Grep `hostDisk\|hostPCI\|hostNetwork\|privileged` 查找特权配置
2. 检查 admission webhook 是否限制了这些特权功能的使用
3. 确认 RBAC 是否区分了「创建普通 VMI」和「创建特权 VMI」的权限

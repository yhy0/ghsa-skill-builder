# Go Crypto/TLS — Real-World Cases

7 个真实 Go 密码学/TLS 漏洞案例，每个代表一种独特的验证绕过模式。

---

### Case 1: Terraform Provider SendGrid -- TLS Session Resumption 绕过 CA Trust Store (CVE-2026-XXXX, CVSS 10.0)

**Root Cause**: Go 的 TLS session resumption 机制在 CA trust store 被更新后，仍可能使用旧的 session ticket 恢复 TLS 连接，而不重新验证服务器证书。当管理员撤销某个 CA 后，使用旧 session ticket 的连接仍然成功。

**Source -> Sink 路径**:
- **Source**: TLS session ticket（缓存的 TLS 会话状态）
- **Sink**: HTTPS 连接建立（跳过证书验证）
- **Sanitization Gap**: Session resumption 不重新检查 CA trust store 的更新

**Vulnerable Code Pattern**:
```go
// 默认的 http.Client 启用了 TLS session cache
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            // 默认启用 session ticket，可能导致绕过
            // 修复: 在 CA 更新时清空 session cache
            // SessionTicketsDisabled: true, // 或手动管理 ClientSessionCache
        },
    },
}
```

**Attack Path**:
1. 攻击者获取受害域名的 TLS 证书（通过已泄露的 CA）
2. 管理员发现并从 trust store 移除该 CA
3. 但已有的 TLS session ticket 仍然有效
4. 攻击者利用 session resumption 绕过新的 CA 信任限制

**How to Detect**:
1. Grep `TLSClientConfig\|tls.Config\|SessionTicket` 查找 TLS 配置
2. 检查 CA trust store 更新流程是否清空了 session cache
3. 确认是否有 `ClientSessionCache` 的主动管理

---

### Case 2: SSOReady -- SAML XML 差异化解析导致签名绕过 (CVE-2024-XXXX, CVSS 9.8)

**Root Cause**: SSOReady 在验证 SAML Response 的 XML 签名时，签名验证库和断言提取库使用了不同的 XML 解析器。攻击者可构造特殊的 XML 文档，使签名验证通过但断言提取获取到不同的内容。

**Source -> Sink 路径**:
- **Source**: IdP 返回的 SAML Response XML
- **Sink**: 用户身份断言的提取和信任
- **Sanitization Gap**: XML 签名验证和断言提取使用不同的 XML parser

**Vulnerable Code Pattern**:
```go
func validateSAMLResponse(samlResp []byte) (*Assertion, error) {
    // Step 1: 验证 XML 签名（使用 parser A）
    err := xmldsig.Verify(samlResp, idpCert)
    if err != nil {
        return nil, err
    }

    // Step 2: 提取断言（使用 parser B）
    // BUG: 两个 parser 对同一 XML 的解析结果可能不同
    // 攻击者利用解析差异注入恶意断言
    assertion, err := extractAssertion(samlResp)
    return assertion, err
}
```

**Attack Path**:
1. 获取合法的 SAML Response（包含有效签名）
2. 在 XML 中插入注释或命名空间前缀，使两个 parser 解析不同的子树
3. Parser A 验证签名通过（看到原始断言）
4. Parser B 提取断言时获取到攻击者注入的恶意断言

**How to Detect**:
1. Grep `xmldsig\|saml\|Verify.*XML\|parseAssertion` 查找 SAML 处理
2. 检查签名验证和断言提取是否使用同一个已验证的 DOM
3. 确认 XML canonicalization（C14N）是否正确应用

---

### Case 3: Helm -- 不安全 TLS 默认配置 (CVE-2023-25165, CVSS 9.8)

**Root Cause**: Helm 在连接 chart 仓库时，某些场景下的 TLS 配置使用了 `InsecureSkipVerify: true`，或未正确加载 CA 证书，导致 MITM 攻击风险。

**Source -> Sink 路径**:
- **Source**: Helm chart 仓库的 HTTPS 连接
- **Sink**: 下载的 chart 内容（未经证书验证的连接可被篡改）
- **Sanitization Gap**: `InsecureSkipVerify: true` 或 CA pool 配置不当

**Vulnerable Code Pattern**:
```go
func newRegistryClient(opts ...RegistryClientOption) (*RegistryClient, error) {
    tlsConfig := &tls.Config{
        // BUG: 某些路径下 InsecureSkipVerify 被设为 true
        InsecureSkipVerify: opts.Insecure,
    }
    // 用户可能不知道 --insecure-skip-tls-verify 的安全影响
    transport := &http.Transport{TLSClientConfig: tlsConfig}
    return &RegistryClient{client: &http.Client{Transport: transport}}, nil
}
```

**Attack Path**:
1. 受害者使用 `--insecure-skip-tls-verify` 连接 Helm 仓库（常见于自签名证书环境）
2. 攻击者在网络中执行 MITM
3. 拦截 chart 下载请求，返回恶意 chart
4. 受害者安装被篡改的 chart，可能包含恶意容器镜像或 hook

**How to Detect**:
1. Grep `InsecureSkipVerify` 查找所有出现位置
2. 检查 `InsecureSkipVerify` 是否有配置开关且默认为 false
3. 确认文档是否警告了安全影响

---

### Case 4: Mattermost -- OAuth Token Exchange 验证不完整 (CVSS 10.0)

**Root Cause**: Mattermost 在 OAuth code exchange 阶段未正确验证 token 的完整性，攻击者可通过操纵 exchange 过程获取其他用户的访问令牌。

**Source -> Sink 路径**:
- **Source**: OAuth authorization code + state 参数
- **Sink**: 用户 session 创建
- **Sanitization Gap**: Token exchange response 的验证不完整

**Vulnerable Code Pattern**:
```go
func (a *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")

    // BUG: 未验证 state 与 session 中的值匹配
    token, err := oauthConfig.Exchange(r.Context(), code)
    if err != nil {
        // 错误处理
    }

    // 直接使用 token 而不验证其绑定
    userInfo, _ := getUserInfo(token.AccessToken)
    a.createSession(userInfo)
}
```

**Attack Path**:
1. 攻击者发起 OAuth 流程获取 authorization code
2. 将自己的 code 与受害者的 state 参数组合
3. 由于 state 验证缺失，exchange 成功
4. 攻击者获取与受害者关联的 session

**How to Detect**:
1. Grep `oauthConfig.Exchange\|OAuth.*callback\|handleOAuth` 查找 OAuth 回调
2. 检查 state 参数是否与 session 中的值严格比较
3. 确认 token exchange 后是否验证了 token 的 audience 和 subject

---

### Case 5: Traefik -- 证书验证配置错误导致 MITM (CVSS 8.5)

**Root Cause**: Traefik 作为反向代理在连接后端服务时，某些配置场景下未正确验证后端的 TLS 证书，允许 MITM 攻击者截获代理与后端之间的通信。

**Source -> Sink 路径**:
- **Source**: Traefik 到后端服务的 HTTPS 连接
- **Sink**: 后端返回的敏感数据（通过未验证的 TLS 连接）
- **Sanitization Gap**: `serversTransport` 的 `insecureSkipVerify` 默认或配置不当

**Vulnerable Code Pattern**:
```go
type ServersTransport struct {
    InsecureSkipVerify bool   `json:"insecureSkipVerify"`
    RootCAs           []string `json:"rootCAs"`
}

func (t *Transport) createTLSConfig(st ServersTransport) *tls.Config {
    return &tls.Config{
        InsecureSkipVerify: st.InsecureSkipVerify,
        RootCAs:            t.loadCAs(st.RootCAs),
    }
}
```

**Attack Path**:
1. Traefik 配置了 `insecureSkipVerify: true`（常见于内部服务间通信）
2. 攻击者在 Traefik 和后端之间执行 MITM
3. 拦截并篡改请求/响应数据
4. 窃取认证 token 或注入恶意响应

**How to Detect**:
1. Grep `insecureSkipVerify\|InsecureSkipVerify` 在配置文件和代码中
2. 检查默认值和文档建议
3. 确认生产环境是否使用了正确的 CA 配置

---

### Case 6: NeuVector -- Telemetry 发送器 MITM + DoS (CVSS 8.6)

**Root Cause**: NeuVector 的 telemetry 发送器在连接远程 telemetry 服务时未正确验证 TLS 证书，攻击者可通过 MITM 注入恶意 telemetry 配置导致 agent 行为异常。

**Source -> Sink 路径**:
- **Source**: MITM 攻击者控制的 telemetry 响应
- **Sink**: NeuVector agent 的配置更新
- **Sanitization Gap**: Telemetry HTTPS 连接使用 `InsecureSkipVerify: true`

**Vulnerable Code Pattern**:
```go
func sendTelemetry(endpoint string, data []byte) error {
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                // BUG: 跳过证书验证
                InsecureSkipVerify: true,
            },
        },
    }
    resp, err := client.Post(endpoint, "application/json", bytes.NewReader(data))
    return err
}
```

**Attack Path**:
1. 在 NeuVector 和 telemetry 服务之间执行 MITM
2. 拦截 telemetry 请求
3. 返回恶意配置导致 agent 异常
4. 或大量请求导致 DoS

**How to Detect**:
1. Grep `InsecureSkipVerify.*true` 查找跳过验证的位置
2. 特别检查与外部服务通信的 HTTP client
3. 确认是否使用了正确的 CA pool

---

### Case 7: sigstore/cosign -- 容器镜像签名验证绕过 (CVSS 8.0)

**Root Cause**: Cosign 在验证容器镜像签名时，某些条件下的策略评估可被绕过。攻击者可推送未签名或错误签名的镜像，绕过 admission controller 的签名检查。

**Source -> Sink 路径**:
- **Source**: 容器镜像 + 签名（来自 registry）
- **Sink**: Kubernetes admission decision（allow/deny 部署）
- **Sanitization Gap**: 签名策略评估逻辑中的边缘情况

**Vulnerable Code Pattern**:
```go
func verifyImageSignature(image string, policy Policy) (bool, error) {
    signatures, err := cosign.FetchSignatures(image)
    if err != nil {
        // BUG: 某些错误被视为 "no signatures" 而非 "verification failed"
        if isNotFoundError(err) {
            // 应该拒绝，但某些策略配置下可能放行
            return policy.AllowUnsigned, nil
        }
        return false, err
    }
    return verifySignatures(signatures, policy.PublicKey)
}
```

**Attack Path**:
1. 推送镜像到 registry，不附加签名
2. 或附加无效签名使 Fetch 返回特定错误
3. 错误被视为 "not found" 而非 "invalid"
4. 如果策略允许未签名镜像（默认或配置错误），镜像被部署

**How to Detect**:
1. Grep `cosign.Verify\|FetchSignatures\|verifyImage` 查找签名验证
2. 检查错误处理路径（not found vs invalid vs network error）
3. 确认默认策略是否为 deny（拒绝未签名镜像）

# Go Information Disclosure — Real-World Cases

7 个真实 Go 信息泄露漏洞案例，每个代表一种独特的泄露模式。

---

### Case 1: Rancher -- Cluster Template Answers 明文存储 Cloud Credential (CVE-2021-36782, CVSS 10.0)

**Root Cause**: Rancher 在 cluster template 的 answers 字段中以明文存储 cloud provider 的 credentials（AWS Secret Key、Azure Client Secret 等），任何有权读取 cluster template 的用户都能获取这些凭证。

**Source -> Sink 路径**:
- **Source**: Cloud provider credentials（AWS/GCP/Azure 密钥）
- **Sink**: Rancher API 返回的 `cluster.management.cattle.io` 对象的 `spec.answers` 字段
- **Sanitization Gap**: Answers 字段未使用 K8s Secret 引用，直接以 plaintext 存储

**Vulnerable Code Pattern**:
```go
type ClusterSpec struct {
    // BUG: answers 以明文包含 cloud credential
    Answers map[string]string `json:"answers"`
    // 应该使用 SecretRef 引用 K8s Secret
}

// API handler 直接返回完整对象
func (h *Handler) GetCluster(w http.ResponseWriter, r *http.Request) {
    cluster, _ := h.store.Get(clusterID)
    // 未过滤 answers 中的敏感字段
    json.NewEncoder(w).Encode(cluster)
}
```

**Attack Path**:
1. 拥有 Rancher 只读权限的用户列出 cluster templates
2. 读取 `spec.answers` 字段
3. 获取 cloud provider credentials（AWS_SECRET_ACCESS_KEY 等）
4. 使用凭证直接访问云平台资源

**How to Detect**:
1. Grep `answers\|Answers\|plaintext\|credential` 查找凭证存储
2. 检查 CRD spec 中是否有明文密码/token 字段
3. 确认 API 响应是否过滤了敏感字段

---

### Case 2: Argo CD -- Cluster Secret 在日志中泄露 (CVE-2024-28175, CVSS 9.9)

**Root Cause**: Argo CD 在 cluster details 页面/API 中暴露了 cluster secret（包含 kubeconfig 和 bearer token），且在日志中以 `%+v` 格式化输出了完整的 cluster 对象。

**Source -> Sink 路径**:
- **Source**: K8s Secret 中存储的 cluster kubeconfig / bearer token
- **Sink**: Argo CD API 响应 + application 日志
- **Sanitization Gap**: Cluster 对象的 Secret 字段缺少 `json:"-"` tag，且日志使用了 `%+v` 格式化

**Vulnerable Code Pattern**:
```go
type Cluster struct {
    Server string `json:"server"`
    Name   string `json:"name"`
    // BUG: 缺少 json:"-" tag，序列化时会包含
    Config ClusterConfig `json:"config"`
}

type ClusterConfig struct {
    BearerToken string `json:"bearerToken"` // 应该是 json:"-"
    TLSClientConfig
}

// 日志中使用 %+v 输出完整对象
func (c *ClusterService) Update(cluster *Cluster) error {
    log.Printf("Updating cluster: %+v", cluster) // 泄露 bearerToken
    return c.store.Update(cluster)
}
```

**Attack Path**:
1. 有 Argo CD 读取权限的用户访问 cluster details API
2. API 返回包含 `config.bearerToken` 的完整 cluster 对象
3. 或从 Argo CD 日志中搜索 cluster 更新记录
4. 获取 cluster 的 bearer token，直接访问目标 K8s 集群

**How to Detect**:
1. Grep `%+v\|%#v` 查找可能泄露结构体的日志语句
2. 检查包含敏感字段的 struct 是否有 `json:"-"` tag
3. 确认 API 响应是否使用专门的 DTO 过滤敏感字段

---

### Case 3: Argo CD -- 匿名访问启用时盲目信任 JWT Claims (CVE-2024-22424, CVSS 10.0)

**Root Cause**: 当 Argo CD 启用匿名访问时，API server 盲目信任 JWT token 中的 claims（如 `sub`、`groups`），而不验证 JWT 的签名。攻击者可伪造 JWT 获取任意用户身份。

**Source -> Sink 路径**:
- **Source**: HTTP `Authorization` header 中的 JWT token
- **Sink**: Argo CD RBAC 决策（基于 JWT claims 中的 user/group）
- **Sanitization Gap**: 匿名模式下 JWT 签名验证被跳过

**Vulnerable Code Pattern**:
```go
func (s *Server) authenticate(r *http.Request) (*Claims, error) {
    token := r.Header.Get("Authorization")
    if token == "" {
        if s.anonymousEnabled {
            return &Claims{Subject: "anonymous"}, nil
        }
        return nil, ErrUnauthorized
    }

    // BUG: 当 anonymousEnabled=true 时，即使 JWT 签名无效也继续
    claims, err := s.verifyToken(token)
    if err != nil && s.anonymousEnabled {
        // 签名验证失败但匿名已启用，使用未验证的 claims
        claims, _ = parseClaimsWithoutVerification(token)
        return claims, nil // 返回未验证的 claims!
    }
    return claims, err
}
```

**Attack Path**:
1. 确认 Argo CD 启用了匿名访问
2. 构造伪造的 JWT token，claims 中设置 `sub: admin`
3. 发送带有伪造 JWT 的请求
4. Argo CD 信任未验证的 claims，授予 admin 权限

**How to Detect**:
1. Grep `anonymousEnabled\|anonymous.*true\|skipVerify` 查找匿名模式处理
2. 检查认证失败时的 fallback 逻辑是否安全
3. 确认 JWT 签名验证是否在所有路径上都强制执行

---

### Case 4: Gogs -- 内部文件删除导致 RCE (CVE-2024-39931, CVSS 10.0)

**Root Cause**: Gogs 允许仓库所有者通过 Web 编辑器删除仓库内的文件，但未限制删除 `.git/` 目录下的内部文件。攻击者可删除 `.git/hooks/pre-receive`（安全 hook），然后 push 恶意 hook 实现 RCE。

**Source -> Sink 路径**:
- **Source**: Web 编辑器的文件删除 API（文件路径参数）
- **Sink**: `os.Remove(filepath.Join(repoPath, filePath))` — 删除 `.git/` 内部文件
- **Sanitization Gap**: 未禁止删除 `.git/` 目录下的文件

**Vulnerable Code Pattern**:
```go
func deleteFile(repoPath, filePath string) error {
    fullPath := filepath.Join(repoPath, filePath)
    // BUG: filePath 可以是 ".git/hooks/pre-receive"
    // 未检查是否在 .git 目录内
    return os.Remove(fullPath)
}
```

**Attack Path**:
1. 通过 Web 编辑器删除 `.git/hooks/pre-receive`
2. Pre-receive hook 是 Gogs 用于安全检查的关键 hook
3. Push 新的 `.git/hooks/post-receive` 作为仓库文件
4. 后续操作触发恶意 hook 执行

**How to Detect**:
1. Grep `os.Remove\|os.RemoveAll` 查找文件删除操作
2. 检查路径是否过滤了 `.git/` 目录
3. 确认内部配置/hook 目录是否受保护

---

### Case 5: Rancher -- API 对象明文暴露敏感凭证 (CVE-2023-22649, CVSS 10.0)

**Root Cause**: Rancher 的 `cluster.management.cattle.io` API 对象在 `spec` 和 `status` 字段中以明文存储了各种凭证（S3 backup credentials、cloud provider tokens），任何有 RBAC 读取权限的用户都能看到。

**Source -> Sink 路径**:
- **Source**: S3 备份凭证、cloud provider token、SMTP 密码等
- **Sink**: Rancher API 响应的 JSON 序列化
- **Sanitization Gap**: 凭证字段缺少 `json:"-"` tag，API handler 未过滤

**Vulnerable Code Pattern**:
```go
type RancherClusterSpec struct {
    BackupConfig BackupConfig `json:"backupConfig"`
}

type BackupConfig struct {
    S3Config *S3Config `json:"s3Config"`
}

type S3Config struct {
    AccessKey string `json:"accessKey"`
    SecretKey string `json:"secretKey"` // BUG: 明文暴露
    Bucket    string `json:"bucket"`
}
```

**Attack Path**:
1. 拥有 cluster 读取权限的用户查询 Rancher API
2. API 返回包含 S3Config 的完整对象
3. `secretKey` 以明文出现在 JSON 响应中
4. 使用凭证访问 S3 bucket，窃取备份数据

**How to Detect**:
1. Grep `SecretKey\|Password\|Token\|AccessKey` 在 struct 定义中查找
2. 检查这些字段是否有 `json:"-"` tag
3. 确认 API handler 是否使用 DTO 过滤敏感字段

---

### Case 6: interactsh -- 外部可访问文件泄露 (CVE-2024-25623, CVSS 9.8)

**Root Cause**: ProjectDiscovery 的 interactsh server 未正确限制文件访问路径，外部用户可通过 HTTP 请求读取服务器上的任意文件（包含收集到的交互数据和配置）。

**Source -> Sink 路径**:
- **Source**: HTTP 请求中的文件路径
- **Sink**: `http.ServeFile` 或 `os.ReadFile` — 读取服务器文件
- **Sanitization Gap**: 文件路径未限制在安全目录内

**Vulnerable Code Pattern**:
```go
func (s *Server) handleFileRequest(w http.ResponseWriter, r *http.Request) {
    filePath := r.URL.Path
    // BUG: 未验证路径是否在允许的目录内
    http.ServeFile(w, r, filepath.Join(s.dataDir, filePath))
}
```

**Attack Path**:
1. 发送 HTTP 请求 `GET /../../../etc/passwd`
2. Server 拼接路径并通过 `http.ServeFile` 返回
3. 读取服务器配置或收集到的安全测试数据

**How to Detect**:
1. Grep `http.ServeFile\|http.FileServer` 查找文件服务
2. 检查路径参数是否经过 `filepath.Clean` + 前缀验证
3. 确认文件服务是否限制在预期目录内

---

### Case 7: SiYuan Note -- Export 端点路径遍历泄露任意文件 (CVE-2025-27421, CVSS 9.3)

**Root Cause**: 思源笔记的 `/export` API 端点存在路径遍历漏洞，攻击者可通过构造恶意路径读取服务器上的任意文件，包括 JWT Secret 等敏感配置。

**Source -> Sink 路径**:
- **Source**: `/export` API 的文件路径参数
- **Sink**: `os.ReadFile(filepath.Join(workspaceDir, exportPath))` — 路径遍历
- **Sanitization Gap**: Export path 未过滤 `..` 组件

**Vulnerable Code Pattern**:
```go
func handleExport(w http.ResponseWriter, r *http.Request) {
    exportPath := r.URL.Query().Get("path")
    // BUG: exportPath 可包含 "../../conf/conf.json"
    fullPath := filepath.Join(workspaceDir, exportPath)
    data, _ := os.ReadFile(fullPath)
    w.Write(data)
}
```

**Attack Path**:
1. 发送请求 `GET /export?path=../../conf/conf.json`
2. 服务器拼接路径遍历到 workspace 外
3. 读取 `conf.json` 获取 JWT Secret
4. 伪造 admin JWT token 实现权限提升

**How to Detect**:
1. Grep `export\|download\|file.*path` 查找文件导出/下载端点
2. 检查路径参数是否过滤了 `..` 并验证了前缀
3. 确认导出功能是否需要认证

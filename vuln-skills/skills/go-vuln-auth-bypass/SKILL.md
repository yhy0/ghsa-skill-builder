---
name: go-vuln-auth-bypass
description: "Use when auditing Go code involving authentication flows, RBAC policies, Kubernetes admission webhooks, JWT/OAuth token validation, or privilege escalation in cloud-native infrastructure. Covers CWE-287/863/269/284/285/862. Keywords: authentication bypass, authorization bypass, RBAC, admission webhook, JWT, OAuth, privilege escalation, Rancher, Kyverno, impersonation, namespace isolation, middleware auth"
---

# Go Auth Bypass Vulnerability Patterns (CWE-287/863/269/284/285/862)

当审计 Go 代码中涉及认证流程、RBAC 权限检查、K8s admission webhook、JWT/OAuth 验证时加载此 Skill。

## Detection Strategy

通用检测模型，适用于 Go 云原生生态中认证/授权绕过的所有变体。

**Sources（攻击入口）：**
- HTTP 请求头部（`Authorization`, `Impersonate-User`, `Impersonate-Group`）
- Kubernetes API 请求（ServiceAccount token, RBAC RoleBinding）
- gRPC metadata（`authorization`, custom auth headers）
- JWT/OAuth token（`id_token`, `access_token`, `state` parameter）
- Webhook 回调请求（admission webhook, mutating webhook）
- Rancher API proxy 请求（`/v3/clusters/:id/proxy`）

**Sinks（受保护资源/操作）：**
- Kubernetes API 调用（`client-go` `Create`/`Update`/`Delete`）
- Rancher 管理 API（集群凭证、cloud credential）
- Secret 读取/修改操作（`v1.Secret` 对象）
- 特权提升操作（`ClusterRoleBinding` 创建, `RoleRef` 修改）
- Admission webhook 的 `allow/deny` 决策
- gRPC service method 实现

**Sanitization（认证/授权屏障）：**
- Go HTTP 中间件（chi `Use()`, gin `Use()`, echo middleware chain）
- Kubernetes RBAC（`SubjectAccessReview`, `SelfSubjectAccessReview`）
- OPA/Gatekeeper 策略评估
- JWT 验证库（`golang-jwt/jwt/v5` 的 `Parse` + `WithValidMethods`）
- gRPC interceptor（`UnaryInterceptor`, `StreamInterceptor`）
- Rancher webhook 验证（`cattle.io` webhook admission）

**检测路径：**

搜索认证/授权模式的 Grep 模式：
```bash
# K8s admission webhook — 检查是否正确拒绝请求
grep -rn "admission.Response\|admission.Allowed\|admission.Denied" --include="*.go"
# RBAC 检查
grep -rn "SubjectAccessReview\|SelfSubjectAccessReview\|authz" --include="*.go"
# JWT 解析
grep -rn "jwt.Parse\|jwt.ParseWithClaims\|token.Valid" --include="*.go"
# OAuth state 参数
grep -rn "oauth\|OAuth\|state.*param\|csrf.*token" --include="*.go"
# HTTP 中间件注册
grep -rn "\.Use(\|\.Group(\|middleware\.\|interceptor" --include="*.go"
# Rancher proxy API
grep -rn "proxy.*handler\|proxyRequest\|cloud.*credential" --include="*.go"
# K8s impersonation
grep -rn "Impersonate\|impersonate\|as-user\|as-group" --include="*.go"
```

1. 搜索受保护的资源端点（HTTP handler、gRPC method、admission webhook handler）
2. 检查是否有认证/授权中间件保护（middleware chain、interceptor、RBAC check）
3. 验证屏障是否可被绕过：
   - Admission webhook 在升级过程中是否被临时禁用？
   - RBAC 策略是否存在跨 namespace 权限泄漏？
   - JWT 验证是否检查了 `alg` 字段和 `audience`？
   - OAuth state 参数是否正确验证？
   - 中间件顺序是否正确（auth middleware 在路由之前）？
   - Impersonation header 是否在 API proxy 中被正确过滤？
   - ServiceAccount token 的权限范围是否过宽？
4. 若无屏障或屏障可被绕过 -> 标记为候选漏洞

## Detection Checklist

- [ ] **Admission Webhook 升级期间绕过审计** (CWE-284)：Rancher/K8s webhook 在升级过程中是否被临时删除或跳过？升级脚本是否先删除 webhook 再安装新版本？`failurePolicy` 设为 `Ignore`（failOpen）时 webhook 故障会导致请求被放行。`namespaceSelector` 配置不当可能导致特定 namespace 绕过 webhook 检查。务必验证 admission request 的来源（TLS 证书）防止伪造请求。
- [ ] **跨 Namespace 权限泄漏审计** (CWE-269)：Kyverno/OPA 策略中的 `apiCall` 是否使用了 ServiceAccount 的集群级权限访问其他 namespace 的资源？
- [ ] **JWT 验证完整性审计** (CWE-287)：`jwt.Parse()` 是否指定了 `jwt.WithValidMethods([]string{"RS256"})`？是否检查了 `aud`/`iss`/`exp` claims？
- [ ] **OAuth state 参数验证审计** (CWE-287)：OAuth 回调处理是否验证 `state` 参数与 session 中存储的值一致？是否存在 token 交换时的 TOCTOU？
- [ ] **gRPC Interceptor 认证审计** (CWE-285)：所有需要认证的 gRPC method 是否都经过 `UnaryInterceptor` 认证链？是否有 method 被排除在外？
- [ ] **中间件顺序审计** (CWE-285)：chi/gin/echo 的 auth 中间件是否在路由组注册之前执行？`r.Group().Use(authMiddleware)` 是否覆盖了所有子路由？
- [ ] **K8s Impersonation Header 过滤审计** (CWE-284)：API proxy 是否转发了 `Impersonate-User`/`Impersonate-Group` header？低权限用户是否能通过 proxy 冒充高权限用户？
- [ ] **Rancher Cloud Credential 访问控制审计** (CWE-284)：Proxy API 是否正确验证用户对 cloud credential 的访问权限？是否存在通过代理绕过权限检查的路径？
- [ ] **ServiceAccount Token 权限范围审计** (CWE-269)：自动创建的 SA token 是否具有集群级 `cluster-admin` 权限？是否遵循最小权限原则？

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **测试代码中的权限豁免** -- `_test.go` 文件中使用 `fake.NewSimpleClientset()` 跳过认证
- **健康检查端点无认证** -- `/healthz`、`/readyz`、`/livez` 不需要认证是正常行为
- **公开的 metrics 端点** -- `/metrics` 在 Prometheus 架构中通常不需要认证（需确认网络隔离）
- **内部 gRPC 通信使用 mTLS** -- 如果 gRPC 服务仅在 mesh 内通信且使用 mTLS，缺少 application-level 认证可接受

以下模式**需要深入检查**：
- **`admission.Allowed("")`** -- 空 reason 的 allow 决策可能是 webhook 的默认放行逻辑
- **`if err != nil { return true }`** -- 认证错误时默认允许是高危模式
- **中间件链中 `Next()` 在认证检查之前被调用** -- 可能导致后续 handler 在未认证情况下执行
- **`ClusterRole` 使用 `*` 通配符** -- `resources: ["*"]` + `verbs: ["*"]` 是过宽权限

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

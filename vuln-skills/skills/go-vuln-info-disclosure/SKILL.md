---
name: go-vuln-info-disclosure
description: "Use when auditing Go code involving logging, error handling, HTTP response data, Kubernetes Secret management, or credential storage. Covers CWE-200/532/522/312/552. Keywords: information disclosure, credential leak, log exposure, Kubernetes Secret, json tag, struct formatting, error message, stack trace, Rancher, Argo CD, sensitive data"
---

# Go Information Disclosure Vulnerability Patterns (CWE-200/532/522/312/552)

当审计 Go 代码中涉及日志记录、错误处理、API 响应、K8s Secret 管理、凭证存储时加载此 Skill。

## Detection Strategy

**Sources（敏感数据来源）：**
- Kubernetes Secret 对象（`v1.Secret.Data`）
- 数据库凭证（`database/sql` 连接字符串）
- API token / OAuth credential（struct 字段）
- TLS 证书私钥
- 环境变量中的密钥（`os.Getenv("API_KEY")`）
- Git 仓库 URL 中的认证信息（`https://user:token@github.com`）

**Sinks（泄露出口）：**
- `log.Printf("%+v", configStruct)` -- `%+v` 格式化输出所有字段包括密钥
- `logrus.WithFields(logrus.Fields{...}).Error()` -- 结构化日志中包含敏感字段
- `zap.Any("config", struct)` -- zap 日志序列化完整结构体
- HTTP API 响应 body（`json.Marshal(objectWithSecrets)`）
- K8s API 对象的 `.status` / `.spec` 字段
- 错误信息（`fmt.Errorf("failed to connect: %v", err)`）中的连接字符串
- `runtime.Stack()` 输出包含参数值

**Sanitization（数据保护措施）：**
- Struct field tag `json:"-"` -- JSON 序列化时忽略字段
- `String()` / `MarshalJSON()` 方法 -- 自定义序列化隐藏敏感字段
- Log scrubbing 中间件 -- 过滤日志中的敏感模式
- K8s Secret `stringData` -> base64 `data` 转换
- Error wrapping（`fmt.Errorf("connection failed: %w", ErrGeneric)`）-- 隐藏内部细节

**检测路径：**

```bash
# 格式化输出 struct
grep -rn '%+v\|%#v' --include="*.go"
# 日志中可能的敏感信息
grep -rn 'log\.Print\|logrus\.\|zap\.\|logger\.' --include="*.go" | grep -i 'secret\|password\|token\|credential\|key'
# JSON 序列化 — 检查是否有 json:"-" tag
grep -rn 'json:"-"' --include="*.go"
# K8s Secret 操作
grep -rn 'v1.Secret\|corev1.Secret\|StringData\|\.Data\[' --include="*.go"
# 错误信息中的敏感信息
grep -rn 'fmt.Errorf\|errors.New\|errors.Wrap' --include="*.go"
# Git URL with credentials
grep -rn 'https://.*:.*@\|git.*token\|git.*password' --include="*.go"
# API 响应
grep -rn 'json.Marshal\|json.NewEncoder.*Encode' --include="*.go"
```

1. 搜索敏感数据的定义位置（Secret struct、credential 字段、token 变量）
2. 追踪数据流向，检查是否流入日志、API 响应、错误信息
3. 验证是否有保护措施：
   - 包含密钥的 struct 是否有 `json:"-"` tag？
   - 日志是否使用了 scrubbing/redaction 过滤？
   - API 响应是否使用专门的 DTO（而非直接返回内部对象）？
   - K8s Secret 是否在 CRD status 中被明文暴露？
   - 错误信息是否包含连接字符串或堆栈追踪？
4. 若敏感数据可能泄露 -> 标记为候选漏洞

## Detection Checklist

- [ ] **`%+v` 格式化审计** (CWE-532)：`fmt.Sprintf("%+v", struct)` 或 `log.Printf("%+v", struct)` 是否会输出包含密码/token 的 struct 字段？`%+v` 会打印所有字段名和值。
- [ ] **K8s Secret 明文存储审计** (CWE-312)：Secret 值是否作为明文存储在 CRD 的 `.spec` 或 `.status` 字段中？CRD status subresource 的 RBAC 通常比 Secret 宽松，任何有 CRD read 权限的用户都能读取 status 中的凭证。**修复方式**：凭证应存储在 K8s Secret 对象中，CRD status 仅引用 Secret 的名称（如 `secretRef: my-backup-credentials`）。Rancher 的 cluster template answers 曾直接存储 cloud credential。
- [ ] **API 响应中的凭证字段审计** (CWE-200)：API endpoint 返回的 JSON 是否包含 `password`、`token`、`secret` 等字段？是否使用独立的 response DTO 而非直接 Marshal 内部对象？
- [ ] **Argo CD Cluster Secret 泄露审计** (CWE-532)：Argo CD 的 cluster details API 是否在日志或响应中暴露了 cluster secret（kubeconfig、bearer token）？
- [ ] **Git URL 凭证泄露审计** (CWE-522)：Git clone URL 中是否包含 `https://user:token@host` 格式的认证信息？该 URL 是否出现在日志或错误信息中？
- [ ] **错误信息堆栈追踪审计** (CWE-200)：生产环境的 HTTP error response 是否包含 `runtime.Stack()` 输出或内部文件路径？Go 的 panic recovery 中间件是否向客户端暴露了堆栈？
- [ ] **`json:"-"` 缺失审计** (CWE-200)：包含敏感字段（Password, Token, SecretKey）的 struct 是否为敏感字段添加了 `json:"-"` tag？未标记的字段在 `json.Marshal` 时会被包含。
- [ ] **JWT Claims 未验证 Audience 审计** (CWE-200)：Argo CD 风格的 JWT 信任——启用匿名访问时是否盲目信任 JWT claims？攻击者是否能通过伪造 JWT 获取敏感信息？

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **Debug 级别日志中的详细信息** -- 如果 debug 日志仅在开发环境启用且不会出现在生产日志中
- **`json:"-"` 用于内部 RPC struct** -- 仅在服务内部使用的 struct 不需要隐藏字段
- **错误信息中的操作描述** -- `"failed to create user"` 不包含敏感数据
- **测试代码中的 mock Secret** -- `_test.go` 中使用假密钥

以下模式**需要深入检查**：
- **`json.Marshal(clusterObject)`** -- 集群对象是否包含 kubeconfig 或 bearer token 字段？
- **`logrus.WithError(err).Error("operation failed")`** -- `err` 中是否包含连接字符串或凭证？
- **CRD 的 `status` subresource** -- status 通常有较宽松的 RBAC，其中的敏感数据更容易被低权限用户读取
- **Rancher API 的 `answers` 字段** -- cluster template 的 answers 可能包含 cloud provider credentials

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

---
name: go-vuln-crypto-tls
description: "Use when auditing Go code involving TLS configuration, certificate validation, JWT token parsing, SAML assertion verification, webhook signature checking, or cryptographic operations. Covers CWE-295/347/345. Keywords: InsecureSkipVerify, TLS, mTLS, certificate validation, JWT algorithm, SAML signature, cosign, sigstore, hmac.Equal, X.509, webhook HMAC"
---

# Go Crypto/TLS Vulnerability Patterns (CWE-295/347/345)

当审计 Go 代码中涉及 TLS 配置、证书验证、JWT 解析、SAML 验证、Webhook 签名校验时加载此 Skill。

## Detection Strategy

**Sources（不可信输入）：**
- TLS 连接的对端证书
- JWT token（来自 HTTP `Authorization` header）
- SAML Response XML（来自 IdP 回调）
- Webhook 请求 body + signature header
- Container image 签名（cosign/sigstore）
- X.509 证书链

**Sinks（密码学验证点）：**
- `tls.Config{InsecureSkipVerify: true}` -- 跳过 TLS 证书验证，允许中间人攻击（MITM）
- `http.Transport{TLSClientConfig: &tls.Config{...}}` -- HTTP 客户端 TLS 配置
- `jwt.Parse(tokenString, keyFunc)` -- JWT 解析（无 `WithValidMethods`）
- `xmldsig.Verify()` / SAML signature validation -- XML 签名验证
- `hmac.New()` + `==` 比较 -- 非时间常量的 HMAC 比较
- `x509.Certificate.Verify(opts)` -- 证书链验证

**Sanitization（正确的密码学验证）：**
- `tls.Config{InsecureSkipVerify: false}` + 正确的 `RootCAs` / `ClientCAs`
- `jwt.Parse(token, keyFunc, jwt.WithValidMethods([]string{"RS256"}))` -- 限制算法
- `hmac.Equal(expected, actual)` -- 时间常量比较
- `x509.VerifyOptions` 配置完整的 CA pool 和 usage 约束
- SAML 签名验证使用 canonicalization（C14N）防止 XML 签名包装攻击
- TLS `MinVersion: tls.VersionTLS12`

**检测路径：**

```bash
# InsecureSkipVerify
grep -rn "InsecureSkipVerify" --include="*.go"
# TLS 配置
grep -rn "tls.Config\|TLSClientConfig\|tls.Dial" --include="*.go"
# JWT 解析
grep -rn "jwt.Parse\|jwt.ParseWithClaims\|jwt.NewParser" --include="*.go"
# SAML 处理
grep -rn "saml\|SAML\|xmldsig\|xml.*signature" --include="*.go"
# HMAC 比较
grep -rn "hmac.New\|hmac.Equal\|crypto/hmac" --include="*.go"
# Cosign/Sigstore
grep -rn "cosign\|sigstore\|Verify.*signature\|VerifyImage" --include="*.go"
# 证书验证
grep -rn "x509.Verify\|x509.Certificate\|CertPool" --include="*.go"
# mTLS 配置
grep -rn "ClientAuth\|RequireAndVerifyClientCert\|ClientCAs" --include="*.go"
```

1. 搜索密码学验证点（TLS 配置、JWT 解析、签名验证）
2. 检查验证是否被正确实施或被跳过
3. 验证安全性：
   - `InsecureSkipVerify` 是否为 `true`？
   - JWT 解析是否限制了允许的算法（防止 `alg: none` 或算法混淆）？
   - HMAC 比较是否使用 `hmac.Equal`（而非 `==` 或 `bytes.Equal`）？
   - SAML 签名验证是否正确处理了 XML canonicalization？
   - TLS session resumption 是否可能绕过 CA trust store 的更新？
   - mTLS 是否要求客户端证书（`ClientAuth: tls.RequireAndVerifyClientCert`）？
4. 若验证被跳过或不完整 -> 标记为候选漏洞

## Detection Checklist

- [ ] **`InsecureSkipVerify: true` 审计** (CWE-295)：所有 `tls.Config` 实例是否将 `InsecureSkipVerify` 设为 `false`？设为 `true` 将跳过 TLS 证书验证，攻击者可实施中间人攻击（MITM）窃取或篡改通信内容。仅测试环境可接受，生产环境应正确配置 `RootCAs` CA 证书池。搜索所有 `InsecureSkipVerify` 出现的位置，包括测试代码中被复制到生产环境的情况。
- [ ] **TLS Session Resumption 审计** (CWE-295)：Go 的 TLS session resumption 是否可能在 CA trust store 更新后继续使用旧证书？`tls.Config.SessionTicketsDisabled` 是否需要在 CA 更换时设为 `true`？
- [ ] **JWT 算法验证审计** (CWE-347)：`jwt.Parse` 是否指定了 `jwt.WithValidMethods([]string{"RS256"})`？未指定时攻击者可能用 `HS256`（对称算法）伪造 token，使用服务器的公钥作为 HMAC key。
- [ ] **JWT Claims 完整性审计** (CWE-287)：JWT 验证是否检查了 `iss`（签发者）、`aud`（受众）、`exp`（过期）claims？Mattermost 曾因未验证 OAuth state token 导致认证绕过。
- [ ] **SAML XML 签名包装审计** (CWE-347)：SAML 签名验证是否仅验证了 XML 文档的一部分？攻击者可能在已签名的节点外插入恶意断言。SSOReady 曾因 differential XML parsing 导致签名绕过。
- [ ] **Webhook HMAC 时间常量比较审计** (CWE-345)：Webhook 签名验证是否使用 `hmac.Equal()` 而非 `==` 或 `bytes.Equal()`？非常量时间比较允许时间侧信道攻击逐字节猜测签名。
- [ ] **mTLS 客户端证书验证审计** (CWE-295)：mTLS 配置是否使用 `tls.RequireAndVerifyClientCert`？是否正确设置了 `ClientCAs` CA pool？NeuVector 曾因 mTLS 配置错误导致 MITM。
- [ ] **Cosign/Sigstore 签名验证审计** (CWE-347)：容器镜像签名验证是否可被绕过？签名策略是否被正确评估（sigstore policy-controller）？

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **测试代码中的 `InsecureSkipVerify: true`** -- `_test.go` 中连接 localhost 测试服务器
- **开发环境的自签名证书** -- 明确限制在开发环境且有配置开关
- **`hmac.Equal` 用于非安全场景** -- 如校验数据完整性而非认证
- **JWT 不用于认证** -- 如仅用于内部 RPC 的元数据传递

以下模式**需要深入检查**：
- **`InsecureSkipVerify` 通过配置文件控制** -- 默认值是什么？文档是否建议在生产环境禁用？
- **自定义 `VerifyPeerCertificate` 回调** -- 是否正确验证了证书链？空回调 `func(...) error { return nil }` 等于跳过验证
- **`jwt.Parse` 的 `keyFunc` 返回错误时的行为** -- 是否 fallback 到不验证？
- **TLS `MinVersion` 未设置** -- Go 默认 TLS 1.2，但显式设置更安全

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

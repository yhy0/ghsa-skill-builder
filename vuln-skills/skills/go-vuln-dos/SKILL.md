---
name: go-vuln-dos
description: "Use when auditing Go code involving goroutine management, channel operations, HTTP request handling, resource allocation, or panic recovery. Covers CWE-400/770/476. Keywords: denial of service, goroutine leak, channel deadlock, panic recover, io.ReadAll, resource exhaustion, OOM, HTTP/2 abuse, protobuf, unbounded allocation, rate limiting"
---

# Go DoS/Resource Exhaustion Vulnerability Patterns (CWE-400/770/476)

当审计 Go 代码中涉及 goroutine 管理、channel 操作、HTTP 请求处理、资源分配、panic 恢复时加载此 Skill。

## Detection Strategy

**Sources（攻击入口）：**
- HTTP 请求 body（大 payload、大量并发请求）
- gRPC 消息（protobuf 嵌套深度、repeated 字段大小）
- WebSocket 帧（无限制的消息大小/频率）
- P2P 网络消息（如 go-ethereum 的 peer message）
- 用户控制的分配大小参数

**Sinks（资源消耗点）：**
- `go func()` -- 无限制的 goroutine 创建
- `make([]byte, userSize)` / `make([]T, userSize)` -- 用户控制的内存分配
- `io.ReadAll(r)` / `ioutil.ReadAll(r)` -- 读取整个 body 到内存
- `json.NewDecoder(r).Decode(&v)` -- 无大小限制的 JSON 解码
- `yaml.Unmarshal(data, &v)` -- YAML 解码（支持 anchor/alias 指数扩展）
- `proto.Unmarshal(data, msg)` -- protobuf 解码无嵌套限制
- `panic()` 在 HTTP handler 中未被 `recover()` 捕获
- Channel 操作（`ch <- v` 阻塞、`<-ch` 永久等待）

**Sanitization（资源限制屏障）：**
- `io.LimitReader(r, maxSize)` -- 限制读取大小
- `http.MaxBytesReader(w, r.Body, maxSize)` -- HTTP body 大小限制
- `context.WithTimeout` / `context.WithDeadline` -- 超时控制
- Goroutine pool（worker pattern, `semaphore.Weighted`）
- `recover()` 在 goroutine 入口
- Rate limiting 中间件（`golang.org/x/time/rate`）
- Channel 缓冲区大小限制 + `select` with `default`

**检测路径：**

```bash
# Goroutine 创建
grep -rn "go func\|go .*(" --include="*.go"
# 无限制读取
grep -rn "io.ReadAll\|ioutil.ReadAll\|io.Copy" --include="*.go"
# 内存分配
grep -rn "make(\[\]byte\|make(\[\]" --include="*.go"
# Panic/Recover
grep -rn "panic(\|recover()" --include="*.go"
# JSON/YAML/Protobuf 解码
grep -rn "json.NewDecoder\|json.Unmarshal\|yaml.Unmarshal\|proto.Unmarshal" --include="*.go"
# 资源限制
grep -rn "LimitReader\|MaxBytesReader\|context.WithTimeout" --include="*.go"
# Channel 操作
grep -rn "make(chan\|<-.*chan" --include="*.go"
```

1. 搜索资源消耗点（goroutine 创建、内存分配、IO 读取、解码操作）
2. 追踪输入来源，确认是否来自不可信外部输入
3. 验证是否有资源限制：
   - `io.ReadAll` 之前是否有 `LimitReader`/`MaxBytesReader`？
   - Goroutine 是否有退出条件（context cancellation、done channel）？
   - `make([]T, size)` 的 size 是否有上限检查？
   - HTTP handler 是否有 `recover()` 中间件防止 panic 导致进程崩溃？
   - JSON/protobuf 解码是否限制了嵌套深度或大小？
4. 若无资源限制 -> 标记为候选漏洞

## Detection Checklist

- [ ] **Goroutine 泄漏审计** (CWE-400)：`go func()` 内部是否有退出条件？是否监听 `ctx.Done()` 或 `done` channel？无退出条件的 goroutine 在请求取消后仍会占用资源。
- [ ] **`io.ReadAll` 无限制审计** (CWE-770)：是否直接 `io.ReadAll(r.Body)` 而未使用 `http.MaxBytesReader` 或 `io.LimitReader` 限制？攻击者可发送超大 body 导致 OOM。
- [ ] **`make([]byte, size)` 分配审计** (CWE-789)：`size` 是否来自用户输入？是否有上限检查？直接 `make([]byte, userSize)` 可用于 OOM 攻击。
- [ ] **HTTP Handler Panic 恢复审计** (CWE-476)：注意 Go 标准库 `net/http` 的 `Server` 内置了 per-request `recover()`，单个 handler panic 不会导致进程崩溃（但会关闭该连接）。第三方框架（如 gin/echo）通常也有内置 recovery 中间件。真正危险的是在 handler 中启动的 **子 goroutine** 中 panic（不受 HTTP server recover 保护）。对于不安全的类型断言（如 `data["key"].(string)`），应使用 comma-ok 模式 `v, ok := data["key"].(string)` 避免 panic。
- [ ] **Channel 死锁审计** (CWE-400)：无缓冲 channel（`make(chan T)`）在发送端/接收端缺失时是否会永久阻塞？`select` 是否包含 `default` 或 timeout 分支？
- [ ] **JSON/YAML/Protobuf 大小限制审计** (CWE-770)：`json.NewDecoder(r).Decode()` 是否限制了输入大小？YAML 的 anchor/alias 是否允许指数级扩展（"billion laughs"）？Protobuf 嵌套深度是否有限制？
- [ ] **HTTP/2 流滥用审计** (CWE-400)：Go HTTP/2 server 是否配置了 `MaxConcurrentStreams`？是否容易受到 rapid reset 攻击（CVE-2023-44487）？
- [ ] **自引用/循环引用审计** (CWE-400)：etcd gateway 风格的配置中，服务是否可能将自身作为后端端点，形成无限循环？DNS 或服务发现是否可能形成环路？
- [ ] **WebSocket 消息限制审计** (CWE-770)：WebSocket 连接是否配置了 `SetReadLimit`？是否有消息频率限制？

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **`go func()` 在 `init()` 中启动的后台 worker** -- 生命周期与进程相同，不会泄漏
- **`io.ReadAll` 读取小文件或内部配置** -- 来源可信且大小可控
- **`panic` 用于编程错误检测** -- 如 `panic("unreachable")` 在 switch default 中
- **带 `context.WithTimeout` 的 goroutine** -- 有超时退出机制

以下模式**需要深入检查**：
- **`go func()` 在 HTTP handler 中** -- 每个请求创建 goroutine 且无 pool 限制
- **`json.Decoder` 在 API endpoint** -- 未设置 `MaxBytesReader` 的 HTTP handler
- **`recover()` 在 goroutine 内但不在 HTTP handler 链** -- 可能只保护了子 goroutine 但 handler 本身可 panic
- **`select {}` 永久阻塞** -- 在某些情况下是有意设计，但也可能是 bug

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

# Go DoS/Resource Exhaustion — Real-World Cases

7 个真实 Go DoS/资源耗尽漏洞案例，每个代表一种独特的攻击模式。

---

### Case 1: ecnepsnai/web -- WebSocket 未认证导致 Nil Pointer Panic (CVE-2024-45258, CVSS 9.8)

**Root Cause**: `ecnepsnai/web` 框架的 WebSocket 请求未调用 `AuthenticateMethod`，导致认证上下文为 nil。后续代码访问 nil 指针导致 panic，在无 recover 中间件时崩溃整个服务器。

**Source -> Sink 路径**:
- **Source**: 未认证的 WebSocket 连接请求
- **Sink**: `panic` — nil pointer dereference on `authContext`
- **Sanitization Gap**: WebSocket upgrade 路径绕过了 HTTP 认证中间件

**Vulnerable Code Pattern**:
```go
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    // BUG: WebSocket 升级请求未调用 AuthenticateMethod
    // authCtx 为 nil
    conn, err := upgrader.Upgrade(w, r, nil)

    // 后续代码假设 authCtx 非 nil
    user := s.authCtx.User // panic: nil pointer dereference
}
```

**Attack Path**:
1. 发送 WebSocket 升级请求到服务器
2. 服务器未执行认证，authCtx 为 nil
3. 访问 nil 指针导致 panic
4. 无 recover 中间件，服务器进程崩溃

**How to Detect**:
1. Grep `upgrader.Upgrade\|websocket.Upgrade` 查找 WebSocket 处理
2. 检查 WebSocket handler 是否在认证中间件覆盖范围内
3. 确认是否有 `recover()` 捕获 panic

---

### Case 2: Rancher -- 未认证 API 导致资源耗尽 DoS (CVSS 8.2)

**Root Cause**: Rancher 的某些 API 端点未要求认证，攻击者可发送大量请求触发资源密集型操作（如集群 discovery），耗尽服务器资源。

**Source -> Sink 路径**:
- **Source**: 未认证的 HTTP 请求到 Rancher API
- **Sink**: 资源密集型后端操作（K8s API 调用、数据库查询）
- **Sanitization Gap**: 未认证端点缺少 rate limiting

**Vulnerable Code Pattern**:
```go
func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
    // BUG: 无认证检查，无 rate limiting
    // 每个请求触发多次 K8s API 调用
    clusters, err := h.clusterClient.List(r.Context(), metav1.ListOptions{})
    for _, c := range clusters.Items {
        // 每个集群执行 health check — 资源密集
        h.checkClusterHealth(c)
    }
    json.NewEncoder(w).Encode(clusters)
}
```

**Attack Path**:
1. 发现 Rancher 的未认证 API 端点
2. 发送大量并发请求
3. 每个请求触发多次 K8s API 调用和 health check
4. 服务器资源耗尽，合法用户无法访问

**How to Detect**:
1. Grep `http.Handle\|http.HandleFunc\|router.` 查找路由注册
2. 检查哪些端点缺少认证中间件
3. 确认未认证端点是否有 rate limiting

---

### Case 3: etcd -- Gateway 自引用导致无限循环 (CVE-2023-47348, CVSS 7.7)

**Root Cause**: etcd gateway 在配置中可以将自身地址作为后端 endpoint，导致请求在 gateway 内部无限循环转发，最终耗尽 goroutine 和内存。

**Source -> Sink 路径**:
- **Source**: etcd gateway 配置中的 endpoint 列表
- **Sink**: `grpc.Dial(selfAddress)` — 连接到自身形成环路
- **Sanitization Gap**: 未检查 endpoint 列表是否包含自身地址

**Vulnerable Code Pattern**:
```go
func (gw *Gateway) Start() error {
    for _, ep := range gw.endpoints {
        // BUG: endpoint 可能是 gateway 自身地址
        conn, err := grpc.Dial(ep, grpc.WithInsecure())
        gw.conns = append(gw.conns, conn)
    }
    // 当收到请求时，转发到自身，触发新请求，形成无限循环
    return gw.serve()
}
```

**Attack Path**:
1. 配置 etcd gateway，endpoint 列表包含 gateway 自身地址
2. 发送 etcd 请求到 gateway
3. Gateway 转发到自身，触发新请求
4. 无限循环消耗 goroutine 和内存直到 OOM

**How to Detect**:
1. Grep `grpc.Dial\|endpoint\|backend` 查找后端连接配置
2. 检查是否验证了 endpoint 不包含自身地址
3. 确认是否有请求深度/TTL 限制

---

### Case 4: Kyverno -- Context Variable 放大导致策略引擎 DoS (CVSS 7.7)

**Root Cause**: Kyverno 策略引擎在解析 policy 中的 context variable 时，允许变量引用链形成指数级放大。恶意策略可以通过嵌套引用导致内存/CPU 耗尽。

**Source -> Sink 路径**:
- **Source**: Kyverno Policy 的 `context` 变量定义
- **Sink**: 策略评估时的变量解析 — 递归/指数级展开
- **Sanitization Gap**: 无变量解析深度限制

**Vulnerable Code Pattern**:
```go
func resolveContext(ctx map[string]interface{}, vars []Variable) map[string]interface{} {
    for _, v := range vars {
        // BUG: 变量可以引用其他变量，形成链式放大
        // a = "{{b}}{{b}}", b = "{{c}}{{c}}", c = "large_string"
        // 解析 a 需要指数级内存
        resolved := resolveReferences(v.Value, ctx)
        ctx[v.Name] = resolved
    }
    return ctx
}
```

**Attack Path**:
1. 创建 Kyverno Policy，定义链式 context 变量
2. 每级变量引用两次下级变量（`a=bb, b=cc, c=dd...`）
3. N 级深度导致 2^N 倍展开
4. 策略评估时耗尽内存/CPU

**How to Detect**:
1. Grep `resolveContext\|resolveVariable\|evaluatePolicy` 查找变量解析
2. 检查是否有递归深度限制
3. 确认变量展开后的大小是否有上限

---

### Case 5: IPFS Boxo -- Bitswap 无限内存泄漏 (CVSS 8.2)

**Root Cause**: IPFS Boxo 的 bitswap/server 组件在处理 block want 请求时，为每个请求分配内存但不释放。持续发送请求可导致无限内存增长。

**Source -> Sink 路径**:
- **Source**: P2P 网络中的 bitswap want 消息
- **Sink**: 内存中的 want 队列 — 持久增长不回收
- **Sanitization Gap**: 无队列大小限制，无过期清理

**Vulnerable Code Pattern**:
```go
type Server struct {
    wantList map[cid.Cid]*wantEntry // BUG: 无限增长
}

func (s *Server) handleWant(msg bsmsg.BitSwapMessage) {
    for _, entry := range msg.Wantlist() {
        // 每个 want 请求添加到 map，从不清理
        s.wantList[entry.Cid] = &wantEntry{
            Cid:     entry.Cid,
            AddedAt: time.Now(),
        }
    }
}
```

**Attack Path**:
1. 连接到 IPFS 节点
2. 持续发送 bitswap want 消息（请求不存在的 CID）
3. 每个 CID 被添加到 wantList map
4. Map 无限增长直到 OOM

**How to Detect**:
1. Grep `map\[.*\].*=\|append(` 在请求处理路径中查找无限增长的数据结构
2. 检查 map/slice 是否有大小上限或过期清理
3. 确认是否有 per-peer 的请求限制

---

### Case 6: Flux -- Helm Controller OOM via 大 HelmRelease (CVSS 7.7)

**Root Cause**: Flux helm-controller 在处理 HelmRelease 时，将整个 chart 和 values 加载到内存。恶意用户可创建引用超大 chart 或 values 的 HelmRelease，导致 controller OOM。

**Source -> Sink 路径**:
- **Source**: HelmRelease CR 引用的 chart/values（可能来自用户控制的 Git 仓库）
- **Sink**: `io.ReadAll(chartArchive)` — 将整个 chart 加载到内存
- **Sanitization Gap**: 无 chart 大小限制

**Vulnerable Code Pattern**:
```go
func loadChart(source string) (*chart.Chart, error) {
    resp, _ := http.Get(source)
    // BUG: 读取整个 chart 到内存，无大小限制
    data, err := io.ReadAll(resp.Body)
    return loader.LoadArchive(bytes.NewReader(data))
}
```

**Attack Path**:
1. 在 Git 仓库中放置超大 Helm chart（数百 MB）
2. 创建 HelmRelease 引用该 chart
3. Flux controller 尝试加载整个 chart 到内存
4. Controller OOM 崩溃，影响集群中所有 HelmRelease 的协调

**How to Detect**:
1. Grep `io.ReadAll\|ioutil.ReadAll` 在 controller 代码中查找
2. 检查是否有 `io.LimitReader` 或 `http.MaxBytesReader` 限制
3. 确认 chart/values 大小是否有配置上限

---

### Case 7: flagd -- 无限制资源分配导致 DoS (CVSS 7.5)

**Root Cause**: flagd（feature flag 服务）的 gRPC API 未限制请求大小和并发数，攻击者可通过大 payload 或高并发请求导致服务资源耗尽。

**Source -> Sink 路径**:
- **Source**: gRPC 请求（大 payload 或高频率）
- **Sink**: 内存分配（proto.Unmarshal 大消息）和 goroutine 创建
- **Sanitization Gap**: gRPC server 未配置 `MaxRecvMsgSize` 和 `MaxConcurrentStreams`

**Vulnerable Code Pattern**:
```go
func main() {
    // BUG: 未设置 gRPC server 限制
    server := grpc.NewServer(
        // 缺少: grpc.MaxRecvMsgSize(maxSize)
        // 缺少: grpc.MaxConcurrentStreams(maxStreams)
    )
    flagdpb.RegisterFlagServiceServer(server, &flagService{})
    server.Serve(lis)
}
```

**Attack Path**:
1. 发送超大 gRPC 消息到 flagd
2. protobuf 反序列化分配大量内存
3. 或发送大量并发请求创建过多 goroutine
4. 服务 OOM 或 goroutine 耗尽

**How to Detect**:
1. Grep `grpc.NewServer\|grpc.Server` 查找 gRPC server 配置
2. 检查是否设置了 `MaxRecvMsgSize`、`MaxConcurrentStreams`
3. 确认 HTTP server 是否配置了 `ReadTimeout`、`WriteTimeout`、`MaxHeaderBytes`

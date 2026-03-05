---
name: vuln-patterns-deserialization
description: "Use when auditing Python code involving pickle/unpickle, yaml.load, torch.load, joblib.load, shelve, marshal, custom JSON object_hook with importlib, or ZeroMQ recv_pyobj. Covers CWE-502. Keywords: deserialization, pickle, unpickle, yaml.load, torch.load, joblib, shelve, marshal, __reduce__, cloudpickle, dill, safetensors, weights_only, picklescan"
---

# Deserialization Vulnerability Patterns (CWE-502)

当审计 Python 代码中涉及反序列化操作、模型加载、数据持久化读取时加载此 Skill。

## Detection Strategy

反序列化漏洞的核心模式是：**不可信数据** 进入 **反序列化函数**，且中间缺乏有效的安全屏障。Python 的反序列化漏洞尤其危险，因为 `pickle`、`shelve`、`torch.load` 等机制原生支持通过 `__reduce__` 方法执行任意代码。

**Sources（不可信数据来源）：**
- HTTP 请求体（REST API、gRPC、Flight RPC）
- 用户上传的模型文件（.pt, .pkl, .bin, .keras, .ckpt）
- ZeroMQ / TCP Socket 接收的数据
- 用户控制的 JSON 数据中的 `__type__` / `__class__` 字段
- 自定义序列化框架的 fallback 路径
- 文件系统中可被路径遍历访问的 session 文件
- 数据库或缓存中的序列化对象（shelve, dbm）
- 跨节点分布式通信数据（torch.distributed, Ray, Dask）

**Sinks（反序列化函数）：**
- `pickle.loads()` / `pickle.load()` — 直接反序列化
- `zmq.Socket.recv_pyobj()` — 内部调用 `pickle.loads()`
- `torch.load()` — 不带 `weights_only=True` 时使用 pickle
- `shelve.open()` — 内部使用 pickle 进行序列化/反序列化
- `json.loads()` 配合自定义 `object_hook` + `importlib.import_module()` — 动态类实例化
- `cloudpickle.loads()` / `dill.loads()` — pickle 变体
- `yaml.load()` — 不使用 `safe_load` 时可执行任意 Python 对象
- `joblib.load()` — 内部使用 pickle
- `marshal.loads()` — 可执行字节码
- `Unpickler.load()` — 自定义 Unpickler 若未限制 `find_class` 仍然危险

**Sanitization（安全屏障）：**
- 使用 `yaml.safe_load()` 替代 `yaml.load()`
- 使用 `torch.load(weights_only=True)` 限制只加载张量
- 使用 `json.loads()` 配合白名单 `object_hook`（仅允许已注册类型）
- 自定义 `Unpickler` 并重写 `find_class()` 限制允许的类
- 对序列化数据进行签名验证（HMAC）后再反序列化
- 使用 `safetensors` 格式替代 pickle 格式的模型文件
- 使用 `pickle.loads()` 前通过 `fickling` 或 `picklescan` 扫描恶意 opcode
- 在 HTTP API 层面拒绝 `application/vnd.bentoml+pickle` 等危险 Content-Type
- 使用 `struct.pack/unpack`、`json`、`protobuf` 等安全序列化替代 pickle
- 绑定服务到 `127.0.0.1` 而非 `0.0.0.0`，配合认证机制

**检测路径：**
1. **搜索反序列化函数调用**：Grep `pickle.loads`, `pickle.load`, `recv_pyobj`, `torch.load`, `shelve.open`, `yaml.load`, `joblib.load`, `marshal.loads`, `cloudpickle`, `dill.loads`
2. **搜索隐式反序列化**：Grep `importlib.import_module` + `object_hook`, `__type__`, `__class__`, `getattr` 组合模式；检查 `from_payload`, `deserialize` 等方法中是否有 pickle
3. **检查数据来源是否可被外部控制**：从 sink 参数向上回溯，确认数据是否来自网络请求、用户上传文件、外部 Socket
4. **验证是否使用了安全的反序列化方式**：检查是否有白名单、签名验证、`weights_only=True`、`safe_load` 等防护
5. **若使用不安全方式且数据来源不可信** -> 标记为候选漏洞

## Detection Checklist

- [ ] 搜索 `pickle.loads` / `pickle.load` 调用，检查数据来源是否可被外部控制
- [ ] 搜索 `recv_pyobj()` 调用（ZeroMQ），这是隐式 `pickle.loads`
- [ ] 搜索 `torch.load` 调用，检查是否缺少 `weights_only=True` 参数
- [ ] 搜索 `shelve.open` 调用，检查存储路径是否可被外部控制
- [ ] 搜索 `json.loads` + 自定义 `object_hook`，检查是否有 `importlib.import_module` 或动态 `getattr` 调用
- [ ] 搜索 `yaml.load` 调用，检查是否使用了 `Loader=SafeLoader` 或 `yaml.safe_load`
- [ ] 检查 HTTP API 中是否接受 pickle 相关的 Content-Type（如 `application/vnd.bentoml+pickle`）
- [ ] 检查序列化框架（如 pyfory/pyfury）是否存在 pickle fallback 路径
- [ ] 检查模型文件扫描逻辑是否正确处理了 `scan_err`（扫描失败时是否放行）
- [ ] 检查分布式通信中的序列化方式（ZeroMQ, gRPC, TCPStore），是否绑定到 `0.0.0.0`
- [ ] 检查 session 存储路径是否有路径遍历防护（`safe_join` vs `os.path.join`）
- [ ] 搜索 `joblib.load` 调用，检查加载路径/数据是否来自不可信来源（joblib 内部使用 pickle）
- [ ] 搜索 `marshal.loads` 调用，检查是否反序列化不可信来源的字节码

## False Positive Exclusion Guide

以下情况通常**不是**漏洞：
- `pickle.loads` 的数据来源是本地可信文件且路径不可被外部控制
- `torch.load` 使用了 `weights_only=True` 参数
- `yaml.load` 使用了 `Loader=yaml.SafeLoader` 或调用的是 `yaml.safe_load`
- 自定义 `object_hook` 中有严格的类型白名单（只允许已注册类型）
- 反序列化前有 HMAC 签名验证
- 服务仅监听 `127.0.0.1` 且有认证机制保护
- 使用了 `fickling` / `picklescan` 扫描且**正确处理了扫描错误**
- `pickle.loads` 的数据来自同进程内部的序列化（无网络/文件边界）

以下情况需要**额外关注**：
- `picklescan` 扫描后只检查 `infected_files != 0` 但未检查 `scan_err`（扫描本身失败时会放行恶意文件）
- 自定义序列化框架声称"安全"但存在 pickle fallback 路径
- `torch.load` 的 `weights_only` 参数默认值在不同版本可能不同
- `from_config` / `from_payload` 等反序列化入口可能隐藏在深层调用链中

## Real-World Cases

详见 [references/cases.md](references/cases.md)

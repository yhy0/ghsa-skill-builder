# Deserialization Vulnerability Cases (CWE-502)

本文件包含 8 个真实的 Python 反序列化漏洞案例，每个案例代表一种独特的漏洞变体模式。

---

### Case 1: EPyT-Flow — JSON 自定义 `__type__` 字段触发动态类实例化 (CVE-2026-25632, CVSS 10.0)

**Root Cause**: JSON 反序列化时通过 `__type__` 字段动态导入任意模块并实例化任意类，无类型白名单限制。

**Source -> Sink 路径**:
- **Source**: REST API 请求体中的 JSON 数据，或从不可信来源加载的 JSON 文件
- **Sink**: `importlib.import_module(module_name)` + `getattr(module, class_name)` + `cls(**obj)` 动态类实例化
- **Sanitization Gap**: `object_hook` 函数直接信任 JSON 中的 `__type__` 字段，未对可导入的模块/类做任何白名单限制

**Vulnerable Code Pattern** (`epyt_flow/serialization.py`):
```python
import importlib
import json

def my_load_from_json(data: str) -> Any:
    def __object_hook(obj: dict) -> dict:
        if "__type__" in obj:
            module_name, class_name = obj["__type__"]
            # 危险：直接从 JSON 输入导入任意模块和类
            cls = getattr(importlib.import_module(module_name), class_name)
            del obj["__type__"]
            for attr in obj:
                if isinstance(attr, dict):
                    obj[attr] = __object_hook(obj[attr])
            return cls(**obj)  # 危险：用攻击者控制的参数实例化任意类
        return obj

    return json.loads(data, object_hook=__object_hook)
```

**Attack Path**:
1. 攻击者构造包含 `__type__` 字段的 JSON，如 `{"__type__": ["subprocess", "Popen"], "args": ["whoami"]}`
2. JSON 数据通过 REST API 请求体或 JSON 文件传入 `my_load_from_json`
3. `object_hook` 解析 `__type__` 字段，调用 `importlib.import_module("subprocess")` 导入模块
4. `getattr` 获取 `Popen` 类，`cls(**obj)` 相当于 `subprocess.Popen(args=["whoami"])`，触发命令执行

**Why Standard Scanners Miss It**:
- CodeQL: 标准 deserialization query 只覆盖 `pickle.loads`/`yaml.load` 等已知 sink，不覆盖 `importlib.import_module` + `getattr` + 动态调用的组合模式
- Bandit: B301/B302 规则只检测 pickle/marshal/shelve，不检测 JSON `object_hook` 中的动态导入

**How to Detect**:
1. **定位 Sink**: Grep `object_hook` 参数在 `json.loads` / `json.load` 中的使用
2. **检查 hook 函数**: 查看 `object_hook` 回调中是否有 `importlib.import_module`、`getattr`、`__import__` 等动态导入操作
3. **验证白名单**: 检查是否对 `__type__` / `__class__` 等字段中的模块名和类名有白名单限制
4. **CodeQL 自定义查询方向**: 追踪从 `json.loads(object_hook=...)` 到 `importlib.import_module` 的数据流

**Similar Vulnerabilities**: GHSA-74vm-8frp-7w68

---

### Case 2: vLLM (Mooncake) — ZeroMQ `recv_pyobj()` 隐式 pickle 反序列化 (CVE-2025-32444, CVSS 10.0)

**Root Cause**: 使用 ZeroMQ 的 `recv_pyobj()` 方法接收网络数据，该方法内部调用 `pickle.loads()` 反序列化，且 Socket 绑定到所有网络接口（`0.0.0.0`）。

**Source -> Sink 路径**:
- **Source**: 远程网络客户端通过 ZeroMQ Socket 发送的数据
- **Sink**: `zmq.Socket.recv_pyobj()` -> 内部 `pickle.loads()`
- **Sanitization Gap**: `recv_pyobj()` 是 ZeroMQ 的便利方法，开发者可能不知道它内部使用 pickle；Socket 绑定到 `tcp://*:port` 暴露于全网

**Vulnerable Code Pattern** (`vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py`):
```python
import zmq

class MooncakePipe:
    def _setup_metadata_sockets(self, kv_rank, p_host, p_port, d_host, d_port):
        # 危险：绑定到所有网络接口
        self.sender_socket.bind(f"tcp://*:{p_rank_offset + 1}")
        self.receiver_ack.bind(f"tcp://*:{p_rank_offset + 2}")

    def recv_bytes(self):
        # 危险：recv_pyobj 内部调用 pickle.loads()
        src_ptr, length = self.receiver_socket.recv_pyobj()
        # ...

    def wait_for_ack(self, src_ptr, length):
        # 危险：同样是隐式 pickle 反序列化
        ack = self.sender_ack.recv_pyobj()
```

**Attack Path**:
1. 攻击者发现 vLLM 的 ZeroMQ Socket 监听在 `0.0.0.0` 的特定端口上
2. 攻击者构造恶意 pickle 对象（包含 `__reduce__` 方法执行任意命令）
3. 通过 ZeroMQ 客户端发送恶意序列化数据到目标 Socket
4. `recv_pyobj()` 内部调用 `pickle.loads()` 触发 `__reduce__` 方法，执行任意代码

**Why Standard Scanners Miss It**:
- CodeQL: 标准 query 不将 `zmq.Socket.recv_pyobj()` 识别为 pickle sink，因为 `pickle.loads` 调用发生在 pyzmq 库内部
- Bandit: 只检测直接的 `pickle.loads` 调用，不检测第三方库中封装的隐式 pickle 反序列化

**How to Detect**:
1. **定位 Sink**: Grep `recv_pyobj` / `send_pyobj` — ZeroMQ 中所有 `*_pyobj` 方法都使用 pickle
2. **检查网络绑定**: 查找 `bind("tcp://*:` 或 `bind("tcp://0.0.0.0:` 模式，确认是否暴露于外部网络
3. **验证认证**: 检查 ZeroMQ Socket 是否配置了 CURVE 或其他认证机制
4. **CodeQL 自定义查询方向**: 将 `zmq.Socket.recv_pyobj` 添加为额外的 deserialization sink

**Similar Vulnerabilities**: GHSA-hj4w-hm2g-p6w5 (vLLM Mooncake), GHSA-hjq4-87xh-g4fv (vLLM PyNcclPipe), GHSA-x3m8-f7g5-qhm7 (vLLM 早期版本), GHSA-5vqr-wprc-cpp7 (vLLM MessageQueue)

---

### Case 3: pgAdmin4 — 路径遍历 + Session 文件 pickle 反序列化链 (CVE-2024-2044, CVSS 10.0)

**Root Cause**: Session 管理使用 `pickle.load` 从文件反序列化 session 数据，且 session ID 作为文件名时未经路径遍历防护（`os.path.join` 而非 `safe_join`），攻击者可通过路径遍历指向恶意 pickle 文件。

**Source -> Sink 路径**:
- **Source**: HTTP Cookie 中的 session ID（用户可控）
- **Sink**: `pickle.load(f)` 加载 session 文件
- **Sanitization Gap**: 使用 `os.path.join(self.path, sid)` 拼接路径，未使用 `werkzeug.security.safe_join` 做路径规范化，允许 `../` 遍历

**Vulnerable Code Pattern** (`web/pgadmin/utils/session.py`):
```python
import os
from pickle import load

class FileBackedSessionManager:
    def get(self, sid, digest):
        # 危险：os.path.join 不防止路径遍历
        fname = os.path.join(self.path, sid)
        if os.path.exists(fname):
            try:
                with open(fname, 'rb') as f:
                    # 危险：从可能被路径遍历控制的文件中 pickle.load
                    randval, hmac_digest, data = load(f)
            except Exception:
                pass

    def exists(self, sid):
        # 同样的问题
        fname = os.path.join(self.path, sid)
        return os.path.exists(fname)
```

**Attack Path**:
1. 攻击者（Windows 场景无需认证，Linux 需认证）构造包含 `../` 的恶意 session ID
2. 在目标路径放置恶意 pickle 文件（Windows 下可通过 SMB 共享）
3. pgAdmin 使用 `os.path.join(path, sid)` 拼接路径，`../` 使路径指向恶意文件
4. `pickle.load(f)` 反序列化恶意文件，触发 `__reduce__` 方法执行任意代码

**Why Standard Scanners Miss It**:
- CodeQL: 路径遍历和 pickle 反序列化是两个独立的 vulnerability class，CodeQL 默认不检测两者链式组合
- Bandit: B301 会标记 `pickle.load` 但不会分析数据来源是否可被路径遍历控制

**How to Detect**:
1. **定位 Sink**: Grep `pickle.load` / `pickle.loads` + `open(` 的组合模式
2. **回溯文件路径来源**: 检查 `open()` 的文件路径参数是否包含用户可控输入（如 session ID、文件名）
3. **验证路径拼接方式**: 检查是否使用 `os.path.join`（不安全）还是 `werkzeug.security.safe_join`（安全）
4. **CodeQL 自定义查询方向**: 追踪从 HTTP Cookie/Header 到 `open()` 路径参数的数据流，再从 `open()` 的文件对象到 `pickle.load` 的数据流

**Similar Vulnerabilities**: GHSA-rj98-crf4-g69w

---

### Case 4: Keras — `TorchModuleWrapper.from_config` 绕过 safe_mode 触发 `torch.load` (CVE-2025-49655, CVSS 9.8)

**Root Cause**: Keras 的 `TorchModuleWrapper` 类在 `from_config` 方法中使用 `torch.load` 加载嵌入在 Keras 模型文件中的 PyTorch 模块，即使 Keras 的 `safe_mode=True` 也无法阻止此操作。

**Source -> Sink 路径**:
- **Source**: 用户加载的 `.keras` 模型文件（可从不可信来源下载）
- **Sink**: `torch.load(buffer)` 反序列化嵌入的 PyTorch 模块
- **Sanitization Gap**: Keras 的 safe_mode 机制未覆盖 `TorchModuleWrapper.from_config` 中的 `torch.load` 调用

**Vulnerable Code Pattern** (`keras/src/utils/torch_utils.py`):
```python
import base64
import io
import torch

class TorchModuleWrapper:
    @classmethod
    def from_config(cls, config):
        if "module" in config:
            # 缺失：未检查 safe_mode 状态
            # 直接从 config 中解码 base64 并通过 torch.load 加载
            buffer_bytes = base64.b64decode(config["module"].encode("ascii"))
            buffer = io.BytesIO(buffer_bytes)
            # 危险：torch.load 默认使用 pickle 反序列化
            module = torch.load(buffer)  # 无 weights_only=True
```

**Attack Path**:
1. 攻击者创建包含恶意 `TorchModuleWrapper` 配置的 `.keras` 文件
2. 在配置的 `module` 字段中嵌入 base64 编码的恶意 pickle 数据
3. 用户使用 `keras.saving.load_model(path, safe_mode=True)` 加载模型
4. Keras safe_mode 未拦截 `TorchModuleWrapper.from_config`，`torch.load` 执行恶意 pickle

**Why Standard Scanners Miss It**:
- CodeQL: `torch.load` 调用的数据来自 `config["module"]` 经 base64 解码，数据流分析难以穿透 base64 编解码 + `BytesIO` 包装
- Bandit: B614 检查 `torch.load` 但不分析 safe_mode 是否生效

**How to Detect**:
1. **定位 Sink**: Grep `torch.load` 调用，检查是否缺少 `weights_only=True`
2. **检查 safe_mode 覆盖**: 在 `from_config` / `from_pretrained` 等反序列化入口中，检查是否正确检查了框架的 safe_mode 标志
3. **验证数据来源**: 检查 `torch.load` 的数据是否可能来自用户上传的模型文件
4. **CodeQL 自定义查询方向**: 追踪 `from_config` / `from_pretrained` 方法中的所有 `torch.load` 调用，检查 `weights_only` 参数

**Similar Vulnerabilities**: GHSA-cvhh-q5g5-qprp, CVE-2024-12029 (InvokeAI torch.load)

---

### Case 5: Apache Pyfory — 序列化框架的 Pickle Fallback 路径 (CVE-2025-61622, CVSS 9.8)

**Root Cause**: Pyfory（原 Pyfury）自定义序列化框架在遇到不支持的类型时，fallback 到 `pickle` 进行序列化/反序列化。攻击者可构造数据流使反序列化过程选择 pickle fallback 路径。

**Source -> Sink 路径**:
- **Source**: 任何使用 Pyfory 反序列化的不可信数据流
- **Sink**: `Unpickler(buffer).load()` — 在 `handle_unsupported_read` 方法中的 pickle fallback
- **Sanitization Gap**: 即使启用了 `require_type_registration`，内部的 fallback 机制仍可在特定条件下触发 pickle 反序列化

**Vulnerable Code Pattern** (`python/pyfory/_fory.py`):
```python
from cloudpickle import Pickler
from pickle import Unpickler

class Fory:
    def __init__(self, require_type_registration=False):
        if not require_type_registration:
            self.pickler = Pickler(self.buffer)
            self.unpickler = None
        else:
            self.pickler = _PicklerStub()
            self.unpickler = _UnpicklerStub()

    def handle_unsupported_write(self, buffer, obj):
        if self._unsupported_callback is None or self._unsupported_callback(obj):
            buffer.write_bool(True)
            self.pickler.dump(obj)  # 危险：fallback 到 pickle 序列化

    def handle_unsupported_read(self, buffer):
        in_band = buffer.read_bool()
        if in_band:
            unpickler = self.unpickler
            if unpickler is None:
                # 危险：动态创建 Unpickler 进行 pickle 反序列化
                self.unpickler = unpickler = Unpickler(buffer)
            return unpickler.load()  # 触发任意代码执行
```

**Attack Path**:
1. 攻击者了解 Pyfory 的序列化协议格式
2. 构造数据流，在特定位置设置标志位使反序列化进入 `handle_unsupported_read` 分支
3. 在 `in_band=True` 的数据段中嵌入恶意 pickle payload
4. `Unpickler(buffer).load()` 执行恶意 pickle 数据中的 `__reduce__` 方法

**Why Standard Scanners Miss It**:
- CodeQL: pickle fallback 隐藏在自定义序列化框架的内部逻辑中，不在常规的 API 调用链上
- Bandit: 只检测直接的 `pickle.loads` 调用，`Unpickler(buffer).load()` 使用不同的调用模式可能被忽略

**How to Detect**:
1. **定位 Sink**: Grep `Unpickler` / `pickle.loads` / `cloudpickle` / `dill` 在序列化框架代码中的使用
2. **追踪 fallback 路径**: 在自定义序列化框架中搜索 "unsupported"、"fallback"、"default" 等关键词，检查是否 fallback 到 pickle
3. **验证类型注册机制**: 检查 `require_type_registration` 等安全选项是否真正阻止了 pickle fallback
4. **CodeQL 自定义查询方向**: 追踪序列化框架中 `Unpickler` 实例化和 `.load()` 调用的控制流

**Similar Vulnerabilities**: GHSA-538v-3wq9-4h3r

---

### Case 6: BentoML — HTTP Content-Type 触发 pickle 反序列化 (CVE-2025-27520, CVSS 9.8)

**Root Cause**: BentoML 的请求处理器根据 HTTP `Content-Type` 头选择反序列化方式，当 Content-Type 为 `application/vnd.bentoml+pickle` 时直接使用 `pickle.loads` 反序列化请求体。

**Source -> Sink 路径**:
- **Source**: HTTP POST 请求体（任意未认证用户）
- **Sink**: `pickle.loads(b"".join(payload.data))` 在 `serde.py` 的 `deserialize_value` 中
- **Sanitization Gap**: 无认证、无输入验证，攻击者只需设置正确的 Content-Type 头即可触发 pickle 反序列化

**Vulnerable Code Pattern** (`src/_bentoml_impl/serde.py`):
```python
import pickle

class PickleSerde:
    def deserialize_value(self, payload: Payload) -> Any:
        if "buffer-lengths" not in payload.metadata:
            # 危险：直接对 HTTP 请求体进行 pickle.loads
            return pickle.loads(b"".join(payload.data))
```

以及请求路由中的 Content-Type 分发（`src/_bentoml_impl/server/app.py`）：
```python
async def api_endpoint(self, name, request):
    media_type = request.headers.get("Content-Type", "application/json")
    media_type = media_type.split(";")[0].strip()
    # 未限制：允许 application/vnd.bentoml+pickle 触发 pickle 反序列化
    # 缺少对危险 Content-Type 的拦截
```

**Attack Path**:
1. 攻击者发现 BentoML 服务端点（默认端口 3000）
2. 构造 HTTP POST 请求，设置 `Content-Type: application/vnd.bentoml+pickle`
3. 请求体为恶意 pickle 数据（包含 `__reduce__` 方法调用 `os.system`）
4. 服务端根据 Content-Type 选择 `PickleSerde`，调用 `pickle.loads` 触发 RCE

**Why Standard Scanners Miss It**:
- CodeQL: 标准 query 追踪从 HTTP 请求体到 `pickle.loads` 的数据流，但中间经过 serde 框架的多层抽象（Payload 类、Content-Type 路由），可能断链
- Bandit: B301 会标记 `pickle.loads` 但不分析 HTTP 路由上下文，可能将其标记为低优先级

**How to Detect**:
1. **定位 Sink**: Grep `pickle.loads` / `pickle.load` 在 Web 框架代码中的使用
2. **检查 Content-Type 路由**: 在 HTTP 请求处理器中搜索 `Content-Type` 头的处理逻辑，检查是否有 pickle 相关的 MIME 类型
3. **验证认证**: 检查 pickle 反序列化端点是否需要认证
4. **CodeQL 自定义查询方向**: 追踪从 `request.body` / `request.data` 经过 Content-Type 分发到 `pickle.loads` 的完整数据流

**Similar Vulnerabilities**: GHSA-33xw-247w-6hmc (BentoML serde.py), GHSA-7v4r-c989-xh26 (BentoML runner server `NdarrayContainer.from_payload`)

---

### Case 7: Kedro — `shelve` 模块作为隐藏的 pickle 反序列化 Sink (CVE-2024-9701, CVSS 9.8)

**Root Cause**: Kedro 的 `ShelveStore` 类使用 Python `shelve` 模块持久化 session 数据。`shelve` 内部使用 `pickle` 进行序列化，攻击者可通过修改 shelve 文件注入恶意 pickle 数据。

**Source -> Sink 路径**:
- **Source**: 磁盘上的 shelve 数据文件（可被攻击者写入或替换）
- **Sink**: `shelve.open(path, flag="r")` -> 内部 `pickle.loads`
- **Sanitization Gap**: `shelve` 模块无安全反序列化选项，一旦文件可被攻击者控制即可触发 RCE

**Vulnerable Code Pattern** (`kedro/framework/session/shelvestore.py`):
```python
import shelve
import dbm
from pathlib import Path

class ShelveStore(BaseSessionStore):
    @property
    def _location(self) -> Path:
        return Path(self._path).expanduser().resolve() / self._session_id / "store"

    def read(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        try:
            # 危险：shelve.open 内部使用 pickle 反序列化
            # S301 (Bandit) 已标记但被 noqa 忽略
            with shelve.open(str(self._location), flag="r") as _sh:  # noqa: S301
                data = dict(_sh)
        except dbm.error:
            pass
        return data

    def save(self) -> None:
        location = self._location
        location.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, shelve.open(str(location)) as _sh:  # noqa: S301
            keys_to_del = _sh.keys() - self.data.keys()
            for key in keys_to_del:
                del _sh[key]
            _sh.update(self.data)
```

**Attack Path**:
1. 攻击者获取对 Kedro session 存储目录的写入权限（通过其他漏洞或共享文件系统）
2. 在 session 目录下放置恶意 shelve 文件，包含构造的 pickle payload
3. Kedro 调用 `ShelveStore.read()` 加载 session 数据
4. `shelve.open()` 内部调用 `pickle.loads` 触发恶意代码执行

**Why Standard Scanners Miss It**:
- CodeQL: 标准 query 不将 `shelve.open()` 识别为 deserialization sink（它看起来像文件操作而非反序列化）
- Bandit: B301 会标记 `shelve.open`（S301），但开发者可能使用 `# noqa: S301` 忽略告警（如本例所示）

**How to Detect**:
1. **定位 Sink**: Grep `shelve.open` / `shelve.Shelf` — 所有 shelve 操作都涉及 pickle
2. **检查文件路径控制**: 确认 shelve 文件路径是否包含用户可控输入（session ID、用户名等）
3. **检查 noqa 注释**: 搜索 `# noqa: S301` 或 `# nosec`，这些注释可能隐藏了真实的安全问题
4. **CodeQL 自定义查询方向**: 将 `shelve.open` 添加为额外的 deserialization sink

**Similar Vulnerabilities**: GHSA-747f-ww56-4q4h

---

### Case 8: InvokeAI — `torch.load` 扫描错误处理不当导致恶意模型绕过检测 (CVE-2024-12029, CVSS 9.8)

**Root Cause**: InvokeAI 使用 `picklescan` 扫描模型文件后再通过 `torch.load` 加载。但扫描结果检查逻辑只验证 `infected_files != 0`，未检查 `scan_err`（扫描失败的情况），导致扫描失败时恶意模型被放行。

**Source -> Sink 路径**:
- **Source**: 用户通过 `/api/v2/models/install` API 上传的模型文件
- **Sink**: `torch_load(checkpoint, map_location="cpu")` — 内部使用 pickle 反序列化
- **Sanitization Gap**: 安全扫描只检查 `infected_files != 0`，未处理 `scan_err != 0` 的情况（扫描本身失败时放行恶意文件）

**Vulnerable Code Pattern** (`invokeai/app/services/model_load/model_load_default.py`):
```python
from invokeai.backend.util.pickle_scan import scan_file_path
from torch import load as torch_load

def load_model_from_path(self, ...):
    def torch_load_file(checkpoint: Path) -> AnyModel:
        scan_result = scan_file_path(checkpoint)
        # 漏洞：只检查 infected_files，未检查 scan_err
        if scan_result.infected_files != 0:
            raise Exception("The model is potentially infected by malware.")
        # 如果 scan_err != 0（扫描失败），仍然继续加载
        result = torch_load(checkpoint, map_location="cpu")
        return result
```

同样的问题出现在 `probe.py` 和 `model_util.py` 中：
```python
# invokeai/backend/model_manager/util/model_util.py
def read_checkpoint_meta(path, scan: bool = False):  # 注意：默认 scan=False
    if scan:
        scan_result = scan_file_path(path)
        # 同样的漏洞：未检查 scan_err
        if scan_result.infected_files != 0:
            raise Exception(f'The model file "{path}" is potentially infected.')
```

**Attack Path**:
1. 攻击者构造恶意 `.pt` 模型文件，其中包含可执行任意代码的 pickle payload
2. 恶意文件经过特殊构造使 `picklescan` 扫描失败（`scan_err != 0`）但不报告为 infected
3. 用户通过 API 上传模型，InvokeAI 调用 `scan_file_path` 扫描
4. 扫描失败（`scan_err != 0`），但 `infected_files == 0`，检查通过
5. `torch_load(checkpoint)` 加载恶意模型，触发 RCE

**Why Standard Scanners Miss It**:
- CodeQL: 标准 query 将 `scan_file_path` 视为 sanitization 函数，认为检查后的路径是安全的，不会分析检查逻辑的完整性
- Bandit: 不分析条件检查的逻辑正确性，只关注是否存在 `torch.load` 调用

**How to Detect**:
1. **定位 Sink**: Grep `torch.load` / `torch_load` 调用
2. **检查前置扫描**: 查找调用前是否有 `picklescan` / `scan_file_path` / `fickling` 等扫描操作
3. **验证扫描结果处理**: 确认是否同时检查了 `infected_files` **和** `scan_err`（两者都非零时应拒绝加载）
4. **检查默认参数**: 注意 `scan=False` 等默认参数可能导致扫描被跳过

**Similar Vulnerabilities**: GHSA-mcrp-whpw-jp68, CVE-2025-49655 (Keras torch.load)

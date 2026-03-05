# Path Traversal Vulnerability Cases (CWE-22/23)

本文件包含 7 个真实 Python 路径穿越漏洞案例，每个案例代表一种独特的攻击模式。所有代码片段均从实际 patch diff 中提取。

---

### Case 1: mlflow — API 参数传递 Bug 导致路径验证完全失效 (CVE-2023-1177, CVSS 9.8)

**Root Cause**: `validate_path_is_safe()` 函数被错误地传入了函数对象自身而非实际路径参数，导致路径验证形同虚设。

**Source -> Sink 路径**:
- **Source**: HTTP 请求路径 `GET /mlflow-artifacts/artifacts/<artifact_path>` 中的 `artifact_path`
- **Sink**: `artifact_repo.download_artifacts(artifact_path)` 执行任意文件下载
- **Sanitization Gap**: `validate_path_is_safe(validate_path_is_safe)` 将函数对象传给自身而非传入 `artifact_path`，验证完全无效

**Vulnerable Code Pattern** (`mlflow/server/handlers.py`):
```python
@catch_mlflow_exception
def _download_artifact(artifact_path):
    """
    GET /mlflow-artifacts/artifacts/<artifact_path>
    """
    # BUG: 传入了函数对象自身，而非 artifact_path
    validate_path_is_safe(validate_path_is_safe)  # <-- 应为 validate_path_is_safe(artifact_path)
    tmp_dir = tempfile.TemporaryDirectory()
    artifact_repo = _get_artifact_repo_mlflow_artifacts()
    dst = artifact_repo.download_artifacts(artifact_path, tmp_dir.name)
    return send_file(dst)

@catch_mlflow_exception
def _upload_artifact(artifact_path):
    """
    PUT /mlflow-artifacts/artifacts/<artifact_path>
    """
    # 同样的 BUG
    validate_path_is_safe(validate_path_is_safe)  # <-- 应为 validate_path_is_safe(artifact_path)
    head, tail = posixpath.split(artifact_path)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = os.path.join(tmp_dir, tail)
```

**Attack Path**:
1. 攻击者发送 `GET /mlflow-artifacts/artifacts/../../etc/passwd`
2. `artifact_path` 包含 `../../etc/passwd`，但 `validate_path_is_safe` 被传入了函数对象自身
3. 验证函数对函数对象调用 `str()` 时永远不会触发路径检查
4. `artifact_repo.download_artifacts("../../etc/passwd")` 直接读取服务器上的任意文件

**Why Standard Scanners Miss It**:
- CodeQL: 标准 taint tracking 会认为 `validate_path_is_safe()` 调用构成了 sanitizer，但不检查参数是否正确
- Bandit: 不进行数据流分析，无法检测"sanitizer 被错误调用"的模式

**How to Detect**:
1. **定位 Sink**: Grep `validate_path_is_safe\|sanitize_path\|check_path` — 找到所有路径验证调用
2. **检查参数一致性**: 验证传入验证函数的参数是否确实是需要验证的变量（而非常量、函数对象或其他变量）
3. **验证上下文**: 检查路由处理函数中，路径参数是否在使用前正确传入验证函数
4. **CodeQL 自定义查询方向**: 创建查询检测 "sanitizer 函数被调用但参数不来自 source" 的模式

**Similar Vulnerabilities**:
- GHSA-x422-6qhv-p29g (CVE-2023-2356): MLflow 同一代码库中的相对路径穿越
- GHSA-554w-xh4j-8w64 (CVE-2023-6831): MLflow 的 Windows 反斜杠路径穿越变体

---

### Case 2: mlflow — HTTP 响应头 Content-Disposition 文件名注入 (CVE-2024-0520, CVSS 10.0)

**Root Cause**: 从外部 HTTP 响应的 `Content-Disposition` 头中提取文件名后，未验证其是否包含路径分隔符，直接用于构造本地文件路径。

**Source -> Sink 路径**:
- **Source**: 外部 HTTP 服务器返回的 `Content-Disposition: attachment; filename=../../tmp/poc.txt` 头
- **Sink**: `os.path.join(dst_path, basename)` 构造写入路径后执行文件下载
- **Sanitization Gap**: 未对提取的 `basename` 进行路径遍历检查，直接用于路径拼接

**Vulnerable Code Pattern** (`mlflow/data/http_dataset_source.py`):
```python
class HTTPDatasetSource(DatasetSource):
    def load(self, dst_path=None) -> str:
        # 从 HTTP 响应头提取文件名
        resp = cloud_storage_http_request("GET", self.url)
        content_disposition = resp.headers.get("Content-Disposition")
        if content_disposition:
            _, params = cgi.parse_header(content_disposition)
            file_name = params.get("filename")
            # 直接使用外部服务器提供的文件名，可能包含 ../../
            basename = file_name.strip("'\"")
        elif path is not None:
            basename = posixpath.basename(path)
        # basename 可能是 "../../tmp/poc.txt"
        # 直接拼接为本地路径，导致写入任意位置
        dst = os.path.join(dst_path, basename)
```

**Attack Path**:
1. 攻击者控制一个 HTTP 服务器，返回 `Content-Disposition: attachment; filename=../../tmp/poc.txt`
2. 用户通过 `mlflow.data.from_http()` 加载该数据集
3. MLflow 从响应头提取文件名 `../../tmp/poc.txt`
4. `os.path.join(dst_path, "../../tmp/poc.txt")` 路径穿越，文件写入 `/tmp/poc.txt`

**Why Standard Scanners Miss It**:
- CodeQL: 标准 source 定义不包含 HTTP 响应头（`Content-Disposition`），通常只建模请求参数作为 taint source
- Bandit: 不分析 HTTP 客户端响应数据流，只检查已知的危险函数调用

**How to Detect**:
1. **定位 Sink**: Grep `Content-Disposition\|content_disposition` — 找到从 HTTP 响应中提取文件名的代码
2. **回溯 Source**: 检查提取的 filename 是否来自不可信的外部 HTTP 服务器
3. **验证 Sanitization**: 检查 filename 是否经过 `os.path.basename()` 或路径遍历检查
4. **CodeQL 自定义查询方向**: 将 HTTP response headers 建模为 taint source，追踪到文件系统写入操作

**Similar Vulnerabilities**:
- CVE-2007-4559: Python tarfile 模块本身的路径穿越（经典老洞）
- GHSA-hjqc-jx6g-rwp9 (CVE-2025-12060): Keras 压缩包解压中的类似模式

---

### Case 3: pgAdmin4 — Session ID 路径穿越 + Pickle 反序列化 RCE (CVE-2024-2044, CVSS 10.0)

**Root Cause**: 使用 `os.path.join()` 将用户可控的 session ID 拼接为会话文件路径，未验证 session ID 是否包含路径穿越序列。攻击者可通过路径穿越让服务器加载恶意 pickle 文件实现 RCE。

**Source -> Sink 路径**:
- **Source**: Cookie 中的 `session` ID（用户可控的字符串）
- **Sink**: `os.path.join(self.path, sid)` 拼接路径后，`pickle.load(open(fname, 'rb'))` 反序列化
- **Sanitization Gap**: `os.path.join()` 不阻止路径穿越，session ID 未做格式验证

**Vulnerable Code Pattern** (`web/pgadmin/utils/session.py`):
```python
class ManagedSessionStore:
    def __init__(self, path, secret, ...):
        self.path = path  # session 文件存储目录

    def exists(self, sid):
        fname = os.path.join(self.path, sid)  # sid 来自 cookie，可含 ../
        return os.path.exists(fname)

    def get(self, sid, digest):
        fname = os.path.join(self.path, sid)  # 路径穿越！
        if os.path.exists(fname):
            with open(fname, 'rb') as f:
                randval, hmac_digest, data = load(f)  # pickle.load 反序列化
                # 如果 sid = "../../../../tmp/malicious.pickle"
                # 攻击者可反序列化任意 pickle 文件 -> RCE

    def put(self, session):
        fname = os.path.join(self.path, session.sid)
        with open(fname, 'wb') as f:
            dump((session.randval, session.hmac_digest, dict(session)), f)
```

**Attack Path**:
1. (Windows) 攻击者在 SMB 共享或可写位置放置恶意 pickle 文件
2. 攻击者构造 cookie，将 session ID 设置为 `../../../../tmp/malicious.pickle`
3. pgAdmin 使用 `os.path.join(sessions_dir, "../../../../tmp/malicious.pickle")` 构造文件路径
4. `pickle.load()` 反序列化恶意文件，执行任意代码

**Why Standard Scanners Miss It**:
- CodeQL: 需要将 "cookie 中的 session ID" 建模为 taint source，且追踪到 `os.path.join` + `pickle.load` 的组合 sink。标准 query 通常不覆盖此路径
- Bandit: B301 检测 `pickle.load()` 但不进行数据流分析确认路径参数是否可控

**How to Detect**:
1. **定位 Sink**: Grep `pickle\.load\|pickle\.loads\|load(f)` 在 session 处理相关模块中
2. **回溯 Source**: 检查文件路径是否由 session ID 构造，session ID 是否来自 cookie
3. **验证 Sanitization**: 检查是否用了 `werkzeug.security.safe_join()` 替代 `os.path.join()`
4. **CodeQL 自定义查询方向**: 检测 "cookie/session_id -> os.path.join -> file open -> pickle.load" 链

**Similar Vulnerabilities**:
- CVE-2024-4068: 其他 Web 框架的 session 文件路径穿越
- 通用模式: 任何使用文件系统存储 session 且用 `os.path.join()` 拼接 session ID 的应用

---

### Case 4: Flask-Reuploaded — 文件上传 name 参数路径穿越 + 扩展名绕过 (CVE-2026-27641, CVSS 9.8)

**Root Cause**: 文件上传的 `name` 参数未经 sanitization 直接用于路径拼接和文件名覆盖，且在 `name` 覆盖原始文件名后未重新验证扩展名，导致路径穿越 + 扩展名绕过双重漏洞。

**Source -> Sink 路径**:
- **Source**: `UploadSet.save(storage, name=request.form["custom_name"])` 中的 `name` 参数
- **Sink**: `storage.save(target)` 将文件保存到穿越后的路径
- **Sanitization Gap**: `name` 参数未调用 `secure_filename()`，且 name 覆盖后不重新检查扩展名白名单

**Vulnerable Code Pattern** (`src/flask_uploads/flask_uploads.py`):
```python
class UploadSet:
    def save(self, storage, folder=None, name=None):
        if folder is None and name is not None and "/" in name:
            folder, name = os.path.split(name)
            # name = "../../templates/evil.html" -> folder="../../templates", name="evil.html"
            # folder 未经 sanitization!

        basename = self.get_basename(storage.filename)
        if not self.extension_allowed(extension(basename)):
            raise UploadNotAllowed()

        if name:
            if name.endswith('.'):
                basename = name + extension(basename)
            else:
                basename = name  # 直接替换文件名，绕过上面的扩展名检查！

        if folder:
            target_folder = os.path.join(self.config.destination, folder)
            # os.path.join("/uploads", "../../templates") -> 路径穿越
        target = os.path.join(target_folder, basename)
        storage.save(target)  # 写入任意路径
```

**Attack Path**:
1. 攻击者上传合法的 `.jpg` 文件，但设置 `name="../../../templates/evil.html"`
2. `os.path.split` 将 name 拆分为 folder=`../../templates` 和 name=`evil.html`
3. 扩展名检查使用的是原始文件名 `.jpg`（通过白名单），但 `basename` 被替换为 `evil.html`
4. 文件写入 `templates/evil.html`，通过 Flask SSTI 实现 RCE

**Why Standard Scanners Miss It**:
- CodeQL: 标准 query 检查 `secure_filename()` 的使用，但 `name` 参数是上传库的 API 参数而非直接的 `request.files.filename`
- Bandit: 不分析第三方库 API 参数的安全性

**How to Detect**:
1. **定位 Sink**: Grep `\.save\(.*name=\|upload.*save` — 找到文件上传保存操作
2. **回溯 Source**: 检查 `name` 参数是否来自用户输入（`request.form`, `request.args`）
3. **验证 Sanitization**: 检查 `name` 参数是否经过 `secure_filename()` 处理，以及处理后是否重新验证扩展名
4. **CodeQL 自定义查询方向**: 追踪用户输入到文件上传库的 `name`/`filename` 参数

**Similar Vulnerabilities**:
- CVE-2023-3625: Flask-Upload 类似的路径穿越
- 通用模式: 所有允许用户指定上传文件名的库

---

### Case 5: Unstructured — 邮件 MSG 附件文件名路径穿越 (CVE-2025-64712, CVSS 9.8)

**Root Cause**: 解析 MSG 邮件时，直接使用附件的 `file_name` 属性构造临时文件路径。攻击者可构造含路径穿越序列的 MSG 附件文件名，写入任意位置。

**Source -> Sink 路径**:
- **Source**: MSG 邮件文件中 `attachment.file_name` 属性（如 `../../../etc/cron.d/malicious`）
- **Sink**: 临时文件创建/写入操作，使用未 sanitize 的文件名
- **Sanitization Gap**: 未对 `file_name` 调用 `os.path.basename()` 或 `secure_filename()`

**Vulnerable Code Pattern** (`unstructured/partition/msg.py`):
```python
class _AttachmentPartitioner:
    @property
    def _attachment_file_name(self) -> str:
        """The original name of the attached file, no path.
        This value is 'unknown' if it is not present in the MSG file.
        """
        # 直接返回附件的原始文件名，可能包含 ../../../etc/passwd
        return self._attachment.file_name or "unknown"
        # 该文件名随后被用于构造临时文件路径
        # 当 process_attachments=True 时，附件内容被写入此路径
```

**Patch 修复代码**（对比）:
```python
    @property
    def _attachment_file_name(self) -> str:
        raw_filename = self._attachment.file_name or "unknown"
        # 同时处理 Unix 和 Windows 路径分隔符
        safe_filename = os.path.basename(raw_filename.replace("\\", "/"))
        safe_filename = safe_filename.replace("\0", "")  # 移除 null bytes
        if not safe_filename or safe_filename in (".", ".."):
            safe_filename = "unknown"
        return safe_filename
```

**Attack Path**:
1. 攻击者构造恶意 MSG 文件，设置附件文件名为 `../../../etc/cron.d/malicious`
2. 应用使用 `partition_msg(msg_file, process_attachments=True)` 处理该文件
3. 附件内容被写入 `../../../etc/cron.d/malicious`，穿越到系统关键目录
4. 写入 cron job 或覆盖配置文件实现 RCE

**Why Standard Scanners Miss It**:
- CodeQL: 标准 taint source 不包含 "邮件附件文件名" 这一非常规输入源
- Bandit: 不分析文件格式解析库的数据流

**How to Detect**:
1. **定位 Sink**: Grep `attachment.*file_name\|attachment.*filename` — 找到从附件/嵌入文件中提取文件名的代码
2. **回溯 Source**: 确认 filename 来自不可信的外部文件格式（MSG, EML, ZIP, DOCX 等）
3. **验证 Sanitization**: 检查是否用 `os.path.basename(name.replace("\\", "/"))` 同时处理两种路径分隔符
4. **CodeQL 自定义查询方向**: 将文件格式解析结果（附件名、嵌入文件名）建模为 taint source

**Similar Vulnerabilities**:
- CVE-2024-3429 (LoLLMS): 类似的文件名未 sanitize 模式
- 通用模式: 所有处理 ZIP/TAR/MSG/DOCX 等包含嵌入文件名的格式解析器

---

### Case 6: Keras — Tar 压缩包 symlink PATH_MAX 绕过安全过滤 (CVE-2025-12060, CVSS 9.8)

**Root Cause**: `tarfile.extractall()` 缺少 `filter="data"` 参数。虽然实现了 `filter_safe_paths()` 函数，但 symlink 的 PATH_MAX 绕过发生在提取阶段（而非 member 枚举阶段），导致安全过滤被绕过。同时 `zipfile.extractall()` 完全没有安全过滤。

**Source -> Sink 路径**:
- **Source**: 通过 `keras.utils.get_file(url, extract=True)` 下载的外部 tar/zip 压缩包
- **Sink**: `archive.extractall(path)` (zip) 和 `archive.extractall(path, members=filter_safe_paths(archive))` (tar)
- **Sanitization Gap**: zip 完全无过滤；tar 的 `filter_safe_paths()` 在 member 枚举时检查但 symlink PATH_MAX 绕过发生在提取时

**Vulnerable Code Pattern** (`keras/src/utils/file_utils.py`):
```python
def extract_archive(file_path, path=".", archive_format="auto"):
    if is_match_fn(file_path):
        with open_fn(file_path) as archive:
            if zipfile.is_zipfile(file_path):
                # Zip archive — 完全没有安全过滤！
                archive.extractall(path)
            else:
                # Tar archive — 有过滤但缺少 filter="data"
                archive.extractall(
                    path, members=filter_safe_paths(archive)
                    # 缺少 filter="data" 参数
                    # symlink PATH_MAX 绕过在 extractall 内部发生
                    # filter_safe_paths 只在枚举阶段检查，无法阻止提取阶段的绕过
                )
```

**Patch 修复代码**（对比）:
```python
def extract_open_archive(archive, path="."):
    if isinstance(archive, zipfile.ZipFile):
        archive.extractall(
            path, members=filter_safe_zipinfos(archive.infolist())  # 新增 zip 过滤
        )
    else:
        extractall_kwargs = {}
        if sys.version_info >= (3, 12) and sys.version_info < (3, 14):
            extractall_kwargs = {"filter": "data"}  # 新增 filter="data"
        archive.extractall(
            path, members=filter_safe_tarinfos(archive), **extractall_kwargs
        )
```

**Attack Path**:
1. 攻击者构造包含 16+ 层深度 symlink 链的恶意 tar 文件（每层使用长目录名）
2. 用户调用 `keras.utils.get_file(malicious_url, extract=True)` 下载并解压
3. `filter_safe_paths()` 在枚举阶段检查 symlink 路径看起来安全
4. 提取阶段 symlink 解析因 PATH_MAX 限制失败，回退到字面路径解释
5. `../../../../target/file` 被写入缓存目录之外

**Why Standard Scanners Miss It**:
- CodeQL: 可以检测到 `extractall()` 调用，但 `filter_safe_paths` 会被误认为是有效的 sanitizer
- Bandit: B603 检查 tarfile 使用但不分析 filter 参数的语义

**How to Detect**:
1. **定位 Sink**: Grep `extractall\(` — 找到所有压缩包解压调用
2. **检查 filter 参数**: tar 解压是否使用了 `filter="data"` (Python 3.12+)
3. **检查 zip 解压**: `zipfile.extractall()` 是否有 member 过滤
4. **验证自定义过滤器**: 如果有自定义 member 过滤，检查是否处理了 symlink 场景
5. **CodeQL 自定义查询方向**: 检测 `tarfile.extractall()` 缺少 `filter="data"` 且自定义过滤不充分的情况

**Similar Vulnerabilities**:
- CVE-2007-4559: Python tarfile 模块的经典路径穿越
- CVE-2023-0286: ZipSlip 模式在不同语言/框架中的变体
- GHSA-wxcx-gg9c-fwp2 (CVE-2024-35198): TorchServe 的类似压缩包/URL 路径穿越

---

### Case 7: pyLoad — Form 参数不完整 Sanitization 的路径穿越 (CVE-2025-54802, CVSS 9.8)

**Root Cause**: 使用 `str.replace("/", "").replace("\\", "").replace(":", "")` 对用户输入进行 sanitization，但此方法无法阻止 `..` 与其他技巧的组合绕过（如编码、交替分隔符等），且在某些边缘情况下仍可构造有效的穿越路径。

**Source -> Sink 路径**:
- **Source**: `POST /addcrypted` 表单中的 `package` 参数（无需认证）
- **Sink**: `os.path.join(dl_path, sanitized_package + ".dlc")` + `open(dlc_path, mode="wb")`
- **Sanitization Gap**: `replace("/", "").replace("\\", "")` 不处理路径穿越序列 `..`，且 `os.path.join` 在特定输入下可被绕过

**Vulnerable Code Pattern** (`src/pyload/webui/app/blueprints/cnl_blueprint.py`):
```python
@bp.route("/addcrypted", methods=["POST"])
def addcrypted():
    package = flask.request.form.get(
        "package", flask.request.form.get("source", flask.request.form.get("referer"))
    )
    dl_path = api.get_config_value("general", "storage_folder")
    dlc_path = os.path.join(
        dl_path,
        # 看似移除了路径分隔符，但 ".." 没有被处理
        package.replace("/", "").replace("\\", "").replace(":", "") + ".dlc"
    )
    dlc = flask.request.form["crypted"].replace(" ", "+")
    with open(dlc_path, mode="wb") as fp:  # 写入穿越后的路径
        fp.write(dlc)
```

**Attack Path**:
1. 攻击者发送 `POST /addcrypted` 无需认证
2. 设置 `package=../../../../etc/cron.d/payload`，`crypted=base64(cron_job_content)`
3. `replace` 移除了 `/` 但 `..` 被保留，在某些 OS/文件系统配置下结合 `os.path.join` 仍可穿越
4. 或攻击者利用编码/其他分隔符绕过 replace 链
5. 写入 cron job 文件实现 RCE

**Patch 修复代码**（对比）:
```python
    dlc_filename = package.replace("/", "").replace("\\", "").replace(":", "") + ".dlc"
    dlc_path = os.path.join(dl_path, dlc_filename)
    dlc_path = os.path.normpath(dlc_path)
    # 新增: 确保最终路径在下载目录内
    if not os.path.abspath(dlc_path).startswith(os.path.abspath(dl_path) + os.sep):
        return "failed: invalid package name\r\n", 400
```

**Why Standard Scanners Miss It**:
- CodeQL: `replace()` 调用可能被视为 sanitizer，但 CodeQL 不分析 replace 的完整性
- Bandit: 不检测 `os.path.join` 的路径穿越模式

**How to Detect**:
1. **定位 Sink**: Grep `os\.path\.join.*replace\|replace.*os\.path\.join` — 找到 replace + join 的组合模式
2. **分析 replace 完整性**: 检查是否仅移除了分隔符但未处理 `..`，或是否遗漏了某些分隔符变体
3. **验证 Containment Check**: replace 后是否有 `os.path.abspath().startswith()` 验证
4. **CodeQL 自定义查询方向**: 检测 "使用 str.replace 作为唯一 sanitizer 的 os.path.join" 模式

**Similar Vulnerabilities**:
- GHSA-f798-qm4r-23r5 (CVE-2023-6015): MLflow 的类似文件写入漏洞
- CVE-2024-3429 (LoLLMS): `sanitize_path` 函数在 Windows 上可被绕过
- 通用模式: 所有使用字符替换而非路径解析做 sanitization 的代码

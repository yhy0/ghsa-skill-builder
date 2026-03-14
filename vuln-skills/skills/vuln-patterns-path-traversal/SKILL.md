---
name: vuln-patterns-path-traversal
description: "Use when auditing Python code involving file path operations (os.path.join, pathlib), file upload/download, archive extraction (tarfile, zipfile), or file inclusion. Covers CWE-22/23. Keywords: path traversal, directory traversal, zip slip, file upload, file download, extractall, Content-Disposition, secure_filename, session file, symlink, os.path.join absolute path override"
---

# Path Traversal Vulnerability Patterns (CWE-22/23)

当审计 Python 代码中涉及文件路径构造、文件读写操作、压缩包处理、文件上传下载时加载此 Skill。

本 Skill 从 15 个真实高危漏洞（CVSS 9.7-10.0）中提炼出 7 种独特的路径穿越攻击模式，覆盖 ML 框架（MLflow、Keras、TorchServe）、AI 工具（LoLLMS、InvokeAI、Unstructured）、Web 框架组件（Flask-Reuploaded、pgAdmin4）和下载工具（pyLoad）。

## Detection Strategy

### Sources（用户输入入口）

按危险程度排序：

1. **HTTP 请求参数**: `request.args`, `request.form`, `request.json` 中的文件名、路径参数
2. **HTTP 响应头**: `Content-Disposition` 头中的 `filename` 字段（来自外部服务器）
3. **URL 路径段**: Flask/Django 路由中的 `<path:artifact_path>` 变量
4. **压缩包内嵌路径**: tar/zip 档案中的 `member.name`、`member.linkname`（symlink）
5. **邮件附件文件名**: MSG/EML 等邮件格式中 `attachment.file_name`
6. **API 输入的 source/URL 字段**: 模型注册、数据集下载等 API 中的 `source` 参数
7. **Session ID / Cookie**: 用作文件路径查找的会话标识符
8. **AI Agent 工具调用参数**: `tool_call.arguments` 中的 `localFilePath` 等

### Sinks（危险函数/操作）

| Sink 类型 | 具体函数 | 典型场景 |
|-----------|---------|---------|
| **文件写入** | `open(path, 'wb')`, `storage.save(target)`, `shutil.copy()` | 文件上传、附件保存 |
| **文件读取** | `open(path, 'rb')`, `send_file(path)`, `send_from_directory()` | 文件下载、预览 |
| **路径拼接** | `os.path.join(base, user_input)`, `pathlib.Path(base) / user_input` | 几乎所有场景（注意：两者都存在绝对路径覆盖问题） |
| **压缩包解压** | `tarfile.extractall()`, `zipfile.extractall()` | 数据集下载、模型加载 |
| **反序列化** | `pickle.load(open(path))` | Session 加载（路径穿越 + 反序列化链） |
| **HTTP 下载** | `urllib.request.urlretrieve()`, `requests.get(url)` | 模型/数据集下载 |

### Sanitization（安全屏障）

**有效的防护措施（按推荐程度排序）：**

1. `os.path.realpath()` + 路径前缀检查（containment check）：`resolved.startswith(base_dir + os.sep)`
2. `werkzeug.utils.secure_filename()` — 移除路径分隔符和 `..`
3. `werkzeug.security.safe_join()` — 安全拼接路径
4. `pathlib.Path.resolve()` + `is_relative_to()` (Python 3.9+)
5. `tarfile.extractall(filter="data")` (Python 3.12+)
6. `os.path.basename()` — 提取纯文件名（需同时处理 `\` 和 `/`）

**常见的无效/不完整防护（需重点关注）：**

1. 仅用 `str.replace("/", "").replace("\\", "")` 移除分隔符 — 可被 `..` + 编码绕过
2. 仅用 `os.path.join()` 或 `pathlib.Path(base) / user_input` — **不能防止绝对路径覆盖**（`os.path.join("/base", "/etc/passwd")` 返回 `/etc/passwd`，`PurePosixPath("/base") / "/etc/passwd"` 同理）
3. 仅检查 `".." in path` 但不解码 URL — `%2E%2E%2F` 绕过
4. 正则过滤 `..` 但不处理 Windows 路径 — `..\\` 绕过
5. `filter_safe_paths()` 在提取前检查但不用 `filter="data"` — symlink PATH_MAX 绕过
6. 在下载后才检查路径 — TOCTOU（Time-of-check to time-of-use）

### 检测路径

**Step 1: 定位 Sink**

搜索以下模式，建立候选列表：

```python
# 文件操作类
grep -rn "open(.*['\"]w" --include="*.py"
grep -rn "\.save(" --include="*.py"
grep -rn "send_file\|send_from_directory" --include="*.py"
grep -rn "shutil\.\(copy\|move\|rmtree\)" --include="*.py"

# 路径拼接类
grep -rn "os\.path\.join" --include="*.py"
grep -rn "pathlib.*/" --include="*.py"

# 压缩包类
grep -rn "extractall\|extract(" --include="*.py"
grep -rn "tarfile\|zipfile" --include="*.py"

# 反序列化 + 路径
grep -rn "pickle\.load\|loads(" --include="*.py"
```

**Step 2: 回溯 Source**

从每个 sink 的路径参数向上追踪，确认数据是否最终来源于用户可控输入。重点关注：
- Flask 路由参数（`<path:xxx>`）
- `request.form` / `request.args` / `request.json`
- 外部 HTTP 响应中提取的文件名
- 压缩包 member 列表中的文件名
- 数据库中存储的路径（可能是之前注入的）

**Step 3: 验证 Sanitization**

检查 source 到 sink 路径上是否有上述"有效防护措施"中的任何一种。如果只有"无效/不完整防护"中的模式，标记为潜在漏洞。

**Step 4: 检查平台差异**

- Windows 上 `\` 也是路径分隔符 — `..\\` 可绕过只过滤 `/` 的检查
- Windows 驱动器路径 `C:path` 可绕过 `PurePosixPath.is_absolute()` 检查
- PATH_MAX 限制在不同 OS 上不同 — 影响 symlink 解析

## Detection Checklist

- [ ] **`os.path.join(base, user_input)` 和 `Path(base) / user_input`** — `user_input` 是否可能是绝对路径？（绝对路径会覆盖 base）
- [ ] **路径拼接后是否有 containment check** — `resolved_path.startswith(base_dir + os.sep)`？
- [ ] **`tarfile.extractall()`** — 是否使用了 `filter="data"` 参数？是否过滤 symlink？
- [ ] **`zipfile.extractall()`** — 是否验证了 member 文件名不含 `..`？
- [ ] **文件上传的 `name`/`filename` 参数** — 是否用了 `secure_filename()`？是否在 sanitize 后再次验证扩展名？
- [ ] **HTTP 响应中的 `Content-Disposition` filename** — 是否用 `os.path.basename()` 提取纯文件名？
- [ ] **邮件附件文件名** — 是否同时处理了 Unix（`/`）和 Windows（`\`）路径分隔符？
- [ ] **Session 文件路径** — 是否用 `safe_join()` 替代 `os.path.join()`？
- [ ] **URL 中的路径参数** — 是否在验证前进行了 URL 解码（`urllib.parse.unquote()`）？
- [ ] **`.replace("/", "").replace("\\", "")` 模式** — 是否还有其他绕过方式（如编码、`..` 拼接）？
- [ ] **路径验证时机** — 是否在文件操作**之前**验证（而非之后）？

## False Positive Exclusion Guide

以下情况可以排除误报：

1. **路径来自硬编码或配置文件** — source 不可被用户控制
2. **已使用 `os.path.realpath()` + `startswith()` 做 containment check** — 有效防护
3. **已使用 `werkzeug.security.safe_join()`** — 内置路径穿越防护
4. **`tarfile.extractall()` 使用了 `filter="data"`** — Python 3.12+ 的安全提取
5. **路径参数经过 `int()` 或 UUID 转换** — 无法注入路径字符
6. **路径仅用于数据库查询而非文件系统操作** — 非 sink
7. **应用运行在容器/沙箱中且文件系统只读** — 缓解措施（但仍应修复）
8. **路径拼接的 base 和 user_input 都来自同一可信源** — 如配置文件中的两个字段

**保持警惕的边界情况：**
- `secure_filename()` 后未重新验证扩展名 — 仍可能导致扩展名绕过
- `os.path.basename()` 只传入了 Unix 风格路径但运行在 Windows 上 — 需要先替换 `\\` 为 `/`
- 路径验证在 download 之后 — TOCTOU 问题

## Real-World Cases

详见 [references/cases.md](references/cases.md)，包含 7 个真实漏洞案例，覆盖以下模式：

| Case | 漏洞模式 | Source | Sink |
|------|---------|--------|------|
| 1 | API source URL 路径穿越 | Model Registry API `source` 参数 | `validate_path_is_safe` 传参 bug |
| 2 | HTTP 响应头文件名注入 | `Content-Disposition` header | `os.path.join()` 文件写入 |
| 3 | Session ID 路径穿越 + 反序列化 | Cookie `session_id` | `os.path.join()` + `pickle.load()` |
| 4 | 文件上传 name 参数穿越 + 扩展名绕过 | Upload `name` parameter | `storage.save()` |
| 5 | 邮件附件文件名穿越 | MSG `attachment.file_name` | 临时文件写入 |
| 6 | Tar 压缩包 symlink PATH_MAX 绕过 | `tarfile` member paths | `extractall()` |
| 7 | Form 参数不完整 sanitization | `request.form["package"]` | `os.path.join()` + `open()` |

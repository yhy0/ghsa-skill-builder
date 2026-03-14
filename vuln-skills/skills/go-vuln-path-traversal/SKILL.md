---
name: go-vuln-path-traversal
description: "Use when auditing Go code involving file path operations, archive extraction, symlink handling, container volume mounts, or HTTP file serving. Covers CWE-22/59. Keywords: path traversal, directory traversal, filepath.Join, symlink, archive extraction, zip slip, tar, volume mount, go-git, Helm chart, os.Open, filepath.Clean"
---

# Go Path Traversal Vulnerability Patterns (CWE-22/59)

当审计 Go 代码中涉及文件路径操作、归档解压、符号链接处理、容器卷挂载时加载此 Skill。

## Detection Strategy

**Sources（攻击入口）：**
- HTTP 请求参数中的文件名/路径（`r.URL.Query().Get("file")`）
- Archive 条目路径（`tar.Header.Name`, `zip.File.Name`）
- Git 仓库中的文件路径（go-git clone/checkout）
- gRPC 请求中的文件路径字段
- Helm chart 中的文件引用
- 用户上传的文件名（`multipart.FileHeader.Filename`）

**Sinks（危险操作）：**
- `os.Open(path)`, `os.Create(path)`, `os.ReadFile(path)`
- `os.WriteFile(path, data, perm)`
- `filepath.Join(base, userInput)` -- **当 userInput 为绝对路径时覆盖 base**
- `os.Symlink(target, link)`, `os.Readlink(path)`
- `http.ServeFile(w, r, path)`, `http.FileServer(http.Dir(root))`
- `io.Copy` 写入用户控制的路径
- Container runtime 的 volume mount 路径解析

**Sanitization（路径安全屏障）：**
- `filepath.Clean(path)` -- 规范化路径但不防止绝对路径
- `filepath.Rel(base, target)` -- 计算相对路径，返回 `..` 开头则越界
- `strings.HasPrefix(filepath.Clean(path), base)` -- Clean 后前缀检查
- `filepath.EvalSymlinks(path)` -- 解析所有符号链接后再检查
- `securejoin.SecureJoin(base, path)` -- `filepath-securejoin` 库

**检测路径：**

```bash
# filepath.Join 与用户输入
grep -rn "filepath.Join" --include="*.go"
# 文件操作
grep -rn "os.Open\|os.Create\|os.ReadFile\|os.WriteFile\|os.MkdirAll" --include="*.go"
# Archive 解压
grep -rn "tar.NewReader\|zip.OpenReader\|archive/tar\|archive/zip" --include="*.go"
# Symlink 操作
grep -rn "os.Symlink\|os.Readlink\|os.Lstat\|filepath.EvalSymlinks" --include="*.go"
# HTTP 文件服务
grep -rn "http.ServeFile\|http.FileServer\|http.Dir" --include="*.go"
# 路径安全检查
grep -rn "filepath.Clean\|filepath.Rel\|securejoin\|SecureJoin" --include="*.go"
```

1. 定位文件操作的 Sink 函数（`os.Open`, `os.Create`, `http.ServeFile` 等）
2. 回溯路径参数的来源，确认是否包含用户输入
3. 验证路径是否经过安全检查：
   - `filepath.Join(base, input)` 是否考虑了 input 为绝对路径的情况？
   - Archive 解压是否检查了条目路径包含 `..` 或绝对路径？
   - 是否先 `filepath.EvalSymlinks` 再做路径检查（防止 symlink TOCTOU）？
   - `http.FileServer` 的 root 目录是否限制了访问范围？
4. 若无安全检查或检查可被绕过 -> 标记为候选漏洞

## Detection Checklist

- [ ] **`filepath.Join` 绝对路径覆盖审计** (CWE-22)：`filepath.Join("/safe/base", userInput)` 当 `userInput = "/etc/passwd"` 时，结果为 `/etc/passwd` 而非 `/safe/base/etc/passwd`。必须在 Join 后检查结果是否仍在 base 目录下。
- [ ] **Archive 解压路径审计** (CWE-22)：`tar.NewReader`/`zip.OpenReader` 解压时，是否检查 `header.Name` 不包含 `..` 且不是绝对路径？是否使用 `filepath.Clean` 后再验证前缀？
- [ ] **Symlink TOCTOU 审计** (CWE-59)：是否先 `os.Lstat` 检查文件类型，然后 `os.Open` 读取？攻击者可在检查后、读取前将文件替换为 symlink。应使用 `filepath.EvalSymlinks` 或 `O_NOFOLLOW`。
- [ ] **Container Volume Mount 路径逃逸审计** (CWE-22)：容器 runtime 是否正确解析 volume mount 路径中的 symlink？Pterodactyl Wings 风格的 mount path 是否在 container namespace 内解析？
- [ ] **`http.ServeFile`/`http.FileServer` 审计** (CWE-22)：路径参数是否来自用户输入？`http.Dir` 是否限制在预期目录？是否处理了 `../` 编码变体（`%2e%2e%2f`）？
- [ ] **Git Clone/Checkout 路径审计** (CWE-22)：go-git 的 `worktree.Checkout` 是否验证文件路径？恶意 Git 仓库是否能通过精心构造的 tree object 写入任意位置？
- [ ] **Helm Chart Symlink 审计** (CWE-59)：Helm chart 包中的 symlink 是否指向 chart 目录外部？`helm install` 是否跟随了恶意 symlink？
- [ ] **`filepath.EvalSymlinks` 使用时机审计** (CWE-59)：路径安全检查是否在 `EvalSymlinks` 之后执行？先检查再 Eval 可能被 symlink 绕过。

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- **`filepath.Join` 用于拼接硬编码路径** -- 如 `filepath.Join(configDir, "settings.yaml")`，无用户输入
- **`http.FileServer` 仅服务静态资源目录** -- 且路径参数不可被用户控制
- **`os.ReadFile` 读取配置文件** -- 路径来自环境变量或命令行参数（非 HTTP 输入）
- **测试代码中的临时目录操作** -- `t.TempDir()` 中的文件操作

以下模式**需要深入检查**：
- **`filepath.Clean` 后直接使用** -- `Clean` 不防止绝对路径，需要额外的前缀检查
- **`strings.Contains(path, "..")` 作为唯一检查** -- 可被 `....//` 等变体绕过
- **Lstat + Open 分开调用** -- 存在 TOCTOU 窗口
- **`io.Copy` 目标路径来自 archive header** -- Zip Slip 经典模式

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

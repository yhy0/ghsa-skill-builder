# Go Path Traversal — Real-World Cases

7 个真实 Go 路径遍历漏洞案例，每个代表一种独特的攻击模式。

---

### Case 1: Mattermost -- Board 导入功能任意文件读取 (CVE-2025-20051, CVSS 10.0)

**Root Cause**: Mattermost 的 Board 导入功能在处理上传的归档文件时，未验证归档中的文件路径，攻击者可通过 `../` 路径读取服务器上的任意文件。

**Source -> Sink 路径**:
- **Source**: 用户上传的 Board 导入归档文件（含恶意路径条目）
- **Sink**: `os.Open(filepath.Join(extractDir, entry.Name))` — 路径遍历到 extractDir 之外
- **Sanitization Gap**: 归档条目的 `Name` 未经路径检查直接用于文件操作

**Vulnerable Code Pattern**:
```go
func extractArchive(archivePath, destDir string) error {
    reader, _ := zip.OpenReader(archivePath)
    for _, f := range reader.File {
        // BUG: f.Name 可能包含 "../../../etc/passwd"
        targetPath := filepath.Join(destDir, f.Name)
        // 未检查 targetPath 是否仍在 destDir 内
        os.MkdirAll(filepath.Dir(targetPath), 0755)
        outFile, _ := os.Create(targetPath)
        rc, _ := f.Open()
        io.Copy(outFile, rc)
    }
    return nil
}
```

**Attack Path**:
1. 攻击者构造恶意 Board 导入归档，包含 `../../../etc/passwd` 路径的文件条目
2. 通过 Mattermost Board 导入功能上传归档
3. 服务器解压时写入 `extractDir` 之外的路径
4. 读取或覆盖服务器上的任意文件

**How to Detect**:
1. Grep `zip.OpenReader\|tar.NewReader` 找到归档解压代码
2. 检查 entry name 是否经过 `filepath.Clean` + 前缀检查
3. 验证 `filepath.Join(base, entry.Name)` 的结果是否以 `base` 为前缀

---

### Case 2: BuildKit -- Mount Stub Cleaner 导致宿主机文件系统访问 (CVE-2024-23650, CVSS 10.0)

**Root Cause**: BuildKit 的 mount stub cleaner 在清理构建过程中的 mount 残留时，未正确处理符号链接，攻击者可通过恶意 Dockerfile 使 cleaner 操作宿主机文件系统。

**Source -> Sink 路径**:
- **Source**: 恶意 Dockerfile 中的 `COPY --from` 或 `RUN --mount` 指令创建的 symlink
- **Sink**: Host filesystem 上的文件删除/修改操作
- **Sanitization Gap**: Cleaner 跟随了 symlink，未使用 `filepath.EvalSymlinks` 验证目标路径

**Vulnerable Code Pattern**:
```go
func cleanupMountStubs(rootfs string) error {
    return filepath.Walk(rootfs, func(path string, info os.FileInfo, err error) error {
        if isMountStub(path) {
            // BUG: 如果 path 包含 symlink 组件，可能指向 rootfs 外部
            os.Remove(path) // 可能删除宿主机文件
        }
        return nil
    })
}
```

**Attack Path**:
1. 构造恶意 Dockerfile，在 build context 中创建 symlink 指向宿主机路径
2. 触发 BuildKit 构建
3. Mount stub cleaner 跟随 symlink 执行清理操作
4. 删除或修改宿主机文件

**How to Detect**:
1. Grep `filepath.Walk\|os.Remove\|os.RemoveAll` 查找文件遍历删除
2. 检查遍历过程中是否解析了 symlink（`filepath.EvalSymlinks`）
3. 确认操作目标是否始终在预期的根目录内

---

### Case 3: go-git -- 恶意 Git 仓库导致客户端 RCE (CVE-2024-45388, CVSS 9.8)

**Root Cause**: go-git 在处理 Git server 返回的 pack 文件时，未验证其中包含的文件路径。恶意 Git server 可以返回包含 `../` 路径的 tree object，导致 checkout 时写入工作目录外的文件。

**Source -> Sink 路径**:
- **Source**: 恶意 Git server 返回的 pack 文件中的 tree entry name
- **Sink**: `os.Create(filepath.Join(worktree, entry.Name))` — 写入工作目录外
- **Sanitization Gap**: Tree entry name 未经路径验证

**Vulnerable Code Pattern**:
```go
func (w *Worktree) checkoutFile(f *object.File) error {
    // BUG: f.Name 来自 Git server，可能包含 "../.git/hooks/post-checkout"
    filename := filepath.Join(w.Filesystem.Root(), f.Name)
    // 未验证 filename 是否在 worktree 内
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    reader, _ := f.Reader()
    io.Copy(file, reader)
    return nil
}
```

**Attack Path**:
1. 攻击者搭建恶意 Git server
2. 受害者执行 `git clone` 指向恶意 server
3. Server 返回包含 `../.git/hooks/post-checkout` 路径的 tree object
4. go-git 在 checkout 时写入 `.git/hooks/` 目录
5. 恶意 hook 在下次 Git 操作时执行，实现 RCE

**How to Detect**:
1. Grep `Checkout\|checkoutFile\|worktree.*Create` 查找 checkout 相关代码
2. 检查文件路径是否来自不可信的 Git object
3. 验证路径是否经过 `filepath.Clean` + 前缀检查

---

### Case 4: Helm -- Symlink Following 导致 Chart 外文件访问 (CVE-2024-26147, CVSS 9.8)

**Root Cause**: Helm 在处理 chart 包时跟随了 symlink，恶意 chart 可以包含指向宿主机文件系统的 symlink，导致 `helm install` 时读取或覆盖 chart 目录外的文件。

**Source -> Sink 路径**:
- **Source**: Helm chart 包中的 symlink 文件
- **Sink**: 宿主机文件系统的读取/写入
- **Sanitization Gap**: Chart 解压和模板渲染时未检查 symlink 目标

**Vulnerable Code Pattern**:
```go
func (c *Chart) loadTemplates(dir string) error {
    return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        // BUG: filepath.Walk 默认跟随 symlink
        // 如果 path 是 symlink -> /etc/shadow，将读取宿主机文件
        content, err := os.ReadFile(path)
        c.Templates = append(c.Templates, &chart.File{
            Name: path,
            Data: content,
        })
        return nil
    })
}
```

**Attack Path**:
1. 构造恶意 Helm chart，包含 symlink `templates/evil.yaml -> /etc/shadow`
2. 将 chart 发布到 Helm 仓库或直接分发
3. 受害者执行 `helm install` 或 `helm template`
4. Helm 跟随 symlink 读取宿主机文件，内容被包含在渲染输出中

**How to Detect**:
1. Grep `filepath.Walk\|os.ReadFile\|ioutil.ReadFile` 查找文件遍历读取
2. 检查是否在处理前验证了 symlink（`os.Lstat` 检查 `info.Mode()&os.ModeSymlink`）
3. 确认 `filepath.EvalSymlinks` 后的路径是否仍在预期目录内

---

### Case 5: Pterodactyl Wings -- 竞态条件导致容器文件隔离绕过 (CVE-2024-27297, CVSS 10.0)

**Root Cause**: Pterodactyl Wings（游戏服务器管理面板）在检查文件路径安全性后、实际访问文件之前存在竞态窗口（TOCTOU）。攻击者可在检查通过后将普通文件替换为 symlink，指向容器外的宿主机文件。

**Source -> Sink 路径**:
- **Source**: 用户通过 API 请求的文件路径
- **Sink**: `os.Open(path)` — 在安全检查之后执行
- **Sanitization Gap**: `Lstat` 检查和 `Open` 操作之间存在竞态窗口

**Vulnerable Code Pattern**:
```go
func (fs *Filesystem) SafeOpen(path string) (*os.File, error) {
    resolved := filepath.Join(fs.root, filepath.Clean(path))

    // Step 1: 检查文件不是 symlink
    info, err := os.Lstat(resolved)
    if info.Mode()&os.ModeSymlink != 0 {
        return nil, ErrSymlink
    }

    // BUG: TOCTOU — 攻击者可在此时将文件替换为 symlink

    // Step 2: 打开文件
    return os.Open(resolved) // 此时可能已经是 symlink
}
```

**Attack Path**:
1. 在容器中创建普通文件 `/data/normal.txt`
2. 通过 API 请求读取 `/data/normal.txt`
3. Wings 执行 `Lstat` 检查 — 通过（是普通文件）
4. 在检查和打开之间，将 `normal.txt` 替换为 symlink -> `/etc/shadow`
5. Wings 执行 `Open` — 跟随 symlink 读取宿主机文件

**How to Detect**:
1. Grep `os.Lstat.*os.Open\|Lstat.*Open` 查找分开的检查和操作
2. 确认检查和操作之间是否存在竞态窗口
3. 建议使用 `O_NOFOLLOW` flag 或 `filepath-securejoin` 库

---

### Case 6: Flux -- Kustomization 路径遍历 (CVE-2022-24877, CVSS 10.0)

**Root Cause**: Flux 的 kustomize-controller 在处理 Kustomization 资源时，未正确验证 `spec.path` 字段中的路径，允许使用 `../` 遍历到 Git 仓库外的文件系统。

**Source -> Sink 路径**:
- **Source**: Kustomization CR 的 `spec.path` 字段
- **Sink**: `kustomize build` 在指定路径执行
- **Sanitization Gap**: `spec.path` 未检查 `..` 组件

**Vulnerable Code Pattern**:
```go
func (r *KustomizationReconciler) build(source sourcev1.Source, kustomization kustomizev1.Kustomization) error {
    // BUG: spec.Path 可能包含 "../../../"
    dirPath := filepath.Join(source.GetArtifact().Path, kustomization.Spec.Path)
    // 未验证 dirPath 是否在 source artifact 目录内
    return r.kustomizeBuild(dirPath)
}
```

**Attack Path**:
1. 创建 Kustomization 资源，`spec.path` 设为 `../../../etc`
2. Flux kustomize-controller 拼接路径并执行 `kustomize build`
3. Kustomize 读取 controller 容器中 `/etc` 下的文件
4. 通过 Kustomize output 泄露容器中的敏感文件

**How to Detect**:
1. Grep `spec.Path\|Spec.Path\|kustomization.*path` 查找路径字段使用
2. 检查路径是否经过 `filepath.Clean` + `strings.HasPrefix` 验证
3. 确认 `filepath.Join(base, userPath)` 结果是否在 base 内

---

### Case 7: NATS Server -- 管理操作路径遍历 (CVE-2024-29868, CVSS 9.8)

**Root Cause**: NATS server 的管理 API 在处理 account/stream 操作时，未正确验证 name 参数中的路径组件，允许通过 `../` 访问其他 account 的数据或配置。

**Source -> Sink 路径**:
- **Source**: NATS 管理 API 请求中的 account/stream name
- **Sink**: JetStream 数据目录的文件操作
- **Sanitization Gap**: Name 参数未过滤 `../` 等路径遍历字符

**Vulnerable Code Pattern**:
```go
func (s *Server) handleStreamCreate(name string) error {
    // BUG: name 可能包含 "../other_account/stream1"
    streamDir := filepath.Join(s.dataDir, "jetstream", accountName, "streams", name)
    return os.MkdirAll(streamDir, 0750)
}
```

**Attack Path**:
1. 通过 NATS 管理 API 创建 stream，name 设为 `../other_account/streams/target`
2. NATS server 拼接路径时遍历到其他 account 的数据目录
3. 读取或覆盖其他 account 的 stream 数据

**How to Detect**:
1. Grep `filepath.Join.*name\|filepath.Join.*stream\|filepath.Join.*account` 查找动态路径拼接
2. 检查 name/identifier 参数是否过滤了 `../` 和绝对路径
3. 确认是否使用了 `filepath.Base(name)` 或白名单字符验证

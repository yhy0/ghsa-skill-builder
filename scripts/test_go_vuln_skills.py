#!/usr/bin/env python3
"""
Go vuln skills 测试脚本

按照 writing-skills 指南中 Reference 类型 skill 的测试方法：
1. 静态合规测试：frontmatter 格式、必需章节（可直接 python3 运行）
2. 子代理场景测试：Retrieval / Application / Gap（通过 Agent 工具执行）

测试对象：vuln-skills/skills/go-vuln-*/SKILL.md（7 个 Go 代码审计 skills）

用法：
  python3 scripts/test_go_vuln_skills.py          # 运行静态测试
  python3 scripts/test_go_vuln_skills.py --scenes  # 打印子代理场景定义（供 Agent 调用）
"""

import re
import os
import sys
import json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKILLS = [
    'auth-bypass', 'path-traversal', 'injection', 'dos',
    'info-disclosure', 'crypto-tls', 'ssrf-requestforgery',
]

# ============================================================
# Test Infrastructure
# ============================================================

class TestResult:
    def __init__(self, skill, test_type, test_name, passed, detail=""):
        self.skill = skill
        self.test_type = test_type
        self.test_name = test_name
        self.passed = passed
        self.detail = detail

    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        msg = f"[{status}] {self.skill} / {self.test_type} / {self.test_name}"
        if self.detail:
            msg += f"\n       {self.detail}"
        return msg


results = []

def check(skill, test_type, test_name, condition, detail=""):
    r = TestResult(skill, test_type, test_name, condition, detail)
    results.append(r)
    return r


def load_skill(name):
    path = os.path.join(BASE, f"vuln-skills/skills/go-vuln-{name}/SKILL.md")
    with open(path) as f:
        return f.read()


def load_cases(name):
    path = os.path.join(BASE, f"vuln-skills/skills/go-vuln-{name}/references/cases.md")
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return ""


# ============================================================
# Part 1: Static Compliance Tests (Frontmatter)
# ============================================================

def test_compliance(name, content):
    """Check frontmatter compliance per writing-skills guidelines."""
    fm_match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    check(name, "compliance", "has_frontmatter", fm_match is not None)
    if not fm_match:
        return

    fm = fm_match.group(0)
    fm_body = fm_match.group(1)

    # Frontmatter size ≤ 1024
    fm_bytes = len(fm.encode('utf-8'))
    check(name, "compliance", f"frontmatter_size({fm_bytes}B≤1024)", fm_bytes <= 1024)

    # Only name and description fields
    fields = re.findall(r'^(\w+):', fm_body, re.MULTILINE)
    extra = [f for f in fields if f not in ('name', 'description')]
    check(name, "compliance", "only_name_and_description_fields", len(extra) == 0,
          f"extra fields: {extra}" if extra else "")

    # Name: letters, numbers, hyphens only
    name_match = re.search(r'name:\s*(\S+)', fm_body)
    if name_match:
        n = name_match.group(1)
        check(name, "compliance", "name_valid_chars", bool(re.match(r'^[a-z0-9-]+$', n)),
              f"name='{n}'")
        check(name, "compliance", "name_matches_expected",
              n == f"go-vuln-{name}", f"expected 'go-vuln-{name}', got '{n}'")

    # Description starts with "Use when"
    desc_match = re.search(r'description:\s*"(.*?)"', fm_body, re.DOTALL)
    if desc_match:
        desc = desc_match.group(1)
        check(name, "compliance", "description_starts_use_when", desc.startswith("Use when"),
              f"starts with: '{desc[:30]}...'")
        # Description ≤ 500 chars
        check(name, "compliance", f"description_length({len(desc)}≤500)",
              len(desc) <= 500)


# ============================================================
# Part 1: Static Structure Tests
# ============================================================

def test_structure(name, content):
    """Check required sections per skill structure."""
    required_sections = {
        "Detection Strategy": r'## Detection Strategy|## Detection',
        "Detection Checklist": r'## Detection Checklist',
        "False Positive": r'## False Positive',
        "Real-World Cases": r'## Real-World Cases|references/cases\.md',
    }
    for section, pattern in required_sections.items():
        check(name, "structure", f"has_{section.lower().replace(' ','_').replace('-','_')}",
              bool(re.search(pattern, content)),
              f"pattern: {pattern}")

    # Should have Source → Sink → Sanitization model
    check(name, "structure", "has_sources", "source" in content.lower() or "Sources" in content)
    check(name, "structure", "has_sinks", "sink" in content.lower() or "Sinks" in content)
    check(name, "structure", "has_sanitization", "sanitization" in content.lower() or "Sanitization" in content)

    # Should be Go-specific (not Python)
    check(name, "structure", "is_go_specific",
          '*.go' in content or '--include="*.go"' in content or "`.go`" in content,
          "Should have Go file patterns")

    # Should have grep code block
    has_grep = bool(re.search(r'```(?:bash|sh)?\n.*grep.*--include.*\.go', content, re.DOTALL))
    check(name, "structure", "has_grep_code_block", has_grep,
          "Should have grep code block with *.go patterns")

    # Should have checklist items ≥ 5
    checkbox_count = len(re.findall(r'- \[ \]', content))
    check(name, "structure", f"has_checklist_items({checkbox_count}≥5)",
          checkbox_count >= 5,
          f"Found {checkbox_count} checkbox items")

    # Cases file should exist and have ≥ 5 cases
    cases = load_cases(name)
    check(name, "structure", "has_cases_file", len(cases) > 0,
          "references/cases.md should exist")
    if cases:
        case_count = len(re.findall(r'### Case \d', cases))
        check(name, "structure", f"has_cases({case_count}≥5)",
              case_count >= 5,
              f"Found {case_count} cases in cases.md")


# ============================================================
# Part 2: Subagent Scenario Definitions
# ============================================================
# 每个场景包含：
#   skill: 对应 skill 名
#   type: retrieval / application / gap
#   scenario: 给子代理的场景描述（含代码片段）
#   expected: 子代理输出应包含的关键点列表
#   description: 人类可读的测试描述

SCENARIOS = [
    # --- go-vuln-injection ---
    {
        "skill": "injection",
        "type": "retrieval",
        "description": "模糊问题：exec.Command 安全吗？应区分 shell 调用 vs 直接传参",
        "scenario": (
            "我在 Go 代码里看到 `exec.Command` 调用，这安全吗？"
            "请基于 skill 内容告诉我哪些情况下安全、哪些不安全。"
        ),
        "expected": [
            "区分 exec.Command 直接传参（安全）和通过 sh -c 调用（不安全）",
            "提到参数独立传递不经过 shell 是安全的",
            "提到 sh -c 或 bash -c 拼接用户输入是命令注入",
        ],
    },
    {
        "skill": "injection",
        "type": "application",
        "description": "含命令注入的代码片段，应识别漏洞",
        "scenario": (
            "审计以下 Go 代码片段，找出安全问题并给出修复建议：\n\n"
            "```go\n"
            "func RunUserScript(w http.ResponseWriter, r *http.Request) {\n"
            "    script := r.URL.Query().Get(\"script\")\n"
            "    cmd := exec.Command(\"sh\", \"-c\", script)\n"
            "    output, err := cmd.CombinedOutput()\n"
            "    if err != nil {\n"
            "        http.Error(w, err.Error(), 500)\n"
            "        return\n"
            "    }\n"
            "    w.Write(output)\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别为命令注入（CWE-78 或 OS command injection）",
            "指出 sh -c + 用户输入是根因",
            "建议使用参数化 exec.Command 或白名单验证",
        ],
    },
    {
        "skill": "injection",
        "type": "gap",
        "description": "参数注入 CWE-88，不经过 shell 但通过 flag 注入",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func CloneRepo(repoURL, uploadPack string) error {\n"
            "    cmd := exec.Command(\"git\", \"clone\",\n"
            "        \"--upload-pack=\"+uploadPack, repoURL, \"/tmp/repo\")\n"
            "    return cmd.Run()\n"
            "}\n"
            "```\n\n"
            "uploadPack 来自用户输入。这段代码没用 sh -c，安全吗？"
        ),
        "expected": [
            "识别为参数注入（CWE-88 或 argument injection）",
            "指出 --upload-pack 可被用户控制执行任意命令",
            "不因为没有 sh -c 就判断安全",
        ],
    },

    # --- go-vuln-path-traversal ---
    {
        "skill": "path-traversal",
        "type": "retrieval",
        "description": "模糊问题：filepath.Join 安全吗？应警告绝对路径覆盖",
        "scenario": (
            "我用 `filepath.Join(baseDir, userInput)` 来拼接路径，"
            "这样能防止路径遍历吗？"
        ),
        "expected": [
            "警告 filepath.Join 当 userInput 为绝对路径时会覆盖 baseDir",
            "建议使用 filepath.Rel 或 strings.HasPrefix 做后置检查",
            "提到 filepath.Clean 不能防止绝对路径问题",
        ],
    },
    {
        "skill": "path-traversal",
        "type": "application",
        "description": "zip 解压无路径检查，应识别 zip slip",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func ExtractZip(zipPath, destDir string) error {\n"
            "    r, _ := zip.OpenReader(zipPath)\n"
            "    defer r.Close()\n"
            "    for _, f := range r.File {\n"
            "        path := filepath.Join(destDir, f.Name)\n"
            "        if f.FileInfo().IsDir() {\n"
            "            os.MkdirAll(path, 0755)\n"
            "            continue\n"
            "        }\n"
            "        outFile, _ := os.Create(path)\n"
            "        rc, _ := f.Open()\n"
            "        io.Copy(outFile, rc)\n"
            "        outFile.Close()\n"
            "        rc.Close()\n"
            "    }\n"
            "    return nil\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别为 Zip Slip 漏洞（路径遍历 CWE-22）",
            "指出 f.Name 可含 ../ 导致写到 destDir 外",
            "建议解压前检查路径是否在 destDir 内",
        ],
    },
    {
        "skill": "path-traversal",
        "type": "gap",
        "description": "Lstat+Open 分开调用导致 symlink TOCTOU",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func SafeReadFile(base, name string) ([]byte, error) {\n"
            "    path := filepath.Join(base, name)\n"
            "    // 检查不是符号链接\n"
            "    info, err := os.Lstat(path)\n"
            "    if err != nil {\n"
            "        return nil, err\n"
            "    }\n"
            "    if info.Mode()&os.ModeSymlink != 0 {\n"
            "        return nil, fmt.Errorf(\"symlinks not allowed\")\n"
            "    }\n"
            "    // 读取文件\n"
            "    return os.ReadFile(path)\n"
            "}\n"
            "```\n\n"
            "这段代码检查了 symlink 再读取，安全吗？"
        ),
        "expected": [
            "识别 TOCTOU（Time-of-check to Time-of-use）竞态条件",
            "指出 Lstat 和 ReadFile 之间攻击者可替换文件为 symlink",
            "建议使用 O_NOFOLLOW 或 filepath.EvalSymlinks 后再操作",
        ],
    },

    # --- go-vuln-auth-bypass ---
    {
        "skill": "auth-bypass",
        "type": "retrieval",
        "description": "K8s admission webhook 安全风险",
        "scenario": (
            "Kubernetes admission webhook 有什么安全风险？"
            "在 Go 中实现 admission webhook 时需要注意什么？"
        ),
        "expected": [
            "提到 webhook 升级/故障期间可能被绕过（failOpen vs failClosed）",
            "提到 webhook 的 namespaceSelector 配置问题",
            "提到验证 admission request 来源的重要性",
        ],
    },
    {
        "skill": "auth-bypass",
        "type": "application",
        "description": "缺少认证中间件的 gin router",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func SetupRouter() *gin.Engine {\n"
            "    r := gin.Default()\n"
            "\n"
            "    // Public routes\n"
            "    r.POST(\"/login\", loginHandler)\n"
            "    r.GET(\"/health\", healthHandler)\n"
            "\n"
            "    // Admin routes\n"
            "    r.GET(\"/admin/users\", listUsersHandler)\n"
            "    r.DELETE(\"/admin/users/:id\", deleteUserHandler)\n"
            "    r.PUT(\"/admin/config\", updateConfigHandler)\n"
            "\n"
            "    return r\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别 /admin/* 路由缺少认证/授权中间件",
            "建议使用 gin.Group + Use() 添加 auth 中间件",
            "指出 DELETE 和 PUT 等敏感操作无保护",
        ],
    },
    {
        "skill": "auth-bypass",
        "type": "gap",
        "description": "K8s Impersonate-User header 透传导致冒充",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func ProxyToCluster(w http.ResponseWriter, r *http.Request) {\n"
            "    // 从请求中获取目标集群\n"
            "    clusterID := mux.Vars(r)[\"cluster\"]\n"
            "    cluster := getCluster(clusterID)\n"
            "\n"
            "    // 创建到目标集群的请求\n"
            "    proxyReq, _ := http.NewRequest(r.Method, cluster.APIURL+r.URL.Path, r.Body)\n"
            "\n"
            "    // 透传所有请求头\n"
            "    for key, values := range r.Header {\n"
            "        for _, v := range values {\n"
            "            proxyReq.Header.Add(key, v)\n"
            "        }\n"
            "    }\n"
            "\n"
            "    // 添加集群认证\n"
            "    proxyReq.Header.Set(\"Authorization\", \"Bearer \"+cluster.Token)\n"
            "\n"
            "    resp, _ := http.DefaultClient.Do(proxyReq)\n"
            "    // ... copy response\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别 Impersonate-User/Impersonate-Group header 透传风险",
            "指出攻击者可通过设置 K8s impersonation headers 冒充其他用户",
            "建议过滤或显式控制转发的 header",
        ],
    },

    # --- go-vuln-dos ---
    {
        "skill": "dos",
        "type": "retrieval",
        "description": "goroutine 可能导致什么安全问题",
        "scenario": (
            "Go 的 goroutine 可能导致什么安全问题？"
            "在编写高并发 Go 服务时需要注意什么？"
        ),
        "expected": [
            "提到 goroutine 泄漏（无限创建不释放）",
            "提到缺少超时控制导致 goroutine 堆积",
            "建议使用 context 控制 goroutine 生命周期",
        ],
    },
    {
        "skill": "dos",
        "type": "application",
        "description": "io.ReadAll 无限制读取 HTTP body",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func UploadHandler(w http.ResponseWriter, r *http.Request) {\n"
            "    body, err := io.ReadAll(r.Body)\n"
            "    if err != nil {\n"
            "        http.Error(w, \"read error\", 500)\n"
            "        return\n"
            "    }\n"
            "    // process body...\n"
            "    processData(body)\n"
            "    w.WriteHeader(200)\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别为 DoS 漏洞：无限制读取请求体",
            "指出攻击者可发送超大 body 耗尽内存",
            "建议使用 io.LimitReader 或 http.MaxBytesReader 限制大小",
        ],
    },
    {
        "skill": "dos",
        "type": "gap",
        "description": "HTTP handler 无 recover 导致 panic DoS",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func main() {\n"
            "    mux := http.NewServeMux()\n"
            "    mux.HandleFunc(\"/api/process\", func(w http.ResponseWriter, r *http.Request) {\n"
            "        var data map[string]interface{}\n"
            "        json.NewDecoder(r.Body).Decode(&data)\n"
            "        // 直接访问 nested key，无 nil 检查\n"
            "        result := data[\"config\"].(map[string]interface{})[\"value\"].(string)\n"
            "        w.Write([]byte(result))\n"
            "    })\n"
            "    http.ListenAndServe(\":8080\", mux)\n"
            "}\n"
            "```\n\n"
            "这段代码使用标准库 HTTP server，有什么安全问题？"
        ),
        "expected": [
            "识别 type assertion panic 可导致进程崩溃",
            "指出标准库 http.Server 内置了 per-request recover（注意这一点）或建议显式添加 recover 中间件",
            "建议使用 comma-ok 模式做安全类型断言",
        ],
    },

    # --- go-vuln-info-disclosure ---
    {
        "skill": "info-disclosure",
        "type": "retrieval",
        "description": "Go struct 序列化的安全风险",
        "scenario": (
            "Go struct 序列化（JSON 等）有什么安全风险？"
            "使用 fmt 打印 struct 有什么需要注意的？"
        ),
        "expected": [
            "提到 json:\"-\" tag 用于隐藏敏感字段",
            "提到 %+v 或 %#v 会打印 struct 所有字段包括敏感信息",
            "建议敏感字段实现自定义 Stringer 接口或使用 json:\"-\"",
        ],
    },
    {
        "skill": "info-disclosure",
        "type": "application",
        "description": "log.Printf %+v 打印含密码的 struct",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "type DatabaseConfig struct {\n"
            "    Host     string `json:\"host\"`\n"
            "    Port     int    `json:\"port\"`\n"
            "    Username string `json:\"username\"`\n"
            "    Password string `json:\"password\"`\n"
            "    SSLKey   string `json:\"ssl_key\"`\n"
            "}\n"
            "\n"
            "func InitDB(cfg DatabaseConfig) (*sql.DB, error) {\n"
            "    log.Printf(\"Connecting to database with config: %+v\", cfg)\n"
            "    dsn := fmt.Sprintf(\"%s:%s@tcp(%s:%d)/mydb\",\n"
            "        cfg.Username, cfg.Password, cfg.Host, cfg.Port)\n"
            "    return sql.Open(\"mysql\", dsn)\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别 %+v 会打印 Password 和 SSLKey 到日志",
            "建议使用 json:\"-\" 或自定义 String() 方法隐藏敏感字段",
            "指出日志中的凭证泄露风险",
        ],
    },
    {
        "skill": "info-disclosure",
        "type": "gap",
        "description": "K8s CRD status 中含明文 Secret",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "type BackupStatus struct {\n"
            "    Phase          string `json:\"phase\"`\n"
            "    Message        string `json:\"message\"`\n"
            "    S3Endpoint     string `json:\"s3Endpoint\"`\n"
            "    S3AccessKey    string `json:\"s3AccessKey\"`\n"
            "    S3SecretKey    string `json:\"s3SecretKey\"`\n"
            "    LastBackupTime string `json:\"lastBackupTime\"`\n"
            "}\n"
            "\n"
            "func (r *BackupReconciler) updateStatus(backup *v1alpha1.Backup) error {\n"
            "    backup.Status = BackupStatus{\n"
            "        Phase:       \"Completed\",\n"
            "        S3Endpoint:  r.config.S3Endpoint,\n"
            "        S3AccessKey: r.config.S3AccessKey,\n"
            "        S3SecretKey: r.config.S3SecretKey,\n"
            "    }\n"
            "    return r.client.Status().Update(context.TODO(), backup)\n"
            "}\n"
            "```\n\n"
            "这是一个 K8s operator 的代码，将备份状态写入 CRD status。"
        ),
        "expected": [
            "识别 S3 凭证（AccessKey/SecretKey）写入 CRD status 是明文暴露",
            "指出任何有 CRD read 权限的用户都能看到这些凭证",
            "建议凭证存储在 Secret 中，status 只引用 Secret 名称",
        ],
    },

    # --- go-vuln-crypto-tls ---
    {
        "skill": "crypto-tls",
        "type": "retrieval",
        "description": "InsecureSkipVerify 的风险",
        "scenario": (
            "Go 的 `tls.Config{InsecureSkipVerify: true}` 是做什么的？"
            "什么场景下需要用它？有什么风险？"
        ),
        "expected": [
            "解释 InsecureSkipVerify 跳过 TLS 证书验证",
            "指出中间人攻击风险",
            "建议仅在测试环境使用，生产环境应正确配置 CA",
        ],
    },
    {
        "skill": "crypto-tls",
        "type": "application",
        "description": "JWT parse 未指定 WithValidMethods 导致算法混淆",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func ValidateToken(tokenString string) (*jwt.Token, error) {\n"
            "    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {\n"
            "        return []byte(os.Getenv(\"JWT_SECRET\")), nil\n"
            "    })\n"
            "    if err != nil {\n"
            "        return nil, err\n"
            "    }\n"
            "    if !token.Valid {\n"
            "        return nil, fmt.Errorf(\"invalid token\")\n"
            "    }\n"
            "    return token, nil\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别 JWT 算法混淆漏洞（缺少 WithValidMethods 或算法检查）",
            "指出攻击者可切换为 none 或 HMAC 算法绕过验证",
            "建议在 keyfunc 中验证 token.Method 或使用 WithValidMethods",
        ],
    },
    {
        "skill": "crypto-tls",
        "type": "gap",
        "description": "HMAC 比较使用 == 导致时间侧信道",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func VerifyWebhookSignature(payload []byte, signature string, secret []byte) bool {\n"
            "    mac := hmac.New(sha256.New, secret)\n"
            "    mac.Write(payload)\n"
            "    expected := hex.EncodeToString(mac.Sum(nil))\n"
            "    return expected == signature\n"
            "}\n"
            "```\n\n"
            "这段代码用 HMAC-SHA256 验证 webhook 签名，安全吗？"
        ),
        "expected": [
            "识别时间侧信道攻击（timing side-channel）",
            "指出 == 字符串比较不是常量时间操作",
            "建议使用 hmac.Equal 或 subtle.ConstantTimeCompare",
        ],
    },

    # --- go-vuln-ssrf-requestforgery ---
    {
        "skill": "ssrf-requestforgery",
        "type": "retrieval",
        "description": "Go HTTP client 的安全风险",
        "scenario": (
            "Go 的 HTTP client（http.Get、http.Client 等）有什么安全风险？"
            "在 Go 中发起 HTTP 请求时需要注意什么？"
        ),
        "expected": [
            "提到 SSRF（Server-Side Request Forgery）风险",
            "指出需要验证/限制目标 URL（不允许访问内网地址）",
            "提到 http.Client 应设置超时避免 hang",
        ],
    },
    {
        "skill": "ssrf-requestforgery",
        "type": "application",
        "description": "template.HTML 绕过自动转义导致 XSS",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func RenderPage(w http.ResponseWriter, r *http.Request) {\n"
            "    userBio := r.FormValue(\"bio\")\n"
            "    data := struct {\n"
            "        Bio template.HTML\n"
            "    }{\n"
            "        Bio: template.HTML(userBio),\n"
            "    }\n"
            "    tmpl := template.Must(template.ParseFiles(\"profile.html\"))\n"
            "    tmpl.Execute(w, data)\n"
            "}\n"
            "```"
        ),
        "expected": [
            "识别 template.HTML() 类型转换绕过了 html/template 的自动转义",
            "指出用户输入直接转为 template.HTML 导致 XSS",
            "建议移除 template.HTML 转换或对输入做 HTML sanitize",
        ],
    },
    {
        "skill": "ssrf-requestforgery",
        "type": "gap",
        "description": "缺少 CSRF 保护的 gin POST handler",
        "scenario": (
            "审计以下 Go 代码片段：\n\n"
            "```go\n"
            "func SetupRouter() *gin.Engine {\n"
            "    r := gin.Default()\n"
            "\n"
            "    r.GET(\"/profile\", getProfile)\n"
            "    r.POST(\"/profile/update\", updateProfile)\n"
            "    r.POST(\"/transfer\", transferMoney)\n"
            "    r.POST(\"/password/change\", changePassword)\n"
            "\n"
            "    return r\n"
            "}\n"
            "```\n\n"
            "这些 POST 路由都有认证中间件保护（假设已添加），但还有什么安全问题？"
        ),
        "expected": [
            "识别缺少 CSRF 保护",
            "指出 POST 请求（特别是转账、改密码）需要 CSRF token",
            "建议使用 CSRF 中间件（如 gorilla/csrf 或 gin-csrf）",
        ],
    },
]


def get_scenario_prompt(scenario_def, skill_content):
    """构建子代理的完整 prompt：skill 内容 + 场景 + 评估指令。"""
    return (
        f"你是一个 Go 安全审计专家。以下是你的审计参考知识（skill）：\n\n"
        f"<skill>\n{skill_content}\n</skill>\n\n"
        f"---\n\n"
        f"**场景：**\n{scenario_def['scenario']}\n\n"
        f"---\n\n"
        f"请基于上述 skill 内容进行审计分析，输出：\n"
        f"1. 识别到的安全问题（或确认安全的理由）\n"
        f"2. 引用 skill 中的具体模式/checklist 条目\n"
        f"3. 可操作的修复建议\n"
    )


def print_scenarios():
    """打印所有场景定义，供主对话调用 Agent 执行。"""
    for i, s in enumerate(SCENARIOS):
        print(f"\n{'='*60}")
        print(f"Scenario {i+1}/21: [{s['type'].upper()}] go-vuln-{s['skill']}")
        print(f"Description: {s['description']}")
        print(f"Expected points:")
        for ep in s['expected']:
            print(f"  - {ep}")
        print(f"{'='*60}")


# ============================================================
# Main
# ============================================================

def main():
    if '--scenes' in sys.argv:
        print_scenarios()
        return 0

    if '--json-scenes' in sys.argv:
        print(json.dumps(SCENARIOS, ensure_ascii=False, indent=2))
        return 0

    # Static tests only
    missing = []
    for name in SKILLS:
        path = os.path.join(BASE, f"vuln-skills/skills/go-vuln-{name}/SKILL.md")
        if not os.path.exists(path):
            missing.append(name)
    if missing:
        print(f"ERROR: Missing skill files for: {missing}")
        print("Generate skills first before running tests.")
        return 1

    for name in SKILLS:
        content = load_skill(name)
        test_compliance(name, content)
        test_structure(name, content)

    # Print results
    print("=" * 80)
    print("Go Vuln Skills — Static Tests")
    print("=" * 80)

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    # Group by skill
    by_skill = {}
    for r in results:
        by_skill.setdefault(r.skill, []).append(r)

    for skill in SKILLS:
        skill_results = by_skill.get(skill, [])
        skill_pass = sum(1 for r in skill_results if r.passed)
        skill_fail = sum(1 for r in skill_results if not r.passed)
        print(f"\n--- go-vuln-{skill} ({skill_pass}/{len(skill_results)}) ---")

        for r in skill_results:
            if not r.passed:
                print(f"  FAIL: {r.test_type}/{r.test_name}")
                if r.detail:
                    print(f"        {r.detail}")

        if skill_fail == 0:
            print("  All tests passed!")

    print(f"\n{'='*80}")
    print(f"TOTAL: {passed} passed, {failed} failed, {len(results)} total")
    print(f"{'='*80}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

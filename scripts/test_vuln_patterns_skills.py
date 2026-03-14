#!/usr/bin/env python3
"""
vuln-patterns skills 测试脚本

按照 writing-skills 指南中 Reference 类型 skill 的测试方法：
1. 静态合规测试：frontmatter 格式、必需章节（可直接 python3 运行）
2. 子代理场景测试：Retrieval / Application / Gap（通过 Agent 工具执行）

测试对象：vuln-skills/skills/vuln-patterns-*/SKILL.md（6 个 Python 代码审计 skills）

用法：
  python3 scripts/test_vuln_patterns_skills.py          # 运行静态测试
  python3 scripts/test_vuln_patterns_skills.py --scenes  # 打印子代理场景定义
  python3 scripts/test_vuln_patterns_skills.py --json-scenes  # 导出 JSON
"""

import re
import os
import json
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKILLS = ['injection', 'path-traversal', 'auth-bypass',
          'deserialization', 'ssrf', 'xss']

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
    path = os.path.join(BASE, f"vuln-skills/skills/vuln-patterns-{name}/SKILL.md")
    with open(path) as f:
        return f.read()


# ============================================================
# Part 1: Static Compliance Tests
# ============================================================

def test_compliance(name, content):
    """Check frontmatter compliance per writing-skills guidelines."""
    fm_match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    check(name, "compliance", "has_frontmatter", fm_match is not None)
    if not fm_match:
        return

    fm = fm_match.group(0)
    fm_body = fm_match.group(1)

    fm_bytes = len(fm.encode('utf-8'))
    check(name, "compliance", f"frontmatter_size({fm_bytes}B≤1024)", fm_bytes <= 1024)

    fields = re.findall(r'^(\w+):', fm_body, re.MULTILINE)
    extra = [f for f in fields if f not in ('name', 'description')]
    check(name, "compliance", "only_name_and_description_fields", len(extra) == 0,
          f"extra fields: {extra}" if extra else "")

    name_match = re.search(r'name:\s*(\S+)', fm_body)
    if name_match:
        n = name_match.group(1)
        check(name, "compliance", "name_valid_chars", bool(re.match(r'^[a-z0-9-]+$', n)),
              f"name='{n}'")

    desc_match = re.search(r'description:\s*"(.*?)"', fm_body, re.DOTALL)
    if desc_match:
        desc = desc_match.group(1)
        check(name, "compliance", "description_starts_use_when", desc.startswith("Use when"),
              f"starts with: '{desc[:30]}...'")
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

    check(name, "structure", "has_sources", "source" in content.lower() or "Sources" in content)
    check(name, "structure", "has_sinks", "sink" in content.lower() or "Sinks" in content)
    check(name, "structure", "has_sanitization", "sanitization" in content.lower() or "Sanitization" in content)

    has_numbered_steps = bool(re.search(r'(?:Step \d|^\d+\.\s)', content, re.MULTILINE))
    check(name, "structure", "has_detection_path", has_numbered_steps,
          "Should have numbered detection steps")

    checkbox_count = len(re.findall(r'- \[ \]', content))
    check(name, "structure", f"has_checklist_items({checkbox_count}≥5)",
          checkbox_count >= 5,
          f"Found {checkbox_count} checkbox items")

    has_code = bool(re.search(r'```|grep.*-rn|Grep', content))
    check(name, "structure", "has_code_or_grep_patterns", has_code,
          "Should have concrete code examples or grep commands")


# ============================================================
# Part 2: Subagent Scenario Definitions
# ============================================================

SCENARIOS = [
    # --- vuln-patterns-injection ---
    {
        "skill": "injection",
        "type": "retrieval",
        "description": "模糊问题：eval() 在 Python 代码里安全吗？",
        "scenario": (
            "我在 Python 代码里看到 `eval()` 调用，这安全吗？"
            "什么情况下 eval 是危险的？有没有安全的替代方案？"
        ),
        "expected": [
            "区分 eval()（危险）和 ast.literal_eval()（安全替代）",
            "指出 eval 可执行任意 Python 代码",
            "建议使用 ast.literal_eval 或白名单类型转换替代",
        ],
    },
    {
        "skill": "injection",
        "type": "application",
        "description": "subprocess.run shell=True + 用户输入",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "def run_cmd(request):\n"
            "    hostname = request.GET.get('host')\n"
            "    result = subprocess.run(f'ping -c 1 {hostname}', shell=True, capture_output=True)\n"
            "    return HttpResponse(result.stdout)\n"
            "```"
        ),
        "expected": [
            "识别为命令注入（CWE-78）",
            "指出 shell=True + f-string 拼接用户输入是根因",
            "建议使用 subprocess.run(['ping', '-c', '1', hostname], shell=False) 或 shlex.quote",
        ],
    },
    {
        "skill": "injection",
        "type": "gap",
        "description": "Hydra instantiate 动态实例化注入",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "from hydra.utils import instantiate\n"
            "\n"
            "def load_model(config):\n"
            "    # config 来自用户上传的 YAML 文件\n"
            "    model = instantiate(config.model)\n"
            "    return model\n"
            "```\n\n"
            "config.model 中有 `_target_` 字段指定要实例化的类。这安全吗？"
        ),
        "expected": [
            "识别 Hydra instantiate 可被 _target_ 字段控制执行任意类实例化",
            "指出用户控制的 YAML 配置 _target_ 字段等同于代码执行",
            "建议限制 _target_ 的允许值或使用前缀白名单",
        ],
    },

    # --- vuln-patterns-path-traversal ---
    {
        "skill": "path-traversal",
        "type": "retrieval",
        "description": "os.path.join 是否安全",
        "scenario": (
            "用 `os.path.join(base_dir, user_filename)` 拼接路径能防止路径遍历吗？"
        ),
        "expected": [
            "警告 os.path.join 当 user_filename 为绝对路径时会覆盖 base_dir",
            "建议使用 os.path.commonpath 或 os.path.relpath 做后置检查",
            "提到 Python 3.12+ tarfile filter='data' 是安全的归档解压方式",
        ],
    },
    {
        "skill": "path-traversal",
        "type": "application",
        "description": "tarfile.extractall 无过滤解压",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "import tarfile\n"
            "\n"
            "def extract_upload(tar_path, dest_dir):\n"
            "    with tarfile.open(tar_path) as tf:\n"
            "        tf.extractall(path=dest_dir)\n"
            "```"
        ),
        "expected": [
            "识别为路径遍历漏洞（Zip Slip / Tar Slip）",
            "指出 tar 条目中可包含 ../ 或绝对路径",
            "建议使用 Python 3.12+ 的 filter='data' 参数或手动检查成员路径",
        ],
    },
    {
        "skill": "path-traversal",
        "type": "gap",
        "description": "Content-Disposition filename 注入",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "def download_file(request):\n"
            "    filename = request.GET.get('file')\n"
            "    filepath = os.path.join(UPLOAD_DIR, filename)\n"
            "    if os.path.exists(filepath):\n"
            "        response = FileResponse(open(filepath, 'rb'))\n"
            "        response['Content-Disposition'] = f'attachment; filename=\"{filename}\"'\n"
            "        return response\n"
            "```\n\n"
            "这段代码对下载文件的路径做了什么安全检查？"
        ),
        "expected": [
            "识别 os.path.join + 用户输入的路径遍历风险",
            "识别 Content-Disposition filename 的 HTTP header 注入风险",
            "建议检查文件路径在 UPLOAD_DIR 范围内 + 对 filename 做 sanitize",
        ],
    },

    # --- vuln-patterns-auth-bypass ---
    {
        "skill": "auth-bypass",
        "type": "retrieval",
        "description": "DRF permission_classes 安全问题",
        "scenario": (
            "Django REST Framework 的 permission_classes 有什么安全陷阱？"
            "什么情况下会导致认证绕过？"
        ),
        "expected": [
            "提到缺少 permission_classes 默认允许匿名访问",
            "提到 permission_classes 配置为空列表或元组的风险",
            "建议在 settings 中设置全局默认 permission_classes",
        ],
    },
    {
        "skill": "auth-bypass",
        "type": "application",
        "description": "异常处理中的认证绕过",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "def verify_token(token):\n"
            "    try:\n"
            "        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
            "        user_id = payload['user_id']\n"
            "        return User.objects.get(id=user_id)\n"
            "    except Exception:\n"
            "        return User.objects.get(id=1)  # 返回默认管理员用户\n"
            "```"
        ),
        "expected": [
            "识别异常处理中返回默认管理员用户是认证绕过",
            "指出任何无效/过期/恶意 token 都会触发 except 分支",
            "建议异常时返回 None 或抛出认证异常而非回退到默认用户",
        ],
    },
    {
        "skill": "auth-bypass",
        "type": "gap",
        "description": "OpenID Provider URL 用户可控",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "def login_oidc(request):\n"
            "    provider_url = request.GET.get('provider')\n"
            "    client = OpenIDClient(provider_url)\n"
            "    auth_url = client.get_authorization_url()\n"
            "    return redirect(auth_url)\n"
            "```\n\n"
            "这段 OpenID Connect 登录代码有什么安全问题？"
        ),
        "expected": [
            "识别 OpenID Provider URL 由用户控制是认证绕过风险",
            "指出攻击者可指向自建 IdP 颁发任意身份 token",
            "建议 Provider URL 使用白名单或预配置而非用户输入",
        ],
    },

    # --- vuln-patterns-deserialization ---
    {
        "skill": "deserialization",
        "type": "retrieval",
        "description": "torch.load 安全吗",
        "scenario": (
            "Python 的 `torch.load()` 安全吗？加载 PyTorch 模型文件有什么风险？"
        ),
        "expected": [
            "指出 torch.load 默认使用 pickle 反序列化，可执行任意代码",
            "建议使用 torch.load(..., weights_only=True) 或 safetensors 格式",
            "提到 pickle 模型文件可被植入恶意 __reduce__ 方法",
        ],
    },
    {
        "skill": "deserialization",
        "type": "application",
        "description": "yaml.load 不安全调用",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "import yaml\n"
            "\n"
            "def load_config(config_path):\n"
            "    with open(config_path) as f:\n"
            "        return yaml.load(f, Loader=yaml.FullLoader)\n"
            "```\n\n"
            "config_path 指向用户上传的 YAML 文件。"
        ),
        "expected": [
            "识别 yaml.FullLoader 允许执行 Python 对象的构造（虽比 yaml.Loader 安全但仍有风险）",
            "建议使用 yaml.safe_load 或 yaml.SafeLoader",
            "指出 YAML 的 !!python/object 标签可触发代码执行",
        ],
    },
    {
        "skill": "deserialization",
        "type": "gap",
        "description": "ZeroMQ recv_pyobj 隐藏的 pickle",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "import zmq\n"
            "\n"
            "def worker():\n"
            "    context = zmq.Context()\n"
            "    socket = context.socket(zmq.PULL)\n"
            "    socket.connect('tcp://task-server:5555')\n"
            "    while True:\n"
            "        task = socket.recv_pyobj()\n"
            "        process_task(task)\n"
            "```\n\n"
            "这段 ZeroMQ worker 代码从 task server 接收任务。安全吗？"
        ),
        "expected": [
            "识别 recv_pyobj 内部使用 pickle.loads 反序列化",
            "指出如果 task-server 被攻击者控制或通信被劫持，可实现 RCE",
            "建议使用 JSON/msgpack 等安全序列化格式替代 recv_pyobj",
        ],
    },

    # --- vuln-patterns-ssrf ---
    {
        "skill": "ssrf",
        "type": "retrieval",
        "description": "requests.get(user_url) 的风险",
        "scenario": (
            "Python 的 `requests.get(url)` 有什么安全风险？"
            "url 来自用户输入时要注意什么？"
        ),
        "expected": [
            "识别 SSRF 风险：用户可指定内网 URL 访问",
            "提到需要验证 URL 不指向内网地址（127.0.0.1, 10.x, 169.254.x）",
            "提到 DNS rebinding 攻击的风险",
        ],
    },
    {
        "skill": "ssrf",
        "type": "application",
        "description": "SVG 文件中的 SSRF",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "from cairosvg import svg2png\n"
            "\n"
            "def render_svg(request):\n"
            "    svg_content = request.FILES['svg'].read()\n"
            "    png_data = svg2png(bytestring=svg_content)\n"
            "    return HttpResponse(png_data, content_type='image/png')\n"
            "```\n\n"
            "用户上传 SVG 文件并转换为 PNG。"
        ),
        "expected": [
            "识别 SVG 中可包含 xlink:href 等外部资源引用导致 SSRF",
            "指出 CairoSVG 等渲染库会跟随外部资源请求",
            "建议设置 url_fetcher 回调阻断外部请求或预处理 SVG 移除外部引用",
        ],
    },
    {
        "skill": "ssrf",
        "type": "gap",
        "description": "LLM 框架中的 URL 加载 SSRF",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "from llama_index.core import SimpleDirectoryReader\n"
            "from llama_index.readers.web import SimpleWebPageReader\n"
            "\n"
            "def ingest_url(request):\n"
            "    url = request.json.get('url')\n"
            "    documents = SimpleWebPageReader(html_to_text=True).load_data([url])\n"
            "    index.insert_nodes(documents)\n"
            "    return {'status': 'ok'}\n"
            "```\n\n"
            "这是一个 RAG 应用的 URL 摄入端点。"
        ),
        "expected": [
            "识别 LLM 框架的 WebPageReader 是 SSRF sink",
            "指出用户控制的 URL 可访问内网服务和云元数据端点",
            "建议在调用 Reader 前验证 URL 协议和解析后的 IP 地址",
        ],
    },

    # --- vuln-patterns-xss ---
    {
        "skill": "xss",
        "type": "retrieval",
        "description": "Django mark_safe 的风险",
        "scenario": (
            "Django 的 `mark_safe()` 是做什么的？什么时候可以安全使用？"
        ),
        "expected": [
            "指出 mark_safe 将字符串标记为安全的 HTML，跳过自动转义",
            "指出对用户输入使用 mark_safe 等同于 XSS 漏洞",
            "建议仅对硬编码的 HTML 片段使用 mark_safe",
        ],
    },
    {
        "skill": "xss",
        "type": "application",
        "description": "Jinja2 autoescape=False 导致 XSS",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "from jinja2 import Environment\n"
            "\n"
            "env = Environment(autoescape=False)\n"
            "template = env.from_string('<h1>Hello {{ name }}</h1>')\n"
            "\n"
            "def render(request):\n"
            "    name = request.GET.get('name', 'World')\n"
            "    return HttpResponse(template.render(name=name))\n"
            "```"
        ),
        "expected": [
            "识别 autoescape=False 关闭了 Jinja2 自动转义",
            "指出用户输入 name 可包含 <script> 标签导致 XSS",
            "建议设置 autoescape=True 或使用 select_autoescape()",
        ],
    },
    {
        "skill": "xss",
        "type": "gap",
        "description": "Pandas DataFrame.to_html XSS",
        "scenario": (
            "审计以下 Python 代码片段：\n\n"
            "```python\n"
            "import pandas as pd\n"
            "\n"
            "def show_data(request):\n"
            "    query = request.GET.get('q', '')\n"
            "    df = pd.read_sql(f\"SELECT * FROM logs WHERE message LIKE '%{query}%'\", conn)\n"
            "    html_table = df.to_html()\n"
            "    return HttpResponse(html_table)\n"
            "```\n\n"
            "这段代码查询日志并展示为 HTML 表格。"
        ),
        "expected": [
            "识别 SQL 注入（f-string 拼接 SQL）",
            "识别 DataFrame.to_html() 不转义 HTML 内容导致 XSS",
            "建议使用参数化查询 + 对 to_html 输出做 HTML 转义或使用 escape=True",
        ],
    },
]


def get_scenario_prompt(scenario_def, skill_content):
    """构建子代理的完整 prompt。"""
    return (
        f"你是一个 Python 安全审计专家。以下是你的审计参考知识（skill）：\n\n"
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
    """打印所有场景定义。"""
    for i, s in enumerate(SCENARIOS):
        print(f"\n{'='*60}")
        print(f"Scenario {i+1}/{len(SCENARIOS)}: [{s['type'].upper()}] vuln-patterns-{s['skill']}")
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

    for name in SKILLS:
        content = load_skill(name)
        test_compliance(name, content)
        test_structure(name, content)

    # Print results
    print("=" * 80)
    print("vuln-patterns Skills — Static Tests")
    print("=" * 80)

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    by_skill = {}
    for r in results:
        by_skill.setdefault(r.skill, []).append(r)

    for skill in SKILLS:
        skill_results = by_skill.get(skill, [])
        skill_pass = sum(1 for r in skill_results if r.passed)
        skill_fail = sum(1 for r in skill_results if not r.passed)
        print(f"\n--- vuln-patterns-{skill} ({skill_pass}/{len(skill_results)}) ---")

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

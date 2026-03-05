---
name: vuln-patterns-xss
description: "Use when auditing Python web applications involving HTML rendering, template engines (Jinja2, Mako, Django templates), Markdown parsing, DataFrame-to-HTML conversion, or frontend innerHTML assignments. Covers CWE-79. Keywords: XSS, cross-site scripting, HTML injection, mark_safe, |safe, autoescape, bleach, escape, innerHTML, decode_contents, self.write, to_html, format_html"
---

# XSS Vulnerability Patterns (CWE-79)

当审计 Python Web 应用中涉及 HTML 生成、模板渲染、用户内容展示时加载此 Skill。

## Detection Strategy

**Sources（用户可控数据）：**
- HTTP 请求参数：`request.args`, `request.form`, URL 路径段（如 Tornado handler 中的路径参数）
- 数据库查询结果：SQL 查询返回值通过 DataFrame/ORM 渲染到页面（如 pgAdmin 查询结果、MLflow 数据集）
- 外部数据提交接口：Sentry DSN 事件提交、API endpoint 接收的 JSON body
- 用户配置/表单字段：模型描述、任务名称、告警配置等通过 REST API 写入的文本字段
- 邮件模板变量：用户提供的数据嵌入 MJML/HTML 邮件模板

**Sinks（输出到 HTML 的位置）：**
- Django 模板中的 `{{ var|safe }}` 和 `mark_safe(var)` 调用
- Jinja2 模板中未使用 `|e` 过滤器的变量插值（`{{ VAR }}`，尤其是 `autoescape=False` 时）
- Tornado/Flask handler 中的 `self.write(user_input)` 直接输出
- Pandas `DataFrame.style.to_html()` 渲染未转义的单元格值
- BeautifulSoup `decode_contents()` 反向解码 HTML 实体
- 前端 JavaScript 中的 `.innerHTML` 赋值（Python 后端提供数据）
- Django REST Framework 序列化器返回的未校验 HTML 字段

**Sanitization（HTML 转义/过滤）：**
- `django.utils.html.escape()` / `html.escape()` — 标准 HTML 实体转义
- Django `format_html()` — `mark_safe()` 的安全替代，自动转义插值参数
- Jinja2 `|e` 过滤器 / `autoescape=True`（默认开启但可被覆盖）
- `markupsafe.escape()` — Flask/Jinja2 生态的转义函数
- `bleach.clean()` — 白名单式 HTML 标签过滤
- BeautifulSoup `formatter="html"` — 保持 HTML 实体编码
- 前端 `.textContent` 代替 `.innerHTML` — 安全的 DOM 文本赋值
- DRF 序列化器自定义 `validate()` 中的 XSS 检查

**检测路径：**
1. 搜索 HTML 输出点：`mark_safe(`, `|safe`, `Markup(`, `self.write(`, `.innerHTML`, `to_html(`, `decode_contents(`
2. 检查输出数据是否包含用户输入（回溯 Source）
3. 验证 Source 到 Sink 路径上是否有 HTML 转义或内容过滤
4. 检查是否有 CSP、Content-Type、HttpOnly Cookie 等防御层
5. 特别关注条件分支/异常路径中的 fallback 逻辑（主路径安全但 fallback 跳过转义）

## Detection Checklist

- [ ] **Django `mark_safe()` / `|safe` 审计**：Grep `mark_safe\(` 和 `\|safe`，检查参数是否可能包含用户输入。特别关注 fallback/异常路径中的 `mark_safe`
- [ ] **Jinja2 模板变量转义**：搜索 `{{ VAR }}` 中未使用 `|e` 的变量，检查 `autoescape` 配置。注意 `add_html()` 等自定义方法可能绕过 autoescape
- [ ] **Tornado/Flask 直接写响应**：Grep `self.write(` / `make_response(`，检查是否直接输出含用户数据的字符串
- [ ] **Pandas DataFrame 渲染**：搜索 `.style.to_html(` / `render_table(`，检查是否在 `to_html()` 前对单元格值做了 `html.escape()`
- [ ] **BeautifulSoup 内容提取**：Grep `decode_contents(`，检查 `formatter` 参数。`formatter=None` 会反向解码 HTML 实体
- [ ] **DRF 序列化器字段**：检查 `CharField`/`TextField` 类型字段的 `validate()` 方法中是否有 HTML 字符检查
- [ ] **前端 innerHTML 赋值**：搜索 `.innerHTML =`，检查赋值数据是否来自后端未转义的用户输入
- [ ] **邮件模板渲染**：检查 MJML/HTML 邮件模板中用户数据是否经过转义
- [ ] **Mako 模板引擎**：搜索 Mako `Template(` / `render_unicode(`，检查 `default_filters` 是否配置了 `h`（HTML 转义）

## False Positive Exclusion Guide

以下情况通常**不构成** XSS 漏洞：

1. **`mark_safe()` 用于静态 HTML 片段**：如 `mark_safe('<br>')` 或 `mark_safe('<span class="icon">...</span>')`，不包含任何变量
2. **Jinja2 autoescape 已开启且未使用 `|safe`**：Django/Flask 默认 autoescape=True，`{{ var }}` 会自动转义
3. **`self.write()` 输出 JSON + Content-Type: application/json**：JSON 响应不会被浏览器渲染为 HTML（但需确认设置了 `X-Content-Type-Options: nosniff` 以防止浏览器 MIME 嗅探）
4. **数据已通过白名单验证**：如只允许字母数字的字段（枚举值、UUID 等）
5. **内部管理页面 + 强认证**：仅管理员可访问且无 CSRF 风险的页面（但仍建议修复）
6. **`innerHTML` 赋值内容来自可信源**：如从 Python 常量生成的 HTML，不包含用户数据
7. **`raise web.HTTPError()` 替代 `self.write()`**：Tornado 的 HTTPError 默认会转义错误消息中的 HTML

## Real-World Cases

详见 [references/cases.md](references/cases.md)

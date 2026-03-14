---
name: vuln-patterns-injection
description: "Use when auditing Python code involving command execution (subprocess, os.system, os.popen), SQL queries (cursor.execute, sqlalchemy.text, ORM .extra/.raw), eval/exec calls, template rendering (Jinja2, Mako SSTI), or expression evaluation. Covers CWE-77/78/89/94/95/917. Keywords: command injection, SQL injection, code injection, eval, exec, template injection, expression language injection, Hydra instantiate, allow_dangerous_code"
---

# Injection Vulnerability Patterns (CWE-77/78/89/94/95/917)

当审计 Python 代码中涉及动态命令构造、SQL 拼接、eval/exec 调用、模板渲染时加载此 Skill。

## Detection Strategy

通用检测模型，适用于此类漏洞的所有变体。

**Sources（用户输入入口）：**
- HTTP 请求参数：`request.args`, `request.form`, `request.json`, FastAPI `Query()`, `Path()` 参数
- LLM/Agent 输出：`tool_call.arguments`, Agent 的 `Action Input`, LLM 生成的代码字符串
- ORM 查询参数：用户传入的列名/字段名（如 `column` 参数传入聚合函数）
- 配置/序列化数据：Hydra `_target_` 字段、YAML/JSON 配置中的类路径
- MCP/工具调用：MCP Server 接收的 `kubectl` 命令参数、工具函数的用户输入
- 向量存储过滤表达式：`InMemoryVectorStore` 的 filter lambda 字符串

**Sinks（危险函数/操作）：**
- 代码执行：`eval()`, `exec()`, `compile()`, `__import__()`（注意：开发者常误用 `eval()` 替代 `ast.literal_eval()`，如用 `eval()` 解析布尔值）
- 模板引擎：Jinja2 `Template(user_input).render()`, `Environment().from_string(user_input)`, Mako `Template(user_input).render()`
- 命令执行：`subprocess.run(shell=True)`, `subprocess.Popen(shell=True)`, `os.system()`, `os.popen()`
- SQL 执行：`sqlalchemy.text()` 拼接用户输入, `cursor.execute()` 字符串拼接, ORM `.extra()`, `.raw()`
- 动态实例化：Hydra `instantiate()`, `importlib.import_module()` + `getattr()`
- 沙箱内函数：`python_repl_ast` 工具（LangChain）, `local_python_executor`（smolagents）
- AST 解析后执行：`ast.parse()` + `exec(compile(...))`（当 AST 白名单检查不完整时）

**Sanitization（安全屏障）：**
- **参数化查询**：使用 `cursor.execute(sql, params)` 而非字符串拼接
- **白名单验证**：将用户输入限制为预定义的安全值集合（如字段名白名单）
- **类型转换**：`str.lower() in ('true', '1')` 替代 `eval()` 做布尔解析
- **前缀/模块白名单**：限制动态导入的模块路径必须以安全前缀开头
- **AST 节点白名单**：限制允许的 AST 节点类型 + 属性黑名单（如 `__class__`, `__globals__`）
- **返回值检查**：对沙箱执行结果做安全性验证（模块类型、函数来源检查）
- **Shell 元字符过滤**：对传入 subprocess 的参数使用 `shlex.quote()` 或避免 `shell=True`
- **列表参数模式**：`subprocess.run(shlex.split(cmd), shell=False)` — 避免 shell 解析

**检测路径：**

搜索 sink 调用的 Grep 模式：
```bash
# 代码执行
grep -rn "eval(" --include="*.py"
grep -rn "exec(" --include="*.py"
# 命令执行
grep -rn "shell=True" --include="*.py"
grep -rn "os\.system\|os\.popen" --include="*.py"
# SQL 拼接
grep -rn "sqlalchemy\.text\|\.execute(" --include="*.py"
grep -rn "\.extra(\|\.raw(" --include="*.py"
# 模板注入
grep -rn "Template(" --include="*.py"
grep -rn "from_string(" --include="*.py"
# 动态实例化
grep -rn "instantiate(\|__import__(" --include="*.py"
```

1. 搜索 sink 调用（`eval(`, `exec(`, `subprocess.*shell=True`, `sqlalchemy.text(`, `os.system(`）
2. 回溯数据流，检查参数是否来自 source（HTTP 输入、LLM 输出、用户可控配置）
3. 验证 source->sink 路径上是否存在有效 sanitization
4. 特别关注以下高风险模式：
   - `eval()` 用于解析布尔值/简单类型（应使用类型转换替代）
   - ORM 聚合函数接受用户传入的列名（应做字段名白名单校验）
   - LLM Agent 框架硬编码 `allow_dangerous_code=True`
   - MCP Server 用 `shell=True` 执行用户传入的命令
   - `instantiate()` / `__import__()` 接受用户可控的类路径
5. 若无 sanitization 或 sanitization 不完整 -> 标记为候选漏洞

## Detection Checklist

- [ ] 搜索 `eval(` 和 `exec(` 调用，检查参数是否包含用户输入或外部数据
- [ ] 搜索 `subprocess` / `os.system` / `os.popen`，检查是否使用 `shell=True` 且参数含用户输入
- [ ] 搜索 `sqlalchemy.text()` / 原生 SQL 拼接，检查是否有未参数化的用户输入
- [ ] 搜索 ORM 的 `.extra()`, `.raw()`, `.min()`, `.max()` 等接受字符串参数的方法
- [ ] 搜索 `allow_dangerous_code` 配置项，检查是否硬编码为 `True`
- [ ] 搜索 Hydra `instantiate()` / `_target_` 字段，检查是否有用户可控的类路径
- [ ] 搜索 `ast.parse` + `compile` + `exec` 模式，检查 AST 白名单是否覆盖所有逃逸路径
- [ ] 搜索 `__class__`, `__globals__`, `__builtins__` 等 dunder 属性访问，检查沙箱是否阻止
- [ ] 检查 MCP Server 的工具函数实现，确认命令构造是否安全
- [ ] 检查向量存储/搜索引擎的 filter 表达式解析，确认是否限制了危险的 AST 节点和属性
- [ ] 搜索 Jinja2 `Template(` / `Environment().from_string(` 和 Mako `Template(`，检查参数是否包含用户输入（SSTI 模板注入）
- [ ] 搜索 `shlex.quote` 或 `shlex.split` 使用情况，确认命令执行是否采用列表参数 + `shell=False` 模式

## False Positive Exclusion Guide

以下模式**不是**此类漏洞：
- `eval()` 的参数是硬编码常量字符串 -- 无用户可控输入
- `subprocess.run(["cmd", "arg"], shell=False)` 使用列表参数且无 shell -- 参数不会被 shell 解析
- `ast.literal_eval()` 用于解析 JSON/字面量 — 只接受字面量表达式，不执行代码（但注意不要用 `eval()` 误替代 `ast.literal_eval()`）
- `sqlalchemy.text()` 配合 `.bindparams()` 使用 -- 参数已绑定，不存在拼接
- ORM 的 `.filter(Model.field == value)` -- 使用 ORM 表达式 API，自动参数化
- `instantiate()` 的 `_target_` 来自代码内部硬编码的配置 -- 非用户可控

以下模式**需要深入检查**：
- `eval(request_value) if isinstance(value, str) else value` -- 虽然做了类型检查但 eval 仍危险
- `sqlalchemy.text(f"{user_input}")` 即使被包裹在 ORM 函数中 -- ORM 包装不改变 SQL 注入本质
- `subprocess.run(cmd, shell=True)` 即使 cmd 经过了"过滤" -- 过滤可能不完整
- AST 白名单 + `exec()` 沙箱 -- 白名单遗漏可导致沙箱逃逸
- `allow_dangerous_code` 通过环境变量/配置控制 -- 需确认默认值是否安全
- `__import__(module_path)` 即使有前缀检查 -- 前缀检查可能被绕过（如 `..`）

## Real-World Cases

详见 [references/cases.md](references/cases.md)（7 个真实案例，需要时加载）。

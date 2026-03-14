#!/usr/bin/env python3
"""对 HackerOne hacktivity 索引数据补充报告详情。

HackerOne 报告页面是 React SPA，需要 JS 渲染。本脚本采用混合策略：
  1. 从 hacktivity 索引中提取元数据（标题、CWE、严重度、CVE）
  2. 对有 CVE ID 的报告，从 NVD API 获取漏洞描述（无需认证）
  3. 可选：使用 Playwright 渲染报告页面获取完整内容

环境变量:
    H1_USERNAME  - HackerOne 用户名（可选，用于 API 调用获取额外信息）
    H1_API_TOKEN - HackerOne API Token（可选）

依赖:
    pip install playwright  # 可选，用于网页渲染
    playwright install chromium  # 可选，安装浏览器

用法:
    # 从 hacktivity 索引补充详情
    python3 fetch_h1_details.py data/h1_hacktivity.json

    # 按 CWE 过滤
    python3 fetch_h1_details.py data/h1_hacktivity.json --cwe "79|89|94"

    # 只取前 20 条
    python3 fetch_h1_details.py data/h1_hacktivity.json --top 20

    # 启用 Playwright 抓取完整报告内容
    python3 fetch_h1_details.py data/h1_hacktivity.json --scrape

    # 指定输出
    python3 fetch_h1_details.py data/h1_hacktivity.json --cwe "79" --output data/h1_details_xss.json

输出:
    每条包含: 标题、CWE、严重度、CVE 描述、报告 URL、bounty 等
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def filter_candidates(
    data: list[dict],
    cwe_pattern: str | None,
    severity: str | None,
    top: int | None,
) -> list[dict]:
    """按 CWE 和严重度过滤，可选取 Top N。"""
    filtered = list(data)

    if cwe_pattern:
        regex = re.compile(f"CWE-({cwe_pattern})", re.IGNORECASE)
        filtered = [r for r in filtered if r.get("cwe") and regex.search(r["cwe"])]

    if severity:
        allowed = {s.strip().lower() for s in severity.split(",")}
        filtered = [r for r in filtered if (r.get("severity_rating") or "").lower() in allowed]

    # 按 bounty 降序排列（有 bounty 的优先）
    filtered.sort(key=lambda r: r.get("total_awarded_amount") or 0, reverse=True)

    if top:
        filtered = filtered[:top]
    return filtered


def fetch_nvd_description(cve_id: str) -> str | None:
    """从 NVD API 获取 CVE 描述。免费 API，无需认证。"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (HTTPError, Exception):
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve_data = vulns[0].get("cve", {})
    descriptions = cve_data.get("descriptions", [])
    # 优先取英文描述
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value")
    if descriptions:
        return descriptions[0].get("value")
    return None


def fetch_nvd_details(cve_id: str) -> dict:
    """从 NVD API 获取 CVE 完整详情。"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (HTTPError, Exception):
        return {}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}

    cve_data = vulns[0].get("cve", {})

    # 提取描述
    description = None
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break
    if not description and cve_data.get("descriptions"):
        description = cve_data["descriptions"][0].get("value")

    # 提取 CVSS
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    # 提取 CWE
    cwes = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc.get("value")
            if cwe_id and cwe_id.startswith("CWE-"):
                cwes.append(cwe_id)

    # 提取参考链接
    references = []
    for ref in cve_data.get("references", []):
        references.append({
            "url": ref.get("url"),
            "source": ref.get("source"),
            "tags": ref.get("tags", []),
        })

    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwes": cwes,
        "references": references,
    }


def scrape_report_playwright(url: str, browser) -> dict:
    """使用 Playwright 渲染 HackerOne 报告页面并提取内容。"""
    page = browser.new_page()
    try:
        page.goto(url, wait_until="networkidle", timeout=30000)
        # 等待报告内容加载
        page.wait_for_selector("[class*='report-']", timeout=10000)

        # 提取报告正文
        content = {}

        # 尝试提取漏洞描述
        selectors = [
            "[data-testid='report-section-vulnerability-information']",
            ".vulnerability-information",
            "[class*='report-body']",
            ".markdown-body",
        ]
        for sel in selectors:
            elem = page.query_selector(sel)
            if elem:
                content["vulnerability_information"] = elem.inner_text()
                break

        # 尝试提取 impact
        impact_selectors = [
            "[data-testid='report-section-impact']",
            ".impact-section",
        ]
        for sel in impact_selectors:
            elem = page.query_selector(sel)
            if elem:
                content["impact"] = elem.inner_text()
                break

        # 提取所有 markdown 段落作为 fallback
        if not content:
            all_text = page.query_selector_all(".markdown-body, [class*='markup--']")
            if all_text:
                content["full_text"] = "\n\n".join(e.inner_text() for e in all_text[:10])

        return content
    except Exception as e:
        return {"error": str(e)}
    finally:
        page.close()


def enrich_report(report: dict, nvd_delay: float, browser=None) -> dict:
    """补充单条报告的详情。"""
    result = {
        "id": report.get("id"),
        "title": report.get("title"),
        "url": report.get("url"),
        "severity_rating": report.get("severity_rating"),
        "cwe": report.get("cwe"),
        "cve_ids": report.get("cve_ids", []),
        "disclosed_at": report.get("disclosed_at"),
        "total_awarded_amount": report.get("total_awarded_amount"),
        "reporter": report.get("reporter"),
        "program": report.get("program"),
        "hacktivity_summary": report.get("hacktivity_summary"),
        "nvd_description": None,
        "nvd_cvss_score": None,
        "nvd_cwes": [],
        "nvd_references": [],
        "scraped_content": None,
    }

    # 1. 从 NVD 获取 CVE 详情
    cve_ids = report.get("cve_ids") or []
    if cve_ids:
        for cve_id in cve_ids[:1]:  # 只取第一个 CVE
            nvd = fetch_nvd_details(cve_id)
            if nvd:
                result["nvd_description"] = nvd.get("description")
                result["nvd_cvss_score"] = nvd.get("cvss_score")
                result["nvd_cwes"] = nvd.get("cwes", [])
                result["nvd_references"] = [
                    r["url"] for r in nvd.get("references", [])
                    if any(t in (r.get("tags") or []) for t in ["Patch", "Exploit", "Third Party Advisory"])
                ] or [r["url"] for r in nvd.get("references", [])[:5]]
                time.sleep(nvd_delay)
                break

    # 2. Playwright 抓取报告页面（可选）
    if browser and report.get("url"):
        result["scraped_content"] = scrape_report_playwright(report["url"], browser)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="对 HackerOne hacktivity 索引数据补充报告详情",
    )
    parser.add_argument("input", help="输入 JSON 文件路径（fetch_h1_hacktivity.py 的输出）")
    parser.add_argument("--cwe", type=str, default=None,
                        help="CWE 编号过滤（正则，如 '79|89|94'）")
    parser.add_argument("--severity", type=str, default=None,
                        help="严重度过滤（如 'critical,high'）")
    parser.add_argument("--top", type=int, default=None,
                        help="只取前 N 条 (默认: 不限)")
    parser.add_argument("--scrape", action="store_true",
                        help="启用 Playwright 渲染抓取报告全文（需要安装 playwright）")
    parser.add_argument("--nvd-delay", type=float, default=0.8,
                        help="NVD API 请求间隔秒数 (默认: 0.8，NVD 限 5 req/30s)")
    parser.add_argument("--output", type=str, default=None,
                        help="输出 JSON 文件路径")
    args = parser.parse_args()

    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))

    # 筛选
    candidates = filter_candidates(data, args.cwe, args.severity, args.top)
    print(f"筛选出 {len(candidates)} 条候选", file=sys.stderr)

    # 可选：启动 Playwright
    browser = None
    pw_context = None
    if args.scrape:
        try:
            from playwright.sync_api import sync_playwright
            pw_context = sync_playwright().start()
            browser = pw_context.chromium.launch(headless=True)
            print("Playwright 已启动", file=sys.stderr)
        except ImportError:
            print("警告: playwright 未安装，跳过网页抓取。"
                  "安装: pip install playwright && playwright install chromium",
                  file=sys.stderr)
        except Exception as e:
            print(f"警告: Playwright 启动失败: {e}，跳过网页抓取", file=sys.stderr)

    # 逐条补充详情
    details = []
    cve_count = sum(1 for c in candidates if c.get("cve_ids"))
    print(f"其中有 CVE ID 的: {cve_count} 条", file=sys.stderr)

    for i, report in enumerate(candidates):
        title = (report.get("title") or "")[:60]
        cve_ids = report.get("cve_ids") or []
        cve_str = cve_ids[0] if cve_ids else "无CVE"
        print(f"  [{i+1}/{len(candidates)}] {cve_str} | {title}...",
              file=sys.stderr, end="")

        detail = enrich_report(report, args.nvd_delay, browser)
        details.append(detail)

        has_nvd = "NVD" if detail.get("nvd_description") else ""
        has_scrape = "页面" if detail.get("scraped_content") else ""
        sources = "+".join(filter(None, [has_nvd, has_scrape])) or "仅元数据"
        print(f" [{sources}]", file=sys.stderr)

    # 清理 Playwright
    if browser:
        browser.close()
    if pw_context:
        pw_context.stop()

    # 保存
    if args.output:
        output_path = Path(args.output)
    else:
        stem = input_path.stem
        suffix = f"_{args.cwe.replace('|', '-')}" if args.cwe else ""
        output_path = input_path.parent / f"{stem}_details{suffix}.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(details, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    print(f"\n已保存 {len(details)} 条详情到 {output_path}", file=sys.stderr)

    # 摘要
    with_nvd = sum(1 for d in details if d.get("nvd_description"))
    with_scrape = sum(1 for d in details if d.get("scraped_content"))
    with_refs = sum(1 for d in details if d.get("nvd_references"))
    print(f"\n摘要:")
    print(f"  有 NVD 描述: {with_nvd}/{len(details)}")
    print(f"  有参考链接: {with_refs}/{len(details)}")
    if args.scrape:
        print(f"  有页面内容: {with_scrape}/{len(details)}")

    # CWE 分布
    cwe_count_map: dict[str, int] = {}
    for d in details:
        cwe = d.get("cwe")
        if cwe:
            cwe_count_map[cwe] = cwe_count_map.get(cwe, 0) + 1
    if cwe_count_map:
        print(f"\nCWE 分布 (Top 10):")
        for cwe, count in sorted(cwe_count_map.items(), key=lambda x: -x[1])[:10]:
            print(f"  {cwe}: {count}")


if __name__ == "__main__":
    main()

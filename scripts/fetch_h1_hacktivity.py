#!/usr/bin/env python3
"""从 HackerOne Hacktivity GraphQL API 拉取已公开漏洞报告索引。

使用 HackerOne 内部 GraphQL 端点（hackerone.com/graphql），无需认证。
支持 offset 分页，单次最多拉取 3000 条。

用法:
    # 拉取全部已公开的 critical/high 报告（默认最多 3000 条）
    python3 fetch_h1_hacktivity.py

    # 按严重度过滤
    python3 fetch_h1_hacktivity.py --severity critical
    python3 fetch_h1_hacktivity.py --severity critical,high

    # 按 CWE/关键词过滤
    python3 fetch_h1_hacktivity.py --cwe "SQL Injection"
    python3 fetch_h1_hacktivity.py --cwe "XSS"

    # 按时间范围（客户端过滤）
    python3 fetch_h1_hacktivity.py --since 2y

    # 自定义拉取数量
    python3 fetch_h1_hacktivity.py --max 500

    # 组合过滤
    python3 fetch_h1_hacktivity.py --severity critical --cwe "SSRF" --max 200

    # 自定义输出路径
    python3 fetch_h1_hacktivity.py --output data/h1_critical.json

输出:
    默认保存到 data/h1_hacktivity.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = SKILL_DIR / "data"

GRAPHQL_URL = "https://hackerone.com/graphql"

GRAPHQL_QUERY = """query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
  me { id __typename }
  search(
    index: CompleteHacktivityReportIndex
    query_string: $queryString
    from: $from
    size: $size
    sort: $sort
  ) {
    __typename
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        id
        _id
        severity_rating
        cve_ids
        cwe
        total_awarded_amount
        reporter { username __typename }
        team { handle name __typename }
        report {
          id
          _id
          title
          url
          substate
          disclosed_at
          report_generated_content {
            id
            hacktivity_summary
            __typename
          }
        }
      }
    }
  }
}"""

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Accept": "*/*",
    "Content-Type": "application/json",
    "X-Product-Area": "hacktivity",
    "X-Product-Feature": "overview",
}


def graphql_post(payload: dict) -> dict:
    """发送 GraphQL 请求到 HackerOne。"""
    data = json.dumps(payload).encode()
    req = Request(GRAPHQL_URL, data=data, headers=HEADERS, method="POST")
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 429:
            print("  Rate limited, waiting 30s...", file=sys.stderr)
            time.sleep(30)
            return graphql_post(payload)
        raise


def parse_since(since_str: str) -> datetime:
    """解析 --since 参数，返回 datetime 对象。"""
    unit = since_str[-1].lower()
    value = int(since_str[:-1])
    now = datetime.now(timezone.utc)
    if unit == "y":
        return now - timedelta(days=value * 365)
    elif unit == "m":
        return now - timedelta(days=value * 30)
    elif unit == "d":
        return now - timedelta(days=value)
    else:
        print(f"无效的时间格式: {since_str}，支持 Ny/Nm/Nd", file=sys.stderr)
        sys.exit(1)


def build_query(args: argparse.Namespace) -> str:
    """根据参数构建 Lucene 查询字符串。"""
    parts = ['disclosed:true']

    if args.severity:
        severities = [s.strip().lower() for s in args.severity.split(",")]
        if len(severities) == 1:
            parts.append(f'severity_rating:({severities[0]})')
        else:
            parts.append(f'severity_rating:({" OR ".join(severities)})')

    if args.cwe:
        parts.append(f'cwe:("{args.cwe}")')

    if args.keyword:
        parts.append(args.keyword)

    return " AND ".join(parts)


def fetch_hacktivity(
    query: str,
    max_reports: int,
    page_size: int = 100,
    delay: float = 0.5,
) -> list[dict]:
    """通过 GraphQL offset 分页拉取 hacktivity 数据。"""
    all_nodes = []
    total_count = None

    for offset in range(0, max_reports, page_size):
        size = min(page_size, max_reports - offset)

        payload = {
            "operationName": "HacktivitySearchQuery",
            "variables": {
                "queryString": query,
                "size": size,
                "from": offset,
                "sort": {
                    "field": "latest_disclosable_activity_at",
                    "direction": "DESC",
                },
                "product_area": "hacktivity",
                "product_feature": "overview",
            },
            "query": GRAPHQL_QUERY,
        }

        batch = offset // page_size + 1
        print(f"  批次 {batch} (offset={offset})...", file=sys.stderr, end="")

        try:
            resp = graphql_post(payload)
        except Exception as e:
            print(f" 错误: {e}, 停止", file=sys.stderr)
            break

        search = resp.get("data", {}).get("search", {})
        if total_count is None:
            total_count = search.get("total_count", 0)
            print(f" 总计 {total_count} 条可用", file=sys.stderr, end="")

        nodes = search.get("nodes", [])
        if not nodes:
            print(f" 无更多数据", file=sys.stderr)
            break

        all_nodes.extend(nodes)
        print(f" +{len(nodes)} (累计 {len(all_nodes)})", file=sys.stderr)

        if len(nodes) < size:
            break

        time.sleep(delay)

    return all_nodes


def normalize_nodes(nodes: list[dict], since: datetime | None = None) -> list[dict]:
    """将 GraphQL 响应归一化为简洁的字典列表。"""
    seen = set()
    results = []

    for node in nodes:
        node_id = node.get("_id") or node.get("id")
        if node_id in seen:
            continue
        seen.add(node_id)

        report = node.get("report") or {}
        team = node.get("team") or {}
        reporter = node.get("reporter") or {}
        rgc = report.get("report_generated_content") or {}

        disclosed_at = report.get("disclosed_at")

        # 客户端日期过滤
        if since and disclosed_at:
            try:
                dt = datetime.fromisoformat(disclosed_at.replace("Z", "+00:00"))
                if dt < since:
                    continue
            except ValueError:
                pass

        results.append({
            "id": node_id,
            "title": report.get("title"),
            "url": report.get("url"),
            "substate": report.get("substate"),
            "severity_rating": node.get("severity_rating"),
            "cve_ids": node.get("cve_ids", []),
            "cwe": node.get("cwe"),
            "disclosed_at": disclosed_at,
            "total_awarded_amount": node.get("total_awarded_amount"),
            "reporter": reporter.get("username"),
            "program": team.get("handle"),
            "program_name": team.get("name"),
            "hacktivity_summary": rgc.get("hacktivity_summary"),
        })

    return results


def print_summary(results: list[dict]) -> None:
    """输出摘要。"""
    print(f"\n共 {len(results)} 条已公开报告")

    # 严重度分布
    severity_count: dict[str, int] = {}
    for r in results:
        sev = r.get("severity_rating") or "unknown"
        severity_count[sev] = severity_count.get(sev, 0) + 1
    print("\n严重度分布:")
    for sev, count in sorted(severity_count.items(), key=lambda x: -x[1]):
        print(f"  {sev}: {count}")

    # CWE 分布
    cwe_count: dict[str, int] = {}
    for r in results:
        cwe = r.get("cwe")
        if cwe:
            cwe_count[cwe] = cwe_count.get(cwe, 0) + 1
    if cwe_count:
        print("\nCWE 分布 (Top 15):")
        for cwe, count in sorted(cwe_count.items(), key=lambda x: -x[1])[:15]:
            print(f"  {cwe}: {count}")

    # 项目分布
    program_count: dict[str, int] = {}
    for r in results:
        prog = r.get("program") or "unknown"
        program_count[prog] = program_count.get(prog, 0) + 1
    print("\n项目分布 (Top 10):")
    for prog, count in sorted(program_count.items(), key=lambda x: -x[1])[:10]:
        print(f"  {prog}: {count}")

    # 前 20 条
    print(f"\n前 20 条:")
    for r in results[:20]:
        bounty = f"${r['total_awarded_amount']}" if r.get("total_awarded_amount") else "N/A"
        cwe = r.get("cwe") or "N/A"
        sev = r.get("severity_rating") or "?"
        title = (r.get("title") or "")[:80]
        print(f"  {r['id']} | {sev:8s} | {bounty:>8s} | {cwe:20s} | {title}")

    if len(results) > 20:
        print(f"  ... 还有 {len(results) - 20} 条")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="从 HackerOne Hacktivity GraphQL API 拉取已公开漏洞报告索引",
    )
    parser.add_argument("--severity", type=str, default="critical,high",
                        help="严重度过滤，逗号分隔 (默认: critical,high)")
    parser.add_argument("--cwe", type=str, default=None,
                        help="CWE/漏洞类型关键词 (如 'SQL Injection', 'XSS', 'SSRF')")
    parser.add_argument("--since", type=str, default="3y",
                        help="时间范围，客户端过滤 (默认: 3y，支持 Ny/Nm/Nd)")
    parser.add_argument("--keyword", type=str, default=None,
                        help="额外的 Lucene 查询关键词")
    parser.add_argument("--max", type=int, default=3000,
                        help="最大拉取数量 (默认: 3000)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="请求间隔秒数 (默认: 0.5)")
    parser.add_argument("--output", type=str, default=None,
                        help="输出 JSON 文件路径 (默认: data/h1_hacktivity.json)")
    args = parser.parse_args()

    query = build_query(args)
    since = parse_since(args.since) if args.since else None
    since_desc = f", 自 {since.strftime('%Y-%m-%d')}" if since else ""
    print(f"查询: {query}{since_desc}", file=sys.stderr)

    nodes = fetch_hacktivity(query, args.max, delay=args.delay)
    results = normalize_nodes(nodes, since)

    # 保存
    output_path = Path(args.output) if args.output else DEFAULT_OUTPUT_DIR / "h1_hacktivity.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    print(f"\n已保存到 {output_path} ({len(results)} 条)", file=sys.stderr)

    print_summary(results)


if __name__ == "__main__":
    main()

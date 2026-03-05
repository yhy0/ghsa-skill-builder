#!/usr/bin/env python3
"""从 GitHub Advisory Database 全量拉取高危漏洞并保存到本地。

支持 GraphQL cursor 分页，自动遍历所有结果。
支持时间范围过滤和增量更新检查。

用法:
    # 全量拉取
    python3 fetch_ghsa.py PIP
    python3 fetch_ghsa.py GO --min-cvss 9
    python3 fetch_ghsa.py NPM --severity CRITICAL

    # 按时间范围（最近 N 年）
    python3 fetch_ghsa.py PIP --since 3y
    python3 fetch_ghsa.py GO --since 1y --min-cvss 9

    # 增量检查：对比已有 data 找出新增漏洞
    python3 fetch_ghsa.py PIP --diff

    # 自定义输出路径
    python3 fetch_ghsa.py PIP --output /tmp/pip.json

输出:
    默认保存到 .claude/skills/ghsa-skill-builder/data/{ecosystem}.json
    同时输出摘要到 stdout
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# 导入公共工具
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import check_gh_auth

SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = SKILL_DIR / "data"

GRAPHQL_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $severities: [SecurityAdvisorySeverity!], $cursor: String) {
  securityVulnerabilities(
    first: 100,
    ecosystem: $ecosystem,
    severities: $severities,
    after: $cursor,
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss { score vectorString }
        cwes(first: 5) { nodes { cweId name } }
        publishedAt
        references { url }
      }
      package { name }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""


def gh_graphql(variables: dict) -> dict:
    """调用 gh api graphql，返回解析后的 JSON。"""
    request_body = json.dumps({"query": GRAPHQL_QUERY, "variables": variables})
    result = subprocess.run(
        ["gh", "api", "graphql", "--input", "-"],
        input=request_body, capture_output=True, text=True, check=True,
    )
    data = json.loads(result.stdout)
    if "errors" in data:
        print(f"GraphQL 错误: {data['errors']}", file=sys.stderr)
        sys.exit(1)
    return data


def fetch_all(ecosystem: str, severities: list[str]) -> tuple[list[dict], int]:
    """分页拉取所有漏洞，返回 (nodes, total_count)。"""
    all_nodes = []
    cursor = None
    total_count = 0
    page = 0

    while True:
        page += 1
        variables = {
            "ecosystem": ecosystem,
            "severities": severities,
            "cursor": cursor,
        }
        data = gh_graphql(variables)
        vuln_data = data["data"]["securityVulnerabilities"]
        total_count = vuln_data["totalCount"]
        nodes = vuln_data["nodes"]
        all_nodes.extend(nodes)

        print(f"  第 {page} 页: 获取 {len(nodes)} 条 (累计 {len(all_nodes)}/{total_count})",
              file=sys.stderr)

        if not vuln_data["pageInfo"]["hasNextPage"]:
            break
        cursor = vuln_data["pageInfo"]["endCursor"]

    return all_nodes, total_count


def parse_since(since_str: str) -> datetime:
    """解析 --since 参数，如 '3y', '6m', '30d'。"""
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


def filter_and_dedupe(
    nodes: list[dict],
    min_cvss: float,
    since: Optional[datetime] = None,
) -> list[dict]:
    """按 CVSS、时间过滤并按 GHSA ID 去重。"""
    seen = set()
    results = []
    for node in nodes:
        cvss_score = node["advisory"]["cvss"]["score"]
        if cvss_score is None or cvss_score < min_cvss:
            continue

        # 时间过滤
        if since:
            published = node["advisory"].get("publishedAt", "")
            if published:
                pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                if pub_dt < since:
                    continue

        ghsa_id = node["advisory"]["ghsaId"]
        if ghsa_id in seen:
            continue
        seen.add(ghsa_id)
        results.append(node)

    results.sort(key=lambda n: n["advisory"]["cvss"]["score"] or 0, reverse=True)
    return results


def diff_with_existing(results: list[dict], existing_path: Path) -> list[dict]:
    """对比已有数据，返回新增的漏洞。"""
    if not existing_path.exists():
        return results

    existing = json.loads(existing_path.read_text(encoding="utf-8"))
    existing_ids = {n["advisory"]["ghsaId"] for n in existing}
    new_results = [n for n in results if n["advisory"]["ghsaId"] not in existing_ids]
    return new_results


def print_summary(results: list[dict], label: str = "") -> None:
    """输出摘要到 stdout。"""
    cwe_count: dict[str, int] = {}
    for node in results:
        for cwe in node["advisory"]["cwes"]["nodes"]:
            cid = cwe["cweId"]
            cwe_count[cid] = cwe_count.get(cid, 0) + 1

    prefix = f"[{label}] " if label else ""
    print(f"\n{prefix}共 {len(results)} 条漏洞")

    if cwe_count:
        print("\nCWE 分布 (Top 10):")
        for cwe, count in sorted(cwe_count.items(), key=lambda x: -x[1])[:10]:
            print(f"  {cwe}: {count}")

    print(f"\n前 20 条:")
    for node in results[:20]:
        adv = node["advisory"]
        cwes = ",".join(c["cweId"] for c in adv["cwes"]["nodes"])
        print(f"  {adv['ghsaId']} | CVSS {adv['cvss']['score']} | "
              f"{node['package']['name']} | {cwes} | {adv['summary'][:80]}")

    if len(results) > 20:
        print(f"  ... 还有 {len(results) - 20} 条")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="从 GitHub Advisory Database 全量拉取高危漏洞",
    )
    parser.add_argument(
        "ecosystem",
        choices=["PIP", "GO", "NPM", "MAVEN", "NUGET", "RUBYGEMS", "RUST"],
        help="包管理器生态系统",
    )
    parser.add_argument("--min-cvss", type=float, default=8.0,
                        help="最低 CVSS 分数 (默认: 8.0)")
    parser.add_argument("--severity", type=str, default="CRITICAL,HIGH",
                        help="严重级别，逗号分隔 (默认: CRITICAL,HIGH)")
    parser.add_argument("--since", type=str, default=None,
                        help="时间范围，如 3y(三年) 1y(一年) 6m(六个月) 30d(30天)")
    parser.add_argument("--diff", action="store_true",
                        help="增量模式：只输出相比已有数据新增的漏洞")
    parser.add_argument("--output", type=str, default=None,
                        help="输出 JSON 文件路径 (默认: data/{ecosystem}.json)")
    args = parser.parse_args()

    # 检查 GitHub 认证
    check_gh_auth()

    severities = [s.strip() for s in args.severity.split(",")]
    ecosystem = args.ecosystem.upper()
    since = parse_since(args.since) if args.since else None

    since_desc = f", 自 {since.strftime('%Y-%m-%d')}" if since else ""
    print(f"拉取 {ecosystem} 生态, severity={severities}, "
          f"CVSS >= {args.min_cvss}{since_desc}", file=sys.stderr)

    # 全量分页拉取
    all_nodes, total_count = fetch_all(ecosystem, severities)
    print(f"\nAPI 总条目: {total_count}, 实际拉取: {len(all_nodes)}", file=sys.stderr)

    # 过滤 + 去重
    results = filter_and_dedupe(all_nodes, args.min_cvss, since)

    output_path = Path(args.output) if args.output else DEFAULT_OUTPUT_DIR / f"{ecosystem.lower()}.json"

    # 增量模式
    if args.diff:
        new_results = diff_with_existing(results, output_path)
        print(f"\n增量对比: {len(results)} 条总量, {len(new_results)} 条新增", file=sys.stderr)
        if new_results:
            print_summary(new_results, label="新增")
        else:
            print("\n没有新增漏洞。当前 skills 已是最新。")
        return

    # 保存到文件
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    print(f"\n已保存到 {output_path} ({len(results)} 条)", file=sys.stderr)

    print_summary(results)


if __name__ == "__main__":
    main()

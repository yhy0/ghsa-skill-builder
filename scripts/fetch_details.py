#!/usr/bin/env python3
"""对筛选后的 GHSA 候选批量拉取完整详情（description + references）。

从 data/{ecosystem}.json 中按条件筛选，然后逐条调用 REST API
获取完整 description，保存到 data/{ecosystem}_details.json。

用法:
    # 拉取注入类（CWE-77/78/89/94）全部详情
    python3 fetch_details.py data/pip.json --cwe "77|78|89|94"

    # 不过滤 CWE，全量拉取所有详情
    python3 fetch_details.py data/pip.json

    # 只想快速试试，取 Top 10
    python3 fetch_details.py data/pip.json --cwe "22|23" --top 10

    # 指定输出路径
    python3 fetch_details.py data/pip.json --cwe "22|23" --output data/path-traversal-details.json

输出:
    每条包含完整的 description、references、CWE 等信息
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# 导入公共工具
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import check_gh_auth


def gh_rest(endpoint: str) -> dict:
    """调用 gh api REST 接口。"""
    result = subprocess.run(
        ["gh", "api", endpoint],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  API 错误: {endpoint} -> {result.stderr[:200]}", file=sys.stderr)
        return {}
    return json.loads(result.stdout)


def filter_candidates(
    data: list[dict],
    cwe_pattern: Optional[str],
    top: Optional[int],
) -> list[dict]:
    """按 CWE 过滤，可选取 Top N。"""
    if cwe_pattern:
        regex = re.compile(f"CWE-({cwe_pattern})")
        filtered = []
        for node in data:
            cwes = [c["cweId"] for c in node["advisory"]["cwes"]["nodes"]]
            if any(regex.match(c) for c in cwes):
                filtered.append(node)
    else:
        filtered = list(data)

    # 按 CVSS 降序
    filtered.sort(key=lambda n: n["advisory"]["cvss"]["score"] or 0, reverse=True)
    if top:
        filtered = filtered[:top]
    return filtered


def fetch_detail(ghsa_id: str) -> dict:
    """获取单条 GHSA 的完整详情。"""
    data = gh_rest(f"/advisories/{ghsa_id}")
    if not data:
        return {}

    # 提取 patch commit URL
    patch_urls = []
    for ref in data.get("references", []):
        url = ref if isinstance(ref, str) else ref.get("url", "")
        if "/commit/" in url or "/pull/" in url:
            patch_urls.append(url)

    return {
        "ghsa_id": data.get("ghsa_id"),
        "cve_id": data.get("cve_id"),
        "summary": data.get("summary"),
        "description": data.get("description"),
        "severity": data.get("severity"),
        "cvss_score": data.get("cvss", {}).get("score"),
        "cwes": [c.get("cwe_id", c) if isinstance(c, dict) else c
                 for c in data.get("cwes", [])],
        "published_at": data.get("published_at"),
        "references": [r if isinstance(r, str) else r.get("url", "")
                       for r in data.get("references", [])],
        "patch_urls": patch_urls,
        "vulnerabilities": [
            {
                "package": v.get("package", {}).get("name"),
                "ecosystem": v.get("package", {}).get("ecosystem"),
                "vulnerable_range": v.get("vulnerable_version_range"),
            }
            for v in data.get("vulnerabilities", [])
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="对筛选后的 GHSA 候选批量拉取完整详情",
    )
    parser.add_argument("input", help="输入 JSON 文件路径（fetch_ghsa.py 的输出）")
    parser.add_argument("--cwe", type=str, default=None,
                        help="CWE 编号过滤（正则，如 '77|78|89|94'）")
    parser.add_argument("--top", type=int, default=None,
                        help="只取 CVSS 最高的 N 条 (默认: 不限制，全量拉取)")
    parser.add_argument("--output", type=str, default=None,
                        help="输出 JSON 文件路径")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="请求间隔秒数，避免 rate limit (默认: 0.5)")
    args = parser.parse_args()

    # 检查 GitHub 认证
    check_gh_auth()

    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))

    # 筛选候选
    candidates = filter_candidates(data, args.cwe, args.top)
    print(f"筛选出 {len(candidates)} 条候选", file=sys.stderr)

    # 逐条拉取详情
    details = []
    for i, node in enumerate(candidates):
        ghsa_id = node["advisory"]["ghsaId"]
        cvss = node["advisory"]["cvss"]["score"]
        print(f"  [{i+1}/{len(candidates)}] {ghsa_id} (CVSS {cvss})...",
              file=sys.stderr, end="")

        detail = fetch_detail(ghsa_id)
        if detail:
            details.append(detail)
            desc_len = len(detail.get("description") or "")
            patches = len(detail.get("patch_urls", []))
            print(f" OK (desc: {desc_len} chars, patches: {patches})",
                  file=sys.stderr)
        else:
            print(f" FAILED", file=sys.stderr)

        if i < len(candidates) - 1:
            time.sleep(args.delay)

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
    with_patches = sum(1 for d in details if d.get("patch_urls"))
    with_desc = sum(1 for d in details if d.get("description"))
    print(f"有完整描述: {with_desc}/{len(details)}, "
          f"有 patch commit: {with_patches}/{len(details)}")


if __name__ == "__main__":
    main()

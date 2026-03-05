#!/usr/bin/env python3
"""检查已有漏洞模式 Skill 的覆盖情况。

扫描 .claude/skills/ 下的 vuln-patterns-*/SKILL.md 文件，
统计每个文件的案例数、覆盖的 CWE、已包含的 GHSA ID，
帮助判断新漏洞应追加到哪个文件还是新建文件。

用法:
    python3 check_existing_skills.py --skills-dir .claude/skills
    python3 check_existing_skills.py --cwe CWE-89 --skills-dir .claude/skills
"""

import argparse
import re
import sys
from pathlib import Path

# CWE 到 Skill 目录的映射
CWE_FILE_MAP: dict[str, str] = {
    "CWE-77": "vuln-patterns-injection",
    "CWE-78": "vuln-patterns-injection",
    "CWE-89": "vuln-patterns-injection",
    "CWE-94": "vuln-patterns-injection",
    "CWE-22": "vuln-patterns-path-traversal",
    "CWE-23": "vuln-patterns-path-traversal",
    "CWE-73": "vuln-patterns-path-traversal",
    "CWE-287": "vuln-patterns-auth-bypass",
    "CWE-288": "vuln-patterns-auth-bypass",
    "CWE-306": "vuln-patterns-auth-bypass",
    "CWE-502": "vuln-patterns-auth-bypass",
    "CWE-918": "vuln-patterns-ssrf",
    "CWE-79": "vuln-patterns-xss",
    "CWE-116": "vuln-patterns-xss",
    "CWE-327": "vuln-patterns-crypto",
    "CWE-328": "vuln-patterns-crypto",
    "CWE-330": "vuln-patterns-crypto",
}


def analyze_skill_file(filepath: Path) -> dict:
    """分析单个 Skill 的 SKILL.md，提取案例数、GHSA ID、CWE 等信息。"""
    content = filepath.read_text(encoding="utf-8")
    lines = content.splitlines()

    # 统计案例数（匹配 "### Case" 标题）
    case_pattern = re.compile(r"^###\s+Case\s+\d+", re.MULTILINE)
    cases = case_pattern.findall(content)

    # 提取已有的 GHSA ID
    ghsa_pattern = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")
    ghsa_ids = set(ghsa_pattern.findall(content))

    # 提取已有的 CVE ID
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")
    cve_ids = set(cve_pattern.findall(content))

    # 提取覆盖的 CWE（从标题和内容中）
    cwe_pattern = re.compile(r"CWE-\d+")
    cwes = set(cwe_pattern.findall(content))

    return {
        "dir": filepath.parent.name,
        "path": str(filepath),
        "lines": len(lines),
        "cases": len(cases),
        "ghsa_ids": sorted(ghsa_ids),
        "cve_ids": sorted(cve_ids),
        "cwes": sorted(cwes),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="检查已有漏洞模式 Skill 的覆盖情况"
    )
    parser.add_argument(
        "--skills-dir",
        type=str,
        default=".claude/skills",
        help="Skills 目录路径 (默认: .claude/skills)",
    )
    parser.add_argument(
        "--cwe",
        type=str,
        default=None,
        help="查询特定 CWE 应归入哪个文件 (如 CWE-89)",
    )
    args = parser.parse_args()

    skills_dir = Path(args.skills_dir)
    if not skills_dir.exists():
        print(f"错误: 目录 {skills_dir} 不存在", file=sys.stderr)
        sys.exit(1)

    # 如果查询特定 CWE
    if args.cwe:
        target_dir = CWE_FILE_MAP.get(args.cwe)
        if target_dir:
            target_path = skills_dir / target_dir / "SKILL.md"
            exists = target_path.exists()
            print(f"{args.cwe} → {target_dir}/SKILL.md")
            if exists:
                info = analyze_skill_file(target_path)
                print(f"  状态: 已存在 ({info['cases']} 个案例, {info['lines']} 行)")
                if info["cases"] >= 8:
                    print("  建议: 案例已满，考虑替换最低价值案例或拆分文件")
                else:
                    print(f"  建议: 可追加 (还可加 {8 - info['cases']} 个案例)")
            else:
                print("  状态: 文件不存在")
                print("  建议: 新建此 Skill")
        else:
            print(f"{args.cwe} 未在映射表中，建议新建对应 Skill")
        return

    # 全量扫描
    skill_dirs = sorted(
        d for d in skills_dir.iterdir()
        if d.is_dir() and d.name.startswith("vuln-patterns-") and (d / "SKILL.md").exists()
    )
    if not skill_dirs:
        print("未找到 vuln-patterns-*/SKILL.md 文件")
        return

    print("=== 已有漏洞模式 Skill 文件 ===\n")
    all_ghsa: set[str] = set()
    all_cwe: set[str] = set()

    for d in skill_dirs:
        info = analyze_skill_file(d / "SKILL.md")
        all_ghsa.update(info["ghsa_ids"])
        all_cwe.update(info["cwes"])

        status = "✓" if info["cases"] < 8 else "⚠ 已满"
        print(f"  {info['dir']}/SKILL.md")
        print(f"    案例: {info['cases']}/8 {status} | 行数: {info['lines']}/300")
        print(f"    CWE: {', '.join(info['cwes'])}")
        print(f"    GHSA: {', '.join(info['ghsa_ids'][:5])}")
        if len(info["ghsa_ids"]) > 5:
            print(f"          ... 共 {len(info['ghsa_ids'])} 个")
        print()

    # 检查未覆盖的 CWE
    covered_cwes = set()
    for cwe in CWE_FILE_MAP:
        target = skills_dir / CWE_FILE_MAP[cwe] / "SKILL.md"
        if target.exists():
            covered_cwes.add(cwe)

    uncovered = set(CWE_FILE_MAP.keys()) - covered_cwes
    if uncovered:
        print("=== 未覆盖的 CWE (需新建 Skill) ===")
        by_dir: dict[str, list[str]] = {}
        for cwe in sorted(uncovered):
            d = CWE_FILE_MAP[cwe]
            by_dir.setdefault(d, []).append(cwe)
        for d, cwes in sorted(by_dir.items()):
            print(f"  {d}: {', '.join(cwes)}")

    print(f"\n总计: {len(skill_dirs)} 个 Skill, "
          f"{len(all_ghsa)} 个 GHSA, {len(all_cwe)} 个 CWE")


if __name__ == "__main__":
    main()

"""公共工具函数。"""

import os
import subprocess
import sys


def check_gh_auth() -> None:
    """检查 GitHub 认证状态。

    优先级：
    1. gh CLI 已登录（gh auth status）
    2. 环境变量 GITHUB_TOKEN / GH_TOKEN
    3. 都没有则提示用户并退出
    """
    # 检查 gh CLI 是否已认证
    result = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return

    # 检查环境变量
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        # gh CLI 会自动读取 GITHUB_TOKEN / GH_TOKEN 环境变量
        return

    print(
        "错误: 未检测到 GitHub 认证。请先执行以下任一操作:\n"
        "\n"
        "  方式 1: gh auth login\n"
        "  方式 2: export GITHUB_TOKEN=ghp_xxxxxxxxxxxx\n"
        "  方式 3: export GH_TOKEN=ghp_xxxxxxxxxxxx\n"
        "\n"
        "未认证状态下 API 速率限制为 60 次/小时，无法完成全量拉取。\n"
        "认证后速率限制为 5000 次/小时。",
        file=sys.stderr,
    )
    sys.exit(1)

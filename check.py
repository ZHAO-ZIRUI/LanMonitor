#!/usr/bin/env python3
"""Repeatable audit gate: static analysis, isolated backend and frontend tests."""

import ast
import importlib.util
import os
import shutil
# this runner executes fixed local validation tools, without a shell.
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCES = ["app.py", "config.py", "constants.py", "store.py", "scanner.py", "http_api.py", "manage.py", "check.py"]


def main():
    missing = [name for name in ("ruff", "bandit") if importlib.util.find_spec(name) is None]
    node = os.environ.get("NODE") or shutil.which("node")
    if missing or not node:
        if missing:
            print("请先安装开发检查依赖：python3 -m pip install -r requirements-dev.txt", file=sys.stderr)
        if not node:
            print("前端测试需要 Node.js 18+；请加入 PATH 或用 NODE 指定可执行文件。", file=sys.stderr)
        return 1
    for path in [*(ROOT / name for name in SOURCES), *sorted((ROOT / "tests").glob("*.py"))]:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 9))
    commands = [
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "bandit", "-q", *SOURCES],
        [sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"],
        [node, "--check", "static/app.js"],
        [node, "--test", "tests/frontend.test.js"],
    ]
    for command in commands:
        print("\n运行：" + " ".join(command), flush=True)
        # fixed checks; NODE is an explicit local executable override.
        result = subprocess.run(command, cwd=ROOT, timeout=180, check=False)  # nosec B603
        if result.returncode:
            return result.returncode
    print("\n全部检查通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

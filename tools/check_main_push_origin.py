#!/usr/bin/env python3
"""main に着いた commit が、マージ済みのPRを経ているかを GitHub 側で見る。

**なぜ要るか（2026-09-05）。** main直push を落とす経路は3本になった——Claude Code の
PreToolUse hook、Cowork面の印→定期タスク、そして git の `pre-push`（`tools/git-hooks/`）。
**3本とも `git push` より前に効く阻止で、git を通らない書き込みは1本も見ない**——
GitHub API（MCP の `push_files` / `create_or_update_file`）と Web 画面の直接編集は、
どの clone の hook も通らずに main へ着く。GitHub 側のブランチ保護は個人プランでは
効かない（`BRANCH_PROTECTION_SETUP.md`）ので、**着いた後に赤くする経路だけが、
面にも clone にも依存せずに全部を見られる。** これは阻止ではなく検知。

`.github/workflows/main-guard.yml` が main への push のたびにこれを走らせる。
**通常は緑で無音。** 直pushの時だけ赤くなり、その1通がようすけさんへ届く——
それは望んだ信号であって、通知の増加ではない（`CLAUDE.md`「赤いCI」）。

    python3 tools/check_main_push_origin.py --repo owner/name --sha <commit>

exit 0 = マージ済みPRの commit / 1 = **PRを経ていない**（main直push） /
2 = **判定できなかった**（token 無し・API失敗・引数不足。合格ではない・`ADAPTIVE_QA.md` §6-2）

判定：`GET /repos/{repo}/commits/{sha}/pulls` が返すPRに、`merged_at` を持ち base が main の
ものが1つでもあれば PR 経由。squash でも merge commit でも、その commit は PR に紐づく。
**読み取り専用。** GET しか呼ばない。token は出力へ出さない。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable

API = "https://api.github.com"
TIMEOUT = 30
BASE_BRANCH = "main"


def token() -> str | None:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    return None


def fetch_pulls(repo: str, sha: str, tok: str | None) -> list[dict] | None:
    """紐づくPRの一覧。取れなければ None（空リストとは区別する）。"""
    request = urllib.request.Request(
        f"{API}/repos/{repo}/commits/{sha}/pulls?per_page=100",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ys-os-main-guard",
            **({"Authorization": f"Bearer {tok}"} if tok else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    return data if isinstance(data, list) else None


def classify(pulls: list[dict] | None) -> tuple[int, str]:
    """(exit code, 1行の理由)。API の結果だけを見る純粋関数——テストはここを突く。"""
    if pulls is None:
        return 2, "紐づくPRを取得できなかった（判定していない。合格ではない）"
    merged = [
        p for p in pulls
        if p.get("merged_at") and (p.get("base") or {}).get("ref") == BASE_BRANCH
    ]
    if merged:
        numbers = ", ".join(f"#{p.get('number', '?')}" for p in merged)
        return 0, f"マージ済みPR {numbers} の commit"
    if pulls:
        states = ", ".join(f"#{p.get('number', '?')}={p.get('state', '?')}" for p in pulls)
        return 1, f"紐づくPRはあるがマージ済みでない（{states}）——PRを経ずに main へ着いた"
    return 1, "紐づくPRが1本も無い——PRを経ずに main へ着いた"


def head_sha() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, timeout=10).stdout.strip() or None
    except (subprocess.SubprocessError, OSError):
        return None


def main(argv: list[str] | None = None,
         fetch: Callable[[str, str, str | None], list[dict] | None] = fetch_pulls) -> int:
    ap = argparse.ArgumentParser(description="main に着いた commit が PR を経ているか")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="owner/name")
    ap.add_argument("--sha", default=None, help="見る commit（既定: HEAD）")
    args = ap.parse_args(argv)

    if not args.repo:
        print("  判定不能 --repo（または GITHUB_REPOSITORY）が無い。どのrepoの main かを決められない。",
              file=sys.stderr)
        return 2
    sha = args.sha or head_sha()
    if not sha:
        print("  判定不能 --sha が無く、HEAD も読めない。", file=sys.stderr)
        return 2

    code, why = classify(fetch(args.repo, sha, token()))
    if code == 0:
        print(f"  OK   {sha[:8]} は {why}")
    elif code == 1:
        print(f"  NG   {sha[:8]} は {why}", file=sys.stderr)
        print("       AGENTS.md §5——正本編集は作業ブランチ → PR → mainマージで完了する。", file=sys.stderr)
        print("       直し方: この commit を revert する PR を開くか、同じ内容を PR に載せ直す。"
              " 経路（API・Web編集・hook未配線のclone）を INCIDENTS.md へ残す。", file=sys.stderr)
    else:
        print(f"  判定不能 {sha[:8]}: {why}"
              + ("。token が無い: GITHUB_TOKEN / GH_TOKEN" if token() is None else ""),
              file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())

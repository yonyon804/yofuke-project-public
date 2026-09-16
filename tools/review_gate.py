#!/usr/bin/env python3
"""PR検品ゲート——実行役と別の監査役が、この差分を、この完了条件で検品した受領書が無いPRを落とす。

**なぜ要るか（2026-09-16・ようすけさん「どの作業においても指示役、実行役、監査役と役割分担が
無視されなくなれば完成度が上がったと言える」「監査、検品担当が確実に機能すること」）。**
`ORG.md` §2 は生成・実行と分離した監査担当を組織図に置き、`ADAPTIVE_QA.md` §1 は
「作成者の再読は独立QAではない」と書く。**ところがPRを開いてmainへ入れるまでに、実行役と
別の主体が差分を見たことを要求する場所が1つも無かった。** 独立検査ゲート
（`tools/validate_confirmation_evidence.py`）が要るのは高影響ファイルかQA-2の自己宣言だけで、
証拠として認める「機械経路」は実行役が自分で走らせたtestの件数——**監査役の不在は、
どのゲートからも見えなかった**（`AGENTS.md` §3「規則が無いのではなく、規則を守らせる経路が無い」）。
`AUDIT_CLOSING_DELTA.md` の失敗の型で言えば「役割が条文にしか無い」。

**何を要求するか。** PR本文に2つ。

1. `## 目的と完了条件` — 指示役が凍結した完了条件。`AC-1: …` の形で1件以上。
2. `## 独立検査` の中の受領書（```review-receipt … ``` のJSON）——監査役が①いまの差分
   （`scope_sha256`）に対して②各 AC と共通検査 R-* を判定した記録。

受領書の `scope_sha256` は、**変更ファイルごとの「状態＋パス＋内容blob」を並べたもののhash。**
検品した後に1バイトでも変えれば一致しない（変更済み成果物で旧PASSを通さない・`WORK_ORDER.md` §5）。
mainを取り込んだだけ（競合なし）では変わらない——差分の中身が同じだから。

**何を落とすか。** 2節のどちらかが無い／ACが0件／受領書が無い・壊れている／scopeが今の差分と違う／
監査役が実行役と同じ（表記揺れを正規化して比較）／`inspector_context` が `self`／ACか R-* に
判定の無いもの・pass でないもの・証拠の無いものがある／`verdict` が pass でない。

**何を落とせないか（隠さない）。** 実行役が監査役の名前を書いて受領書を自分で作れば通る。
ID比較は同名の検出であって別主体の証明ではない（`WORK_ORDER.md` §5 と同じ限界）。
だからこの道具は**手順を省けなくする**ものであって、検品の中身を証明するものではない。
中身は受領書の証拠locatorを次の担当が追う。**受領書を書く側が楽な形にしてある**——
`packet` が監査役へ渡す物（差分・完了条件・共通検査・受領書の雛形）を1コマンドで出す。

    # 実行役：監査役へ渡す物を作る（PR本文の `## 目的と完了条件` を読む）
    python3 tools/review_gate.py packet --pr-body-file PR.md --out /tmp/packet.md
    # 監査役（sub-agent・別session・別モデル）が packet を読み、受領書JSONを返す
    # 実行役：受領書を PR本文の `## 独立検査` へ ```review-receipt ブロックで貼り、検証する
    python3 tools/review_gate.py verify --pr-body-file PR.md
    # CI（PR head を名指し）
    python3 tools/review_gate.py verify --pr-body-file pr-body.txt --base origin/main --rev <head sha>

子repoからは `python3 ../ys-os/tools/review_gate.py verify --repo . --pr-body-file PR.md`。
**このファイルは ys-os が正。** 子repoのCIは同じ内容の写しを `tools/` に持ち、ys-os の
`tests/test_review_gate.py` が写しのずれを落とす（`check_inspection_ledger.py` と同じ配り方）。

終了コード: 0=通った / 1=落ちた / 2=判定できない（git が無い・baseが無い・本文が読めない）。
**判定できないを合格に丸めない**（`ADAPTIVE_QA.md` §6-2）。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

SCHEMA_VERSION = 1

# 監査役が毎回見る共通検査。ACは案件ごと、こちらはY's OSの恒常規律（`AGENTS.md` §3・§5・§7）。
COMMON_CHECKS: tuple[tuple[str, str], ...] = (
    ("R-SCOPE", "差分が `## 目的と完了条件` の範囲内で、依頼に無い別領域の変更や `AGENTS.md` §5 の ASK／DENY に当たる変更を含まない"),
    ("R-CLAIM", "PR本文の主張（何を直した・何を測った）が差分で裏づけられる。差分に無いことを「済」と書いていない"),
    ("R-DUP", "同じ規則・本文を別ファイルへ複製していない。別文書を正と宣言した節が本文を抱え込んでいない（`AGENTS.md` §3）"),
    ("R-PTR", "新しく書いた参照（ファイル・節・ツール・決定ID）が実在する。死んだポインタを増やしていない"),
    ("R-DEL", "置換した旧版・役目を終えた中間物・一時ファイルが消されている。「念のため」で残っていない"),
    ("R-SAFE", "秘匿情報本文・認証情報・大容量データがGitHubへ入っていない。可否を日付なしで固定していない"),
)
CHECK_IDS = tuple(cid for cid, _ in COMMON_CHECKS)
INSPECTOR_CONTEXTS = ("subagent", "separate_session", "separate_model", "human")
RESULTS = ("pass", "fail", "unknown")

GOAL_HEADING = re.compile(r"(?m)^#{1,6}\s*目的と完了条件\s*$")
EVIDENCE_HEADING = re.compile(r"(?m)^#{1,6}\s*独立検査\s*$")
NEXT_HEADING = re.compile(r"(?m)^#{1,6}\s+")
AC_LINE = re.compile(r"(?m)^\s*(?:[-*]\s*)?(AC-\d+)\s*[:：]\s*(\S.*?)\s*$")
RECEIPT_BLOCK = re.compile(r"```review-receipt[ \t]*\n(.*?)\n```", re.S)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PLACEHOLDER_EVIDENCE = {"", "-", "—", "TBD", "tbd", "N/A", "n/a", "なし", "未実施", "（ここへ書く）", "..."}


class Undecidable(Exception):
    """判定に要る材料が取れなかった（exit 2）。"""


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise Undecidable(f"git {' '.join(args)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout


def repo_root(path: Path) -> Path:
    try:
        return Path(_git(path, "rev-parse", "--show-toplevel").strip())
    except Undecidable as exc:
        raise Undecidable(f"{path} は git repo ではない（{exc}）")


def section(body: str, heading: re.Pattern[str]) -> str | None:
    match = heading.search(body)
    if match is None:
        return None
    rest = body[match.end():]
    following = NEXT_HEADING.search(rest)
    return rest[: following.start()] if following else rest


def acceptance_criteria(body: str) -> dict[str, str] | None:
    """`## 目的と完了条件` の AC-n → 本文。節が無ければ None、あって0件なら空dict。"""
    text = section(body, GOAL_HEADING)
    if text is None:
        return None
    found: dict[str, str] = {}
    for ac_id, description in AC_LINE.findall(text):
        found.setdefault(ac_id, description)
    return found


def receipt_from_body(body: str) -> dict | None:
    match = RECEIPT_BLOCK.search(body)
    if match is None:
        return None
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        return {"__error__": f"review-receipt のJSONが読めない: {exc}"}
    if not isinstance(data, dict):
        return {"__error__": "review-receipt はJSONオブジェクトで書く"}
    return data


def scope_rows(repo: Path, base: str, rev: str | None) -> list[str]:
    """変更ファイルごとの `状態\\tパス\\tblob`。rev=None は作業ツリー（未commit・未追跡を含む）。"""
    target = rev or "HEAD"
    merge_base = _git(repo, "merge-base", base, target).strip()
    if not merge_base:
        raise Undecidable(f"{base} と {target} の merge-base が取れない")
    args = ["diff", "--name-status", "--no-renames", "-z", merge_base]
    if rev:
        args.append(rev)
    raw = _git(repo, *args)
    parts = raw.split("\0")
    rows: dict[str, str] = {}
    i = 0
    while i + 1 < len(parts):
        status, path = parts[i][:1], parts[i + 1]
        i += 2
        if not path:
            continue
        rows[path] = status
    if rev is None:
        for path in _git(repo, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
            if path and path not in rows:
                rows[path] = "A"
    out = []
    for path in sorted(rows):
        status = rows[path]
        if status == "D":
            blob = "-"
        elif rev:
            blob = _git(repo, "rev-parse", f"{rev}:{path}").strip()
        else:
            full = repo / path
            if not full.is_file():
                blob = "-"
                status = "D"
            else:
                blob = _git(repo, "hash-object", "--", path).strip()
        out.append(f"{status}\t{path}\t{blob}")
    return out


def scope_sha256(rows: list[str]) -> str:
    return hashlib.sha256(("\n".join(rows) + "\n").encode("utf-8")).hexdigest()


def diff_text(repo: Path, base: str, rev: str | None) -> str:
    target = rev or "HEAD"
    merge_base = _git(repo, "merge-base", base, target).strip()
    args = ["diff", "--no-color", "--no-ext-diff", "--no-renames", merge_base]
    if rev:
        args.append(rev)
    text = _git(repo, *args)
    if rev is None:
        for path in _git(repo, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
            if not path:
                continue
            proc = subprocess.run(["git", "-C", str(repo), "diff", "--no-color", "--no-index", "--", "/dev/null", path],
                                  capture_output=True, text=True)
            text += proc.stdout
    return text


def principal(value: object) -> str:
    """同名の検出用の正規化（NFKC・casefold・英数字だけ）。別主体の証明ではない。"""
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return "".join(ch for ch in text if unicodedata.category(ch)[0] in "LN")


def build_packet(rows: list[str], scope: str, criteria: dict[str, str], diff: str, goal_text: str) -> str:
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "scope_sha256": scope,
        "executor": "<実行役のID。例: claude-code.remote / gpt.chat / codex.cli>",
        "inspector": "<監査役のID。実行役と別。例: claude-code.remote.subagent / gpt.chat.review-session>",
        "inspector_context": "subagent | separate_session | separate_model | human",
        "inspected_at": dt.date.today().isoformat(),
        "criteria": {ac: {"result": "pass|fail", "evidence": "<何を見て判定したか>"} for ac in criteria},
        "checks": {cid: {"result": "pass|fail", "evidence": "<何を見て判定したか>"} for cid in CHECK_IDS},
        "findings": [{"severity": "block|fix|note", "text": "<指摘>", "resolved_by": "<直した後のcommit/差分。blockは未解決のまま通らない>"}],
        "verdict": "pass|fail",
    }
    lines = [
        "# PR検品パケット（監査役へ）",
        "",
        "あなたは**監査役**。実行役の結論・自己評価・弁明は渡していない。**差分と完了条件と正本**だけで判定する。",
        "判定できない項目は `unknown` にして通さない。指摘は severity `block`（通さない）／`fix`（直せば通る）／`note` で書く。",
        "**この差分に対する受領書**として下の雛形を埋めたJSONだけを返す。scope_sha256 は変えない。",
        "",
        f"- scope_sha256: `{scope}`",
        f"- 変更ファイル: {len(rows)} 件",
        "",
        "## 完了条件（指示役が凍結）",
        "",
        goal_text.strip() or "（`## 目的と完了条件` が空）",
        "",
        "## 共通検査（毎回）",
        "",
    ]
    lines += [f"- {cid}: {question}" for cid, question in COMMON_CHECKS]
    lines += [
        "",
        "## 受領書の雛形",
        "",
        "```review-receipt",
        json.dumps(receipt, ensure_ascii=False, indent=1),
        "```",
        "",
        "## 変更ファイル（状態・パス・内容blob）",
        "",
        "```",
        *rows,
        "```",
        "",
        "## 差分",
        "",
        "```diff",
        diff.rstrip("\n"),
        "```",
        "",
    ]
    return "\n".join(lines)


def verify_receipt(body: str, expected_scope: str, errors: list[str], counts: dict[str, int]) -> None:
    criteria = acceptance_criteria(body)
    if criteria is None:
        errors.append("PR本文に `## 目的と完了条件` が無い。指示役が凍結した完了条件（`AC-1: …`）を1件以上書く")
    elif not criteria:
        errors.append("`## 目的と完了条件` に `AC-n: …` の形の完了条件が1件も無い")
    counts["criteria"] = len(criteria or {})
    if section(body, EVIDENCE_HEADING) is None:
        errors.append("PR本文に `## 独立検査` が無い。受領書はこの節へ ```review-receipt ブロックで置く")
    receipt = receipt_from_body(body)
    if receipt is None:
        errors.append("受領書（```review-receipt … ``` のJSON）が無い。監査役が差分を検品した記録なしにPRは開けない")
        return
    if "__error__" in receipt:
        errors.append(receipt["__error__"])
        return
    counts["receipt"] = 1
    if receipt.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"受領書の schema_version は {SCHEMA_VERSION}")
    scope = str(receipt.get("scope_sha256", ""))
    if not SHA256.match(scope):
        errors.append("受領書の scope_sha256 が64桁のhexではない（packet の値をそのまま写す）")
    elif scope != expected_scope:
        errors.append(
            f"受領書の scope（{scope[:12]}…）が今の差分と違う。検品の後に内容が変わっている——"
            "直した分をもう一度監査役へ渡す（旧PASSは持ち越さない）。"
            f"いまの差分の scope_sha256 は {expected_scope}"
            "（git が無い面は、この値を受領書へ写してPR本文を編集すると同じ判定が再実行される）"
        )
    executor, inspector = receipt.get("executor"), receipt.get("inspector")
    if not principal(executor) or not principal(inspector):
        errors.append("受領書の executor / inspector が空か、比較できる文字を持たない")
    elif principal(executor) == principal(inspector):
        errors.append(f"監査役（{inspector}）が実行役（{executor}）と同じ。セルフチェックは検品ではない（`ADAPTIVE_QA.md` §1）")
    context = receipt.get("inspector_context")
    if context not in INSPECTOR_CONTEXTS:
        errors.append(f"inspector_context は {INSPECTOR_CONTEXTS} のどれか（実行役自身＝self は通らない）")
    if not DATE.match(str(receipt.get("inspected_at", ""))):
        errors.append("inspected_at は YYYY-MM-DD")

    def judge(kind: str, expected: list[str], given: object) -> None:
        if not isinstance(given, dict):
            errors.append(f"受領書の {kind} がオブジェクトではない")
            return
        for key in expected:
            entry = given.get(key)
            if not isinstance(entry, dict):
                errors.append(f"{kind} {key} の判定が無い（判定の無い項目は未検品）")
                continue
            result = entry.get("result")
            evidence = str(entry.get("evidence", "")).strip()
            if result not in RESULTS:
                errors.append(f"{kind} {key} の result は {RESULTS} のどれか")
            elif result != "pass":
                errors.append(f"{kind} {key} が {result}。全項目 pass まで本人提示・公開・完成報告へ進めない（`WORK_ORDER.md` §5）")
            if evidence in PLACEHOLDER_EVIDENCE or evidence.startswith("<"):
                errors.append(f"{kind} {key} に証拠（何を見て判定したか）が無い")
        for key in given:
            if key not in expected:
                errors.append(f"{kind} {key} は本文の完了条件／共通検査に無い（本文と受領書がずれている）")

    judge("criteria", list((criteria or {}).keys()), receipt.get("criteria"))
    judge("checks", list(CHECK_IDS), receipt.get("checks"))
    findings = receipt.get("findings")
    if findings is not None:
        if not isinstance(findings, list):
            errors.append("findings はリスト")
        else:
            for item in findings:
                if not isinstance(item, dict):
                    errors.append("findings の要素はオブジェクト")
                    continue
                text = str(item.get("text", "")).strip()
                if text.startswith("<") or not text:
                    continue  # 雛形の空行は無視
                if item.get("severity") == "block" and not str(item.get("resolved_by", "")).strip():
                    errors.append(f"block の指摘が未解決: {text[:60]}")
    if receipt.get("verdict") != "pass":
        errors.append(f"verdict が pass でない（{receipt.get('verdict')!r}）")


def cmd_packet(args: argparse.Namespace) -> int:
    repo = repo_root(Path(args.repo))
    body = Path(args.pr_body_file).read_text(encoding="utf-8")
    criteria = acceptance_criteria(body)
    if criteria is None:
        print("PR本文に `## 目的と完了条件` が無い。監査役へ渡す完了条件が無いのでパケットを作れない", file=sys.stderr)
        return 1
    if not criteria:
        print("`## 目的と完了条件` に `AC-n: …` が1件も無い", file=sys.stderr)
        return 1
    rows = scope_rows(repo, args.base, args.rev)
    if not rows:
        print("変更ファイルが0件——検品する差分が無い（baseの指定を疑う）", file=sys.stderr)
        return 2
    text = build_packet(rows, scope_sha256(rows), criteria, diff_text(repo, args.base, args.rev),
                        section(body, GOAL_HEADING) or "")
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"packet: {args.out}（変更 {len(rows)} 件・AC {len(criteria)} 件・scope {scope_sha256(rows)[:12]}…）")
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    repo = repo_root(Path(args.repo))
    body = Path(args.pr_body_file).read_text(encoding="utf-8")
    rows = scope_rows(repo, args.base, args.rev)
    if not rows:
        print("変更ファイルが0件——検品する差分が無い（baseの指定を疑う。空を合格にしない）", file=sys.stderr)
        return 2
    errors: list[str] = []
    counts: dict[str, int] = {"changed": len(rows)}
    verify_receipt(body, scope_sha256(rows), errors, counts)
    if errors:
        print("PR検品ゲート NG（`tools/review_gate.py` 冒頭）")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"PR検品ゲート passed（変更 {counts['changed']} 件・AC {counts['criteria']} 件・共通検査 {len(CHECK_IDS)} 件・監査役≠実行役）")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    repo = repo_root(Path(args.repo))
    rows = scope_rows(repo, args.base, args.rev)
    for row in rows:
        print(row)
    print(scope_sha256(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func in (("packet", cmd_packet), ("verify", cmd_verify), ("scope", cmd_scope)):
        p = sub.add_parser(name)
        p.add_argument("--repo", default=".")
        p.add_argument("--base", default="origin/main")
        p.add_argument("--rev", default=None, help="検品対象のcommit。省略時は作業ツリー（未commit・未追跡を含む）")
        if name != "scope":
            p.add_argument("--pr-body-file", required=True)
        if name == "packet":
            p.add_argument("--out", default=None)
        p.set_defaults(func=func)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Undecidable as exc:
        print(f"判定できない（合格ではない）: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"判定できない（合格ではない）: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

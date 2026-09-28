#!/usr/bin/env python3
"""
Scan files with every rule in this repo and report hits per file and per rule.

    python tools/yara_scan.py samples/
    python tools/yara_scan.py C:\\Windows\\System32 --rules rules/xworm --summary-only
    python tools/yara_scan.py samples/ -o report.csv --pe-info

The per-rule counts at the end are what goes into the testing tables:
run once on a sample set (true positives) and once on clean files (false positives).

Artful Dodger - MIT License
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

import yara

REPO_RULES = Path(__file__).resolve().parent.parent / "rules"
FIELDS = ["file", "sha256", "rule", "family", "strings", "imphash", "sections"]


def load_rules(path: Path) -> tuple[yara.Rules, list[Path]]:
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.suffix in (".yar", ".yara"))
    if not files:
        raise SystemExit(f"no .yar files under {path}")
    base = path.parent if path.is_file() else path
    namespaces = {str(f.relative_to(base).with_suffix("")).replace(os.sep, "/"): str(f) for f in files}
    try:
        return yara.compile(filepaths=namespaces), files
    except yara.SyntaxError as e:
        raise SystemExit(f"rule error: {e}")


def iter_targets(paths: list[str]) -> Iterable[Path]:
    for p in map(Path, paths):
        if p.is_file():
            yield p
        elif p.is_dir():
            for root, _, names in os.walk(p):
                for name in sorted(names):
                    yield Path(root) / name
        else:
            print(f"not found: {p}", file=sys.stderr)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pe_info(path: Path) -> tuple[str, str]:
    try:
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        names = [s.Name.rstrip(b"\x00").decode(errors="replace") for s in pe.sections]
        sections = " ".join(f"{n}:{s.get_entropy():.2f}" for n, s in zip(names, pe.sections))
        imphash = pe.get_imphash()
        pe.close()
        return imphash, sections
    except Exception:
        return "", ""


def matched_strings(match: yara.Match, limit: int = 5) -> str:
    out = []
    for s in match.strings[:limit]:
        data = s.instances[0].matched_data if s.instances else b""
        out.append(f"{s.identifier}={data[:40]!r}")
    return " ".join(out)


def scan(rules: yara.Rules, targets: Iterable[Path], with_pe: bool, timeout: int) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    stats = {"scanned": 0, "matched_files": 0, "errors": 0, "per_rule": Counter()}
    for path in targets:
        try:
            matches = rules.match(str(path), timeout=timeout)
        except yara.TimeoutError:
            print(f"timeout: {path}", file=sys.stderr)
            stats["errors"] += 1
            continue
        except yara.Error:
            # locked or unreadable files are common when scanning system folders
            stats["errors"] += 1
            continue
        stats["scanned"] += 1
        if not matches:
            continue
        stats["matched_files"] += 1
        digest = sha256(path)
        imphash, sections = pe_info(path) if with_pe else ("", "")
        for m in matches:
            stats["per_rule"][m.rule] += 1
            rows.append({
                "file": str(path),
                "sha256": digest,
                "rule": m.rule,
                "family": m.meta.get("family", ""),
                "strings": matched_strings(m),
                "imphash": imphash,
                "sections": sections,
            })
    return rows, stats


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Scan files with the rules in this repo")
    ap.add_argument("targets", nargs="+", help="files or folders (folders are walked recursively)")
    ap.add_argument("--rules", type=Path, default=REPO_RULES, help="rule file or folder (default: rules/)")
    ap.add_argument("-o", "--output", help="write matches to CSV")
    ap.add_argument("--pe-info", action="store_true", help="add imphash and section entropy to the CSV")
    ap.add_argument("--summary-only", action="store_true", help="don't print each match")
    ap.add_argument("--timeout", type=int, default=30, help="seconds per file")
    args = ap.parse_args(argv)

    rules, rule_files = load_rules(args.rules)
    all_rules = [r.identifier for r in rules]
    rows, stats = scan(rules, iter_targets(args.targets), args.pe_info, args.timeout)

    if not args.summary_only:
        for r in rows:
            print(f"{r['rule']:<36} {r['file']}")

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)

    print(f"\n{len(rule_files)} rule files, {len(all_rules)} rules")
    print(f"{stats['scanned']} files scanned, {stats['matched_files']} matched, {stats['errors']} unreadable")
    for name in all_rules:
        print(f"  {stats['per_rule'][name]:>5}  {name}")
    if args.output:
        print(f"matches written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

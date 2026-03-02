#!/usr/bin/env python3
"""CAPE custom rules installer/validator.

Copies Sigma/YARA/Suricata custom rules into a CAPEv2 tree and optionally
restarts cape-processor. Provides a validate-only mode to check paths.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


RULE_DIRS = ["sigma", "yara", "suricata"]
RULE_EXTS = {".yml", ".yaml", ".yara", ".yar", ".rules"}


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def path_exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def check_src(src_root: Path, rules: list[str]) -> list[Path]:
    missing = []
    for rel in rules:
        p = src_root / rel
        if not path_exists(p):
            missing.append(p)
    return missing


def check_dst(dst_root: Path, rules: list[str]) -> list[Path]:
    missing = []
    for rel in rules:
        p = dst_root / rel
        if not path_exists(p):
            missing.append(p)
    return missing


def collect_rules(src_root: Path) -> list[str]:
    rules: list[str] = []
    for d in RULE_DIRS:
        base = src_root / d
        if not path_exists(base):
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            if p.name == ".placeholder":
                continue
            if p.suffix.lower() not in RULE_EXTS:
                continue
            rules.append(str(p.relative_to(src_root)))
    return sorted(set(rules))


def copy_rule(src: Path, dst: Path, dry_run: bool) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        print(f"DRY-RUN copy {src} -> {dst}")
        return
    shutil.copy2(src, dst)
    print(f"Copied {src} -> {dst}")


def restart_service(dry_run: bool) -> None:
    cmd = ["systemctl", "restart", "cape-processor.service"]
    if dry_run:
        print(f"DRY-RUN {' '.join(cmd)}")
        return
    subprocess.run(cmd, check=False)


def check_service_status() -> None:
    if shutil.which("systemctl") is None:
        eprint("systemctl not found; cannot check service status.")
        return
    cmd = ["systemctl", "is-active", "cape-processor.service"]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    status = (result.stdout or "").strip()
    if status:
        print(f"cape-processor.service status: {status}")
    else:
        eprint("Failed to read service status.")


def check_log_for_rules(log_path: Path, rules: list[str]) -> None:
    if not path_exists(log_path):
        eprint(f"Log file not found: {log_path}")
        return
    try:
        data = log_path.read_text(errors="replace")
    except OSError as exc:
        eprint(f"Failed to read log file: {exc}")
        return
    hits = []
    for rel in rules:
        name = Path(rel).name
        if name in data:
            hits.append(name)
    if hits:
        print("Log check: found rule filenames in log:")
        for name in hits:
            print(f"- {name}")
    else:
        eprint("Log check: rule filenames not found in log.")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Install CAPE custom rules (Sigma/YARA/Suricata)."
    )
    p.add_argument(
        "--src",
        default="/home/my/CAPEv2/custom",
        help="Source CAPE custom directory (default: /home/my/CAPEv2/custom)",
    )
    p.add_argument(
        "--dst",
        default="/opt/CAPEv2/custom",
        help="Destination CAPE custom directory (default: /opt/CAPEv2/custom)",
    )
    p.add_argument(
        "--rules",
        nargs="*",
        default=None,
        help="Relative rule paths to install (omit to auto-discover)",
    )
    p.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate rule paths without copying",
    )
    p.add_argument(
        "--restart",
        action="store_true",
        help="Restart cape-processor after install",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show actions without changing files",
    )
    p.add_argument(
        "--check-dst",
        action="store_true",
        help="Verify destination rule files exist after install",
    )
    p.add_argument(
        "--check-dst-only",
        action="store_true",
        help="Only check destination rule files without copying",
    )
    p.add_argument(
        "--check-runtime",
        action="store_true",
        help="Check cape-processor service status and optional log search",
    )
    p.add_argument(
        "--runtime-only",
        action="store_true",
        help="Only run runtime checks without copying",
    )
    p.add_argument(
        "--log",
        default=None,
        help="Path to cape-processor log to search for rule filenames",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    src_root = Path(args.src).expanduser().resolve()
    dst_root = Path(args.dst).expanduser().resolve()

    rules = args.rules if args.rules else collect_rules(src_root)
    if not rules:
        eprint("No rule files found to install.")
        return 2

    missing = check_src(src_root, rules)
    if missing:
        eprint("Missing source rule files:")
        for p in missing:
            eprint(f"- {p}")
        return 2

    if args.validate_only and not args.check_dst:
        print("Validation OK. All rule files exist.")
        return 0

    if args.check_dst_only:
        missing_dst = check_dst(dst_root, rules)
        if missing_dst:
            eprint("Destination files missing:")
            for p in missing_dst:
                eprint(f"- {p}")
            return 3
        print("Destination check OK. Rule files exist.")
        return 0

    if args.runtime_only:
        check_service_status()
        if args.log:
            check_log_for_rules(Path(args.log), rules)
        else:
            for candidate in [
                Path("/opt/CAPEv2/log/process.log"),
                Path("/opt/CAPEv2/log/cuckoo.log"),
            ]:
                if path_exists(candidate):
                    check_log_for_rules(candidate, rules)
                    break
        return 0

    for rel in rules:
        src = src_root / rel
        dst = dst_root / rel
        copy_rule(src, dst, args.dry_run)

    if args.check_dst and not args.dry_run:
        missing_dst = check_dst(dst_root, rules)
        if missing_dst:
            eprint("Destination files missing after install:")
            for p in missing_dst:
                eprint(f"- {p}")
            return 3
        print("Destination check OK. Rule files exist.")

    if args.check_runtime:
        check_service_status()
        if args.log:
            check_log_for_rules(Path(args.log), rules)
        else:
            # Default to CAPE logs if present.
            for candidate in [
                Path("/opt/CAPEv2/log/process.log"),
                Path("/opt/CAPEv2/log/cuckoo.log"),
            ]:
                if path_exists(candidate):
                    check_log_for_rules(candidate, rules)
                    break

    if args.restart:
        restart_service(args.dry_run)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Deterministic RTP/media network impairment profiles using Linux tc/netem."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:-]+$")


@dataclass(frozen=True)
class Profile:
    delay_ms: float = 0
    jitter_ms: float = 0
    loss_pct: float = 0
    loss_correlation_pct: float = 0
    duplicate_pct: float = 0
    reorder_pct: float = 0
    corrupt_pct: float = 0
    rate_kbit: int = 0


PROFILES: Dict[str, Profile] = {
    "clean": Profile(),
    "wifi": Profile(delay_ms=12, jitter_ms=8, loss_pct=0.3, reorder_pct=0.1, rate_kbit=30000),
    "4g": Profile(delay_ms=35, jitter_ms=15, loss_pct=0.5, rate_kbit=12000),
    "congested-4g": Profile(delay_ms=90, jitter_ms=45, loss_pct=2.5, reorder_pct=0.5, rate_kbit=2500),
    "bad-mobile": Profile(delay_ms=160, jitter_ms=80, loss_pct=7.0, duplicate_pct=0.5, reorder_pct=2.0, rate_kbit=900),
    "satellite": Profile(delay_ms=550, jitter_ms=25, loss_pct=1.0, rate_kbit=5000),
    "burst-loss": Profile(delay_ms=40, jitter_ms=10, loss_pct=12.0, loss_correlation_pct=70.0, rate_kbit=8000),
    "reorder": Profile(delay_ms=30, jitter_ms=20, loss_pct=0.5, duplicate_pct=0.5, reorder_pct=8.0, rate_kbit=10000),
}


def validate_name(value: Optional[str], kind: str) -> None:
    if value and not SAFE_NAME.fullmatch(value):
        raise ValueError(f"unsafe {kind}: {value!r}")


def validate_profile(p: Profile) -> None:
    for name in ("loss_pct", "loss_correlation_pct", "duplicate_pct", "reorder_pct", "corrupt_pct"):
        value = getattr(p, name)
        if value < 0 or value > 100:
            raise ValueError(f"{name} must be in 0..100")
    if p.delay_ms < 0 or p.jitter_ms < 0 or p.rate_kbit < 0:
        raise ValueError("delay, jitter and rate must be non-negative")
    if p.loss_correlation_pct and not p.loss_pct:
        raise ValueError("loss correlation requires non-zero loss")
    if p.jitter_ms and not p.delay_ms:
        raise ValueError("jitter requires non-zero delay")
    if p.reorder_pct and not p.delay_ms:
        raise ValueError("reordering requires non-zero delay in netem")


def ensure_mutation_safe(namespace: Optional[str], allow_host_interface: bool,
                         dry_run: bool = False) -> None:
    if not dry_run and not namespace and not allow_host_interface:
        raise ValueError(
            "refusing to modify a host interface without --allow-host-interface; "
            "use --namespace for isolated impairment tests"
        )


def tc_prefix(namespace: Optional[str]) -> List[str]:
    if namespace:
        validate_name(namespace, "namespace")
        return ["ip", "netns", "exec", namespace, "tc"]
    return ["tc"]


def build_apply(interface: str, profile: Profile, namespace: Optional[str] = None) -> List[str]:
    validate_name(interface, "interface")
    validate_profile(profile)
    cmd = tc_prefix(namespace) + ["qdisc", "replace", "dev", interface, "root", "netem"]
    if profile.delay_ms:
        cmd += ["delay", f"{profile.delay_ms:g}ms"]
        if profile.jitter_ms:
            cmd += [f"{profile.jitter_ms:g}ms", "distribution", "normal"]
    if profile.loss_pct:
        cmd += ["loss", "random", f"{profile.loss_pct:g}%"]
        if profile.loss_correlation_pct:
            cmd += [f"{profile.loss_correlation_pct:g}%"]
    if profile.duplicate_pct:
        cmd += ["duplicate", f"{profile.duplicate_pct:g}%"]
    if profile.reorder_pct:
        cmd += ["reorder", f"{profile.reorder_pct:g}%", "50%"]
    if profile.corrupt_pct:
        cmd += ["corrupt", f"{profile.corrupt_pct:g}%"]
    if profile.rate_kbit:
        cmd += ["rate", f"{profile.rate_kbit}kbit"]
    return cmd


def build_clear(interface: str, namespace: Optional[str] = None) -> List[str]:
    validate_name(interface, "interface")
    return tc_prefix(namespace) + ["qdisc", "del", "dev", interface, "root"]


def build_show(interface: str, namespace: Optional[str] = None) -> List[str]:
    validate_name(interface, "interface")
    return tc_prefix(namespace) + ["qdisc", "show", "dev", interface]


def run(cmd: List[str], dry_run: bool, tolerate_missing: bool = False) -> int:
    print("+", shlex.join(cmd))
    if dry_run:
        return 0
    proc = subprocess.run(cmd, check=False)
    if tolerate_missing and proc.returncode == 2:
        return 0
    return proc.returncode


def load_custom(path: Path) -> Profile:
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = set(Profile.__dataclass_fields__)
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError("unknown profile fields: " + ", ".join(unknown))
    profile = Profile(**data)
    validate_profile(profile)
    return profile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", "-i", required=False, help="network interface to shape")
    parser.add_argument("--namespace", help="optional Linux network namespace")
    parser.add_argument(
        "--allow-host-interface",
        action="store_true",
        help="permit apply/clear directly on a host interface; namespace use is safer",
    )
    parser.add_argument("--dry-run", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_apply = sub.add_parser("apply", help="apply a named or JSON profile")
    group = p_apply.add_mutually_exclusive_group(required=True)
    group.add_argument("--profile", choices=sorted(PROFILES))
    group.add_argument("--config", type=Path)

    sub.add_parser("clear", help="remove the root qdisc")
    sub.add_parser("show", help="show current qdisc")
    sub.add_parser("profiles", help="print built-in profiles as JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "profiles":
        print(json.dumps({k: asdict(v) for k, v in PROFILES.items()}, indent=2, sort_keys=True))
        return 0
    if not args.interface:
        raise SystemExit("--interface is required for apply/clear/show")

    try:
        if args.command in ("apply", "clear"):
            ensure_mutation_safe(args.namespace, args.allow_host_interface, args.dry_run)
        if args.command == "apply":
            profile = PROFILES[args.profile] if args.profile else load_custom(args.config)
            return run(build_apply(args.interface, profile, args.namespace), args.dry_run)
        if args.command == "clear":
            return run(build_clear(args.interface, args.namespace), args.dry_run, tolerate_missing=True)
        if args.command == "show":
            return run(build_show(args.interface, args.namespace), args.dry_run)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"impair: {exc}")
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

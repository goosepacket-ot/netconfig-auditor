"""Command line: ncaudit run config.txt --pack rulepacks/cisco-ios-baseline.yaml --out report/"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .engine import audit, load_pack
from .report import write_all

PACK_DIR = os.path.join(os.path.dirname(__file__), "..", "rulepacks")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ncaudit", description="Audit a network device configuration against a YAML hardening baseline.")
    ap.add_argument("--version", action="version", version=f"ncaudit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="audit a config file")
    r.add_argument("config")
    r.add_argument("--pack", required=True, help="rule pack YAML")
    r.add_argument("--out", default="audit-report", help="output directory")
    r.add_argument("--device", default="", help="device name for the report heading")
    r.add_argument("--fail-under", type=int, default=None, help="exit 2 if the score is below this")
    r.add_argument("--quiet", action="store_true")

    sub.add_parser("packs", help="list the bundled rule packs")

    args = ap.parse_args(argv)

    if args.cmd == "packs":
        for fn in sorted(os.listdir(PACK_DIR)):
            if fn.endswith((".yaml", ".yml")):
                pack = load_pack(os.path.join(PACK_DIR, fn))
                tag = "" if pack.verified else "  [dialect not verified]"
                print(f"{fn:34} {pack.name} — {len(pack.rules)} rules{tag}")
        return 0

    with open(args.config, encoding="utf-8", errors="replace") as f:
        config = f.read()
    pack = load_pack(args.pack)
    res = audit(config, pack)
    device = args.device or os.path.basename(args.config)
    paths = write_all(res, args.out, device)
    if not args.quiet:
        print(f"{device}: score {res['score']}/100 — {res['summary']['failed']} failed of {res['summary']['checks']} checks")
        for f in res["findings"]:
            if f["status"] == "fail":
                scope = f" ({f['scope']})" if f["scope"] and f["scope"] != "(none)" else ""
                print(f"  [{f['severity'].upper():8}] {f['title']}{scope}")
        print("reports:", ", ".join(paths))
    if args.fail_under is not None and res["score"] < args.fail_under:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

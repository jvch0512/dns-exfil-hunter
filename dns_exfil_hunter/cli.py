from __future__ import annotations
import argparse, sys
from . import core


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="dns-exfil-hunter", description="Detect DNS tunneling and exfiltration from query logs. Offline.")
    p.add_argument("input", help="CSV: ts,client,qname,qtype[,rcode]")
    p.add_argument("--min-queries", type=int, default=20)
    p.add_argument("--min-score", type=int, default=60)
    p.add_argument("--allow", action="append", default=[], help="registered domain to ignore (repeatable)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--html", action="store_true")
    p.add_argument("--fail-on-find", action="store_true")
    a = p.parse_args(argv)
    try:
        with open(a.input, encoding="utf-8") as f:
            qs = core.parse(f.read())
    except (core.InputError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    fs = core.analyze(qs, a.min_queries, a.min_score, set(a.allow))
    sys.stdout.write(core.page(fs, len(qs)) if a.html else core.as_json(fs) if a.json else core.text(fs))
    return 1 if a.fail_on_find and fs else 0


if __name__ == "__main__":
    sys.exit(main())

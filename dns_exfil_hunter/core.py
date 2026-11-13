"""DNS tunneling and exfiltration detection from query logs. Standard library only."""
from __future__ import annotations
import csv, html, io, json, math, re
from collections import defaultdict
from dataclasses import dataclass, field

TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "com.br", "com.au", "co.jp", "com.mx", "co.nz", "com.es", "co.za"}
HEXISH = re.compile(r"^[0-9a-f]{12,}$")
B32ISH = re.compile(r"^[a-z2-7]{16,}$")
B64ISH = re.compile(r"^[a-z0-9_-]{20,}$")


class InputError(ValueError):
    pass


@dataclass
class Query:
    ts: float
    client: str
    qname: str
    qtype: str
    rcode: str = ""


@dataclass
class Finding:
    client: str
    domain: str
    queries: int
    unique_subdomains: int
    mean_label_len: float
    mean_entropy: float
    txt_null_ratio: float
    encoded_ratio: float
    qps: float
    score: int
    reasons: list[str] = field(default_factory=list)


def registered_domain(qname: str) -> str:
    parts = qname.lower().rstrip(".").split(".")
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES else 2
    return ".".join(parts[-n:])


def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s)))


def parse(text: str) -> list[Query]:
    rd = csv.DictReader(io.StringIO(text))
    need = {"ts", "client", "qname", "qtype"}
    if not rd.fieldnames or not need <= set(rd.fieldnames):
        raise InputError("CSV needs columns ts,client,qname,qtype (rcode optional)")
    out = []
    for i, row in enumerate(rd, start=2):
        try:
            out.append(Query(float(row["ts"]), row["client"].strip(), row["qname"].strip().lower().rstrip("."), row["qtype"].strip().upper(), (row.get("rcode") or "").strip().upper()))
        except (ValueError, AttributeError):
            raise InputError(f"line {i}: bad row") from None
    return out


def analyze(queries: list[Query], min_queries: int = 20, min_score: int = 60, allow: set[str] | None = None) -> list[Finding]:
    allow = {a.lower() for a in (allow or set())}
    groups: dict[tuple[str, str], list[Query]] = defaultdict(list)
    for q in queries:
        d = registered_domain(q.qname)
        if d in allow or "." not in q.qname:
            continue
        groups[(q.client, d)].append(q)
    out = []
    for (client, dom), qs in groups.items():
        if len(qs) < min_queries:
            continue
        labels = [q.qname[: -(len(dom) + 1)] for q in qs if q.qname != dom and q.qname.endswith("." + dom)]
        if not labels:
            continue
        firsts = [l.split(".")[0] for l in labels]
        uniq = len(set(labels))
        mlen = sum(len(l.replace(".", "")) for l in labels) / len(labels)
        ment = sum(entropy(f) for f in firsts) / len(firsts)
        tn = sum(1 for q in qs if q.qtype in ("TXT", "NULL", "CNAME", "MX")) / len(qs)
        enc = sum(1 for f in firsts if HEXISH.match(f) or B32ISH.match(f) or B64ISH.match(f)) / len(firsts)
        span = max(q.ts for q in qs) - min(q.ts for q in qs)
        qps = len(qs) / span if span > 0 else float(len(qs))
        fan = uniq / len(labels)
        score, why = 0.0, []
        if mlen >= 30:
            score += 25; why.append(f"very long subdomains (mean {mlen:.0f} characters)")
        elif mlen >= 18:
            score += 14; why.append(f"long subdomains (mean {mlen:.0f} characters)")
        if ment >= 3.6:
            score += 25; why.append(f"high-entropy labels ({ment:.1f} bits per character)")
        elif ment >= 3.2:
            score += 12; why.append(f"elevated label entropy ({ment:.1f})")
        if fan >= 0.9 and uniq >= min_queries:
            score += 20; why.append(f"almost every query is a new name ({uniq} unique)")
        if enc >= 0.6:
            score += 15; why.append(f"{enc:.0%} of labels look hex, base32 or base64 encoded")
        if tn >= 0.5:
            score += 10; why.append(f"{tn:.0%} of queries are TXT, NULL, CNAME or MX")
        if qps >= 1:
            score += 5; why.append(f"sustained rate of {qps:.1f} queries per second")
        nx = sum(1 for q in qs if q.rcode == "NXDOMAIN") / len(qs)
        if nx >= 0.8 and fan >= 0.9:
            why.append(f"{nx:.0%} NXDOMAIN with random-looking names: consistent with a domain generation algorithm")
            score += 30
        if score >= min_score:
            out.append(Finding(client, dom, len(qs), uniq, mlen, ment, tn, enc, qps, min(100, int(score)), why))
    # DGA: many distinct, random-looking second-level names, mostly NXDOMAIN, from one client
    byc: dict[str, list[Query]] = defaultdict(list)
    for q in queries:
        if q.rcode == "NXDOMAIN" and registered_domain(q.qname) not in allow:
            byc[q.client].append(q)
    for client, qs in byc.items():
        slds = [registered_domain(q.qname).split(".")[0] for q in qs]
        if len(qs) < min_queries:
            continue
        uniq = len(set(slds)) / len(slds)
        ment = sum(entropy(x) for x in slds) / len(slds)
        mlen = sum(len(x) for x in slds) / len(slds)
        if uniq >= 0.9 and ment >= 3.0 and mlen >= 10:
            span = max(q.ts for q in qs) - min(q.ts for q in qs)
            score = min(100, int(40 + 10 * min(ment - 3.0, 1.5) * 2 + min(len(qs), 100) / 5))
            if score >= min_score:
                out.append(Finding(client, "(many random domains)", len(qs), len(set(slds)), mlen, ment, 0.0, 0.0, len(qs) / span if span else float(len(qs)),
                                   score, [f"{len(qs)} NXDOMAIN answers for {len(set(slds))} different random-looking names ({ment:.1f} bits per character)", "consistent with a domain generation algorithm searching for its command server"]))
    return sorted(out, key=lambda f: (-f.score, f.domain))


def text(fs: list[Finding]) -> str:
    if not fs:
        return "No DNS tunneling candidates above the threshold.\n"
    L = []
    for f in fs:
        L.append(f"{f.score:>3}  {f.client} -> {f.domain}  ({f.queries} queries, {f.unique_subdomains} unique names)")
        L += [f"       - {r}" for r in f.reasons]
    return "\n".join(L) + "\n"


def as_json(fs: list[Finding]) -> str:
    return json.dumps([f.__dict__ for f in fs], indent=2) + "\n"


def page(fs: list[Finding], total: int) -> str:
    rows = "".join(f"<tr><td class=\"{'bad' if f.score >= 85 else 'warn'}\">{f.score}</td><td>{html.escape(f.client)}</td><td>{html.escape(f.domain)}</td><td>{f.queries}</td><td>{html.escape('; '.join(f.reasons))}</td></tr>" for f in fs)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>dns-exfil-hunter</title><style>:root{{color-scheme:dark}}body{{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}}h1{{margin:0 0 4px}}.sub{{color:#8b98a8}}table{{border-collapse:collapse;width:100%;margin-top:14px}}th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}}th{{color:#8b98a8}}td.bad{{color:#f85149;font-weight:700}}td.warn{{color:#e3b341;font-weight:700}}</style></head><body><h1>dns-exfil-hunter</h1><p class="sub">DNS tunneling and exfiltration detection from query logs. Python, standard library only. Synthetic data, {total} queries.</p><table><tr><th>Score</th><th>Client</th><th>Domain</th><th>Queries</th><th>Why</th></tr>{rows}</table><p class="sub">Candidates, not verdicts: CDNs, anti-virus lookups and some mail security products also generate long encoded names. Allowlist them and triage the rest.</p></body></html>
"""

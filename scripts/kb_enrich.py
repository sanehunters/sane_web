#!/usr/bin/env python3
"""Enrich the most valuable reports of each class with severity, status, asset type and a short summary.

Reads kb/data/index.jsonl, fetches HexBrain's open per-report JSON (https://hexbrainai.com/report/<id>.json,
no key needed) for the top N reports of every class, and appends to kb/data/enrich.jsonl. Resumable: ids already
in enrich.jsonl are skipped. Polite by design: one request at a time, --rps requests per second (default 1.5).
Run scripts/kb_build.py afterwards to merge the fields into the listings.

Report text is third-party content. Only short metadata and a truncated summary are stored here.
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(ROOT, "kb", "data", "index.jsonl")
OUT = os.path.join(ROOT, "kb", "data", "enrich.jsonl")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=50, help="reports per class")
    ap.add_argument("--rps", type=float, default=1.5)
    ap.add_argument("--classes", default="", help="comma-separated class slugs (default: all)")
    a = ap.parse_args()
    done = set()
    if os.path.exists(OUT):
        for line in open(OUT, encoding="utf-8"):
            try:
                done.add(int(json.loads(line)["id"]))
            except Exception:
                pass
    by = defaultdict(list)
    for line in open(IDX, encoding="utf-8"):
        r = json.loads(line)
        by[r["class"]].append(r["id"])  # index.jsonl is already sorted most valuable first
    want = []
    only = {c for c in a.classes.split(",") if c}
    for c, ids in by.items():
        if only and c not in only:
            continue
        want += ids[: a.top]
    want = [i for i in dict.fromkeys(want) if i not in done]
    print(f"{len(want)} to fetch, {len(done)} already stored", flush=True)
    delay = 1.0 / a.rps
    n = fail = 0
    with open(OUT, "a", encoding="utf-8") as out:
        for rid in want:
            t0 = time.time()
            try:
                req = urllib.request.Request(f"https://hexbrainai.com/report/{rid}.json",
                                             headers={"User-Agent": "sane-web-kb/1.0 (report index enrichment)"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    d = json.load(resp)
                rec = {"id": rid}
                for k in ("severity", "status", "asset", "asset_type", "weakness", "vuln_class", "reporter"):
                    if d.get(k):
                        rec[k] = d[k]
                for k in ("submitted_at", "disclosed_at"):
                    if d.get(k):
                        rec[k] = d[k][:10]
                if d.get("summary"):
                    rec["summary"] = " ".join(d["summary"].split())[:400]
                rec["has_writeup"] = bool(d.get("writeup"))
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out.flush()
                n += 1
            except urllib.error.HTTPError as e:
                fail += 1
                if e.code == 429:
                    wait = int(e.headers.get("Retry-After", "30"))
                    print(f"429, sleeping {wait}s", flush=True)
                    time.sleep(wait)
                elif e.code == 404:
                    out.write(json.dumps({"id": rid, "missing": True}) + "\n")
            except Exception as e:
                fail += 1
                print(f"{rid}: {e}", flush=True)
            if n and n % 100 == 0:
                print(f"{n} fetched, {fail} failed", flush=True)
            dt = time.time() - t0
            if dt < delay:
                time.sleep(delay - dt)
    print(f"done: {n} fetched, {fail} failed", flush=True)


if __name__ == "__main__":
    main()

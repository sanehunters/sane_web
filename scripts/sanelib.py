"""Shared library for sane_web: paths, engagement state, scope matching, the checklist parser and the
three-valued applicability evaluator. Standard library only."""
import csv, fnmatch, ipaddress, json, os, re, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKLIST = os.path.join(ROOT, "checklist")
KB = os.path.join(ROOT, "kb")
ENG_ROOT = os.environ.get("SANE_ENGAGEMENT_ROOT") or os.path.join(ROOT, "engagements")

UNITS = ("deployment", "host", "programme")
COSTS = {"low": 1.0, "medium": 2.5, "high": 6.0}
# minutes before an item must be called off or explicitly extended (see playbooks/README.md)
TIMEBOX = {"low": 20, "medium": 45, "high": 120}
SEV = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "none": 0.6}
HAND_STATUSES = ("negative", "candidate", "finding", "parked", "dup-risk", "skipped")
AUTO_STATUSES = ("todo", "n/a", "blocked", "excluded", "probe")
META_ROWS = ("Severity", "Requires", "Excluded by", "Unit", "Cost", "Weakness", "Prior art")
BODY_FIELDS = ("Where", "Test", "How", "Proof", "Not a finding when", "Escalate")
CHAPTER_ROWS = ("Class", "Applies when", "Pays", "Weaknesses")
CHAPTER_SECTIONS = ("Why it pays", "The crux question", "Applicability probe", "Triage order", "Items",
                    "Graveyard", "Chains", "Sources")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------- registry and expressions

_registry = None


def registry():
    global _registry
    if _registry is None:
        _registry = read_json(os.path.join(CHECKLIST, "_facts.json"))
    return _registry


def fact_defs():
    return registry()["facts"]


def exclusion_tags():
    return {k for k in registry()["exclusions"] if not k.startswith("_")}


TAG = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def parse_expr(s):
    """'a, b|c, !d' -> [[(False,'a')], [(False,'b'),(False,'c')], [(True,'d')]]  (AND of ORs). Raises ValueError."""
    s = (s or "").replace("\\|", "|").replace("`", "").strip()
    if s in ("", "—", "-", "–", "always"):
        return []
    out = []
    for part in s.split(","):
        ors = []
        for t in part.split("|"):
            t = t.strip()
            neg = t.startswith("!")
            t = t[1:].strip() if neg else t
            if not TAG.match(t):
                raise ValueError(f"bad tag {t!r} in expression {s!r}")
            ors.append((neg, t))
        out.append(ors)
    return out


def expr_tags(expr):
    return {t for ors in expr for _, t in ors}


def eval_expr(expr, facts):
    """Three-valued. Returns (value, tags): value True/False/None; tags = the false tags that decided a False,
    or the unknown tags that keep it None."""
    false_tags, unknown_tags = [], []
    result = True
    for ors in expr:
        vals = []
        for neg, t in ors:
            v = facts.get(t)
            vals.append((None if v is None else (not v if neg else v), t, neg))
        if any(v is True for v, _, _ in vals):
            continue
        if any(v is None for v, _, _ in vals):
            unknown_tags += [t for v, t, _ in vals if v is None]
            if result is True:
                result = None
        else:
            false_tags += [("!" + t if neg else t) for _, t, neg in vals]
            result = False
    if result is False:
        return False, false_tags
    if result is None:
        return None, sorted(set(unknown_tags))
    return True, []


def resolve_facts(raw):
    """Apply the registry's 'needs' implications: a fact whose prerequisite is false is false without a probe.
    raw: tag -> True/False/None. Returns (facts, derived) where derived maps tag -> the prerequisite that failed."""
    defs = fact_defs()
    facts = {t: raw.get(t) for t in defs}
    derived = {}
    for _ in range(6):
        changed = False
        for t, d in defs.items():
            if facts.get(t) is not None or not d.get("needs"):
                continue
            v, why = eval_expr(parse_expr(d["needs"]), facts)
            if v is False:
                facts[t] = False
                derived[t] = d["needs"]
                changed = True
        if not changed:
            break
    return facts, derived


# ---------------------------------------------------------------- checklist parser

H_ITEM = re.compile(r"^###\s+([A-Z]{3})-(\d{3})\s*[·\-]\s*(.+?)\s*$")
H_ANY3 = re.compile(r"^###\s+")
ROW = re.compile(r"^\|\s*\*\*(.+?)\*\*\s*\|\s*(.*?)\s*\|\s*$")
FIELD = re.compile(r"^- \*\*(.+?):\*\*\s*(.*)$")
PRIOR = re.compile(r"#(\d{3,8})")


def classes():
    return read_json(os.path.join(KB, "classes.json"))["classes"]


def parse_chapter(path):
    slug = os.path.basename(path)[:-3]
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    ch = {"slug": slug, "path": path, "errors": [], "warnings": [], "items": [], "meta": {}, "sections": []}
    m = re.match(r"^#\s+([A-Z]{3})\s*·\s*(.+)$", lines[0] if lines else "")
    if not m:
        ch["errors"].append("first line must be '# PFX · Class name'")
        ch["prefix"], ch["title"] = "???", slug
    else:
        ch["prefix"], ch["title"] = m.group(1), m.group(2).strip()
    section = None
    item = None
    field = None
    in_code = False
    for ln in lines[1:]:
        if ln.strip().startswith("```"):
            in_code = not in_code
        if not in_code and ln.startswith("## "):
            section = ln[3:].strip()
            ch["sections"].append(section)
            item = None
            field = None
            continue
        if section != "Items":
            if section is None:
                r = ROW.match(ln)
                if r:
                    ch["meta"][r.group(1).strip()] = r.group(2).strip()
            continue
        if not in_code and H_ANY3.match(ln):
            hm = H_ITEM.match(ln)
            if not hm:
                ch["errors"].append(f"unparseable item heading: {ln.strip()[:80]}")
                item = None
                continue
            item = {"id": f"{hm.group(1)}-{hm.group(2)}", "n": int(hm.group(2)), "pfx": hm.group(1),
                    "title": hm.group(3), "meta": {}, "fields": {}, "chapter": slug}
            ch["items"].append(item)
            field = None
            continue
        if item is None:
            continue
        if not in_code:
            r = ROW.match(ln)
            if r and field is None:
                item["meta"][r.group(1).strip()] = r.group(2).strip()
                continue
            f = FIELD.match(ln)
            if f:
                field = f.group(1).strip()
                item["fields"][field] = f.group(2)
                continue
        if field:
            item["fields"][field] += "\n" + ln
    # normalise
    try:
        ch["applies"] = parse_expr(ch["meta"].get("Applies when", ""))
    except ValueError as e:
        ch["errors"].append(str(e))
        ch["applies"] = []
    for it in ch["items"]:
        try:
            it["requires"] = parse_expr(it["meta"].get("Requires", ""))
        except ValueError as e:
            ch["errors"].append(f"{it['id']}: {e}")
            it["requires"] = []
        ex = it["meta"].get("Excluded by", "").replace("`", "")
        it["excluded_by"] = [] if ex.strip() in ("", "—", "-", "–") else [x.strip() for x in ex.split(",")]
        it["unit"] = it["meta"].get("Unit", "deployment").strip().lower()
        it["cost"] = it["meta"].get("Cost", "medium").strip().lower()
        it["prior"] = [int(x) for x in PRIOR.findall(it["meta"].get("Prior art", ""))]
        sev = it["meta"].get("Severity", "")
        levels = [w for w in re.findall(r"[a-z]+", sev.lower()) if w in SEV]
        it["sev_floor"] = levels[0] if levels else "none"
        it["sev_ceiling"] = max(levels, key=lambda w: SEV[w]) if levels else "none"
        it["expr"] = ch["applies"] + it["requires"]
        for k in list(it["fields"]):
            it["fields"][k] = it["fields"][k].strip()
    return ch


def load_checklist():
    """All chapters, parsed. Returns (chapters, items_by_id)."""
    chapters, items = [], {}
    for fn in sorted(os.listdir(CHECKLIST)):
        if fn.endswith(".md") and not fn.startswith(("_", "README")):
            ch = parse_chapter(os.path.join(CHECKLIST, fn))
            chapters.append(ch)
            for it in ch["items"]:
                items[it["id"]] = it
    return chapters, items


_kb_ids = None


def kb_ids():
    global _kb_ids
    if _kb_ids is None:
        _kb_ids = set()
        p = os.path.join(KB, "data", "index.jsonl")
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                m = re.match(r'\{"id": (\d+)', line)
                if m:
                    _kb_ids.add(int(m.group(1)))
    return _kb_ids


def lint_chapter(ch):
    """Returns (errors, warnings)."""
    err, warn = list(ch["errors"]), list(ch["warnings"])
    by_slug = {c["slug"]: c for c in classes()}
    c = by_slug.get(ch["slug"])
    defs, excl = fact_defs(), exclusion_tags()
    if not c:
        err.append(f"file name {ch['slug']}.md is not a class slug in kb/classes.json")
    else:
        if ch.get("prefix") != c["prefix"]:
            err.append(f"prefix {ch.get('prefix')} should be {c['prefix']}")
        cls = ch["meta"].get("Class", "").replace("`", "").strip()
        if cls != ch["slug"]:
            err.append(f"Class row {cls!r} should be `{ch['slug']}`")
    for r in CHAPTER_ROWS:
        if not ch["meta"].get(r):
            err.append(f"chapter metadata row missing: {r}")
    for s in CHAPTER_SECTIONS:
        if s not in ch["sections"]:
            err.append(f"section missing: ## {s}")
    for t in expr_tags(ch.get("applies", [])):
        if t not in defs:
            err.append(f"Applies when: unknown tag {t!r}")
    if not ch["items"]:
        err.append("no items")
    for i, it in enumerate(ch["items"], 1):
        iid = it["id"]
        if c and it["pfx"] != c["prefix"]:
            err.append(f"{iid}: prefix should be {c['prefix']}")
        if it["n"] != i:
            err.append(f"{iid}: items must be numbered contiguously (expected {i:03d})")
        for r in META_ROWS:
            if not it["meta"].get(r):
                err.append(f"{iid}: metadata row missing or empty: {r}")
        for f in BODY_FIELDS:
            if not it["fields"].get(f):
                err.append(f"{iid}: body field missing or empty: {f}")
        for t in expr_tags(it["requires"]):
            if t not in defs:
                err.append(f"{iid}: Requires: unknown tag {t!r} (tags come from checklist/_facts.json)")
        for x in it["excluded_by"]:
            if x not in excl:
                err.append(f"{iid}: Excluded by: unknown exclusion tag {x!r}")
        if it["unit"] not in UNITS:
            err.append(f"{iid}: Unit must be one of {UNITS}")
        if it["cost"] not in COSTS:
            err.append(f"{iid}: Cost must be one of {tuple(COSTS)}")
        sev = it["meta"].get("Severity", "")
        if sev and not re.match(r"^(critical|high|medium|low|none)\b", sev.strip().lower()):
            err.append(f"{iid}: Severity must start with critical|high|medium|low|none")
        if not it["prior"]:
            warn.append(f"{iid}: no prior art cited")
        ids = kb_ids()
        for p in it["prior"]:
            if ids and p not in ids:
                err.append(f"{iid}: prior art #{p} is not in kb/data/index.jsonl")
        how = it["fields"].get("How", "")
        if how and "`" not in how:
            warn.append(f"{iid}: How has no command, request or payload in code formatting")
        if not it["requires"] and not ch.get("applies"):
            warn.append(f"{iid}: no gate at all (neither chapter nor item)")
        if len(it["title"]) < 25:
            warn.append(f"{iid}: title should be a claim, not a topic")
    for m in re.findall(r"\b([A-Z]{3})-(\d{3})\b", ch["meta"].get("_triage", "")):
        pass
    return err, warn


# ---------------------------------------------------------------- scope

def norm_host(h):
    h = (h or "").strip().lower().rstrip(".")
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0].split("?")[0].split("#")[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if h.startswith("["):
        return h[1:].split("]")[0]
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h


def as_ip(h):
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def _rule_match(rule, host, ip):
    t, v = rule.get("type", "domain"), rule.get("value", "").strip().lower()
    if t in ("cidr", "ip"):
        if ip is None:
            return False
        try:
            return ip in ipaddress.ip_network(v, strict=False)
        except ValueError:
            return False
    if ip is not None:
        return False
    v = norm_host(v) if t == "url" else v.rstrip(".")
    if "*" in v:
        # '*.example.com' matches any depth of subdomain and not the apex; other wildcards are globbed per label run
        return fnmatch.fnmatchcase(host, v)
    return host == v


def scope_verdict(target, scope):
    """('in'|'out'|'unknown', rule). Out-of-scope rules always win over in-scope rules."""
    host = norm_host(target)
    ip = as_ip(host)
    for r in scope.get("out", []):
        if _rule_match(r, host, ip):
            return "out", r
    for r in scope.get("in", []):
        if _rule_match(r, host, ip):
            return "in", r
    return "unknown", None


# ---------------------------------------------------------------- engagements

def list_engagements():
    if not os.path.isdir(ENG_ROOT):
        return []
    out = []
    for d in sorted(os.listdir(ENG_ROOT)):
        p = os.path.join(ENG_ROOT, d)
        if os.path.isfile(os.path.join(p, "engagement.json")):
            out.append(d)
    return out


def active_engagement():
    """Name of the active engagement or None. Order: $SANE_ENGAGEMENT, engagements/.active, the only one, the newest."""
    env = os.environ.get("SANE_ENGAGEMENT")
    names = list_engagements()
    if env:
        env = os.path.basename(env.rstrip("/"))
        return env if env in names else None
    try:
        a = open(os.path.join(ENG_ROOT, ".active"), encoding="utf-8").read().strip()
        if a in names:
            return a
    except FileNotFoundError:
        pass
    if not names:
        return None
    return max(names, key=lambda n: os.path.getmtime(os.path.join(ENG_ROOT, n, "engagement.json")))


class Engagement:
    def __init__(self, name):
        self.name = name
        self.dir = os.path.join(ENG_ROOT, name)
        self.meta = read_json(self.p("engagement.json"), {})
        self.scope = read_json(self.p("scope.json"), {"in": [], "out": []})

    def p(self, *parts):
        return os.path.join(self.dir, *parts)

    def save(self):
        write_json(self.p("engagement.json"), self.meta)
        write_json(self.p("scope.json"), self.scope)

    # assets: one JSON object per host in assets.json {host: {...}}
    def assets(self):
        return read_json(self.p("assets.json"), {})

    def save_assets(self, a):
        write_json(self.p("assets.json"), a)

    def raw_facts(self, host):
        return read_json(self.p("facts", host + ".json"), {})

    def set_fact(self, host, tag, value, ev, by="manual"):
        f = self.raw_facts(host)
        f[tag] = {"v": value, "ev": ev, "by": by, "at": now()}
        write_json(self.p("facts", host + ".json"), f)

    def facts(self, host):
        """Resolved facts for one asset: engagement-level facts, overlaid by the asset's own, then implications."""
        raw = {}
        ev = {}
        for src in (self.meta.get("facts", {}), self.raw_facts(host)):
            for t, rec in src.items():
                if isinstance(rec, dict):
                    raw[t], ev[t] = rec.get("v"), rec.get("ev", "")
                else:
                    raw[t], ev[t] = rec, ""
        facts, derived = resolve_facts(raw)
        for t, need in derived.items():
            ev[t] = f"implied: needs {need}"
        return facts, ev

    def coverage(self):
        rows = {}
        p = self.p("coverage.csv")
        if os.path.exists(p):
            with open(p, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    rows[(r["asset"], r["item"])] = r
        return rows

    def save_coverage(self, rows):
        p = self.p("coverage.csv")
        cols = ["asset", "item", "status", "note", "evidence", "started", "updated"]
        with open(p + ".tmp", "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for k in sorted(rows):
                w.writerow({c: rows[k].get(c, "") for c in cols})
        os.replace(p + ".tmp", p)

    def log(self, kind, **kw):
        os.makedirs(self.p("logs"), exist_ok=True)
        with open(self.p("logs", "journal.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": now(), "kind": kind, **kw}, ensure_ascii=False) + "\n")


def current(required=True):
    n = active_engagement()
    if not n:
        if required:
            raise SystemExit("no engagement: run  scripts/sane new <programme>  (see /engage)")
        return None
    return Engagement(n)

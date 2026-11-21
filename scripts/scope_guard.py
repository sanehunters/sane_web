#!/usr/bin/env python3
"""PreToolUse guard for Bash and WebFetch. Reads the hook JSON on stdin; exit 2 blocks the call and the text on
stderr is shown to the model.

What it enforces, in order:
  1. never a network tool against a host the programme lists as out of scope, or one seen in recon and not in scope
  2. scanners, fuzzers and non-GET requests only against hosts that are in scope (unknown hosts are refused)
  3. no engagement, no active testing
  4. destructive or forbidden modes: OS shells, bulk dumps, brute forcers, load generators, DoS scripts
  5. scanners carry a rate limit at or below the programme's, and nuclei is never run with its whole template set
  6. requests to the target carry the headers the programme requires
Everything it decides about a network command is appended to <engagement>/logs/audit.jsonl.

It is a seatbelt, not a proof: a script can still open a socket the guard cannot see. CLAUDE.md carries the rule;
this catches the slips."""
import ipaddress, json, os, re, shlex, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanelib as L  # noqa: E402

SCANNERS = ["nuclei", "httpx", "ffuf", "gobuster", "feroxbuster", "dirsearch", "dirb", "wfuzz", "nmap", "naabu", "masscan",
            "rustscan", "sqlmap", "ghauri", "dalfox", "xsstrike", "katana", "gospider", "hakrawler", "nikto", "wpscan",
            "whatweb", "wafw00f", "arjun", "x8", "commix", "tplmap", "sstimap", "smuggler", "h2csmuggler", "testssl", "testssl.sh",
            "sslscan", "sslyze", "kr", "kiterunner", "dnsx", "puredns", "shuffledns", "massdns", "gowitness", "aquatone",
            "subjack", "subzy", "websocat", "nc", "ncat", "netcat", "telnet", "jwt_tool", "graphw00f", "clairvoyance",
            "inql", "crlfuzz", "corsy", "trufflehog", "gitleaks"]
FETCHERS = ["curl", "wget", "http", "https", "xh"]
BRUTE = ["hydra", "medusa", "patator", "ncrack", "crowbar", "kerbrute"]
LOAD = ["slowloris", "slowhttptest", "hping3", "goldeneye", "hulk", "thc-ssl-dos", "siege", "wrk", "wrk2", "vegeta",
        "bombardier", "ab", "loic", "torshammer", "t50", "hey", "k6", "locust"]
RATE_FLAGS = {  # tool -> (regexes that set a limit, hint, multiplier allowed over the programme rps)
    "ffuf": ([r"-rate[ =]+(\d+)"], "-rate $RATE", 1), "nuclei": ([r"-(?:rl|rate-limit)[ =]+(\d+)"], "-rl $RATE", 1),
    "httpx": ([r"-(?:rl|rate-limit)[ =]+(\d+)"], "-rl $RATE", 2), "katana": ([r"-(?:rl|rate-limit)[ =]+(\d+)"], "-rl $RATE", 1),
    "naabu": ([r"-rate[ =]+(\d+)"], "-rate $((RATE*10))", 10), "masscan": ([r"--(?:max-)?rate[ =]+(\d+)"], "--rate $((RATE*10))", 10),
    "nmap": ([r"--max-rate[ =]+(\d+)", r"-T([0-3])\b"], "--max-rate $((RATE*10)) or -T3", 10),
    "feroxbuster": ([r"--rate-limit[ =]+(\d+)"], "--rate-limit $RATE", 1), "gobuster": ([r"--delay[ =]+\S+"], "--delay 200ms", 0),
    "sqlmap": ([r"--delay[ =]+[\d.]+"], "--delay 0.5", 0), "ghauri": ([r"--delay[ =]+[\d.]+"], "--delay 0.5", 0),
    "dalfox": ([r"--delay[ =]+\d+"], "--delay 200", 0), "wfuzz": ([r"-s[ =]+[\d.]+"], "-s 0.2", 0),
    "dirsearch": ([r"--max-rate[ =]+(\d+)", r"--delay[ =]+[\d.]+"], "--max-rate $RATE", 1),
    "wpscan": ([r"--throttle[ =]+\d+"], "--throttle 250", 0), "arjun": ([r"--rate-limit[ =]+(\d+)", r"-d[ =]+[\d.]+"], "--rate-limit $RATE", 1),
    "rustscan": ([r"--(?:batch-size|b)[ =]+(\d+)", r"\s-b[ =]+(\d+)"], "-b 100", 100), "nikto": ([r"-Pause[ =]+\d+"], "-Pause 1", 0),
    "kr": ([r"--delay[ =]+\S+", r"-x[ =]+(\d+)"], "--delay 200ms", 0),
}
FORBIDDEN = [
    (r"\bsqlmap\b.*--(os-shell|os-pwn|os-cmd|os-smbrelay|os-bof|sql-shell|dump-all|file-write|priv-esc|reg-add|reg-del)\b",
     "sqlmap shell, bulk-dump, file-write and privilege-escalation modes are never needed for a report: prove with the DBMS version and current user"),
    (r"\bsqlmap\b.*--risk[ =]+3", "sqlmap --risk 3 uses OR-based payloads that can modify data (UPDATE/DELETE statements): stay at risk 1-2"),
    (r"\bnmap\b.*--script[ =]+\S*(dos|brute|intrusive|broadcast|fuzzer)", "nmap dos/brute/intrusive script categories are outside programme rules"),
    (r"\bnuclei\b.*-(?:tags|itags)[ =]+\S*\b(dos|bruteforce|intrusive)\b", "nuclei dos/bruteforce/intrusive tags are outside programme rules"),
    (r"\b(commix|tplmap|sstimap)\b.*--(os-shell|reverse-shell|bind-shell|os-cmd)", "interactive shells are never part of a proof: run one harmless command and stop"),
    (r"\bmsfconsole\b|\bmsfvenom\b.*(meterpreter|reverse_|bind_)", "reverse shells and meterpreter payloads are not a proof of concept a programme accepts: prove with a single harmless command"),
    (r"\b(wpscan)\b.*(--passwords|-P\b)", "wpscan password attacks are brute forcing"),
]
INFRA_DEFAULT = """localhost
github.com api.github.com raw.githubusercontent.com gist.githubusercontent.com objects.githubusercontent.com codeload.github.com
gitlab.com bitbucket.org
hackerone.com api.hackerone.com hackerone-us-west-2-production-attachments.s3.us-west-2.amazonaws.com
hexbrainai.com crt.sh web.archive.org archive.org index.commoncrawl.org
services.nvd.nist.gov nvd.nist.gov cve.org cveawg.mitre.org www.cisa.gov api.first.org api.osv.dev osv.dev
pypi.org files.pythonhosted.org registry.npmjs.org proxy.golang.org sum.golang.org go.dev golang.org rubygems.org crates.io static.crates.io
dns.google cloudflare-dns.com one.one.one.one
otx.alienvault.com urlscan.io api.securitytrails.com api.shodan.io www.shodan.io search.censys.io chaos.projectdiscovery.io
dns.projectdiscovery.io api.projectdiscovery.io rapiddns.io api.certspotter.com www.virustotal.com api.hackertarget.com
oast.fun oast.pro oast.live oast.site oast.online oast.me interact.sh interactsh.com rbndr.us 1u.ms nip.io sslip.io localtest.me
portswigger.net owasp.org cheatsheetseries.owasp.org book.hacktricks.xyz exploit-db.com www.exploit-db.com
docs.projectdiscovery.io nuclei.projectdiscovery.io anthropic.com docs.anthropic.com claude.com code.claude.com
sts.amazonaws.com
"""
FILE_EXT = set("""md json jsonl py sh txt js mjs cjs ts tsx jsx csv tsv html htm css log yaml yml xml zip gz tgz tar bz2 xz 7z png jpg jpeg gif svg
webp ico pdf conf cfg ini toml lock go rs php rb java class jar war c h cpp hpp out err tmp bak old orig db sqlite sql pem key crt cer
der p12 pfx har pcap bin dat map min exe dll so dylib deb rpm apk ipa doc docx xls xlsx ppt pptx mp4 mp3 wav avi mov m3u8 ts lst list
env tpl template j2 proto graphql gql wasm ttf woff woff2 eot nse yar rules headers http req resp body diff patch""".split())
URL_RE = re.compile(r"\b(?:https?|wss?|ftp|gopher|ldaps?|dict|tftp|sftp|smb)://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._~%\-@:]+)", re.I)
HOST_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+([a-z]{2,24})$", re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
VAR_HOST = re.compile(r"\$\{?[A-Za-z_]")


def has_tool(cmd, names):
    found = []
    for n in names:
        if re.search(r"(?:^|[\s;&|(`]|\$\()(?:sudo\s+|time\s+|timeout\s+\S+\s+|proxychains4?\s+|xargs\s+(?:-\S+\s+)*)?(?:\S*/)?" + re.escape(n) + r"(?=\s|$)", cmd):
            found.append(n)
    return found


def infra_hosts(eng):
    hosts = set(INFRA_DEFAULT.split())
    for p in ([os.path.join(L.ROOT, "scripts", "allow-infra.txt")] + ([eng.p("allow-infra.txt")] if eng else [])):
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                line = line.split("#")[0].strip()
                if line:
                    hosts.update(line.split())
    if eng and eng.meta.get("oob_host"):
        hosts.add(eng.meta["oob_host"].lower())
    return hosts


def is_infra(host, infra):
    if host in infra:
        return True
    return any(host.endswith("." + h) for h in infra)


def is_local(host):
    ip = L.as_ip(host)
    if ip:
        return ip.is_loopback or ip.is_unspecified
    return host in ("localhost",) or host.endswith(".localhost")


def targets_in(cmd, scanner_present):
    """Hosts, IPs and CIDRs the command names. Returns (set of targets, list files to check)."""
    out = set()
    for m in URL_RE.finditer(cmd):
        h = L.norm_host(m.group(0))
        if h and not VAR_HOST.search(m.group(1)):
            out.add(h)
    try:
        toks = shlex.split(cmd, comments=False, posix=True)
    except ValueError:
        toks = cmd.split()
    lists = []
    for i, t in enumerate(toks):
        if t in ("-l", "-list", "-iL", "--list", "-L", "--input-file", "--targets", "-targets") and i + 1 < len(toks):
            lists.append(toks[i + 1])
        if t in ("cat", "<") and i + 1 < len(toks) and scanner_present:
            lists.append(toks[i + 1])
        t0 = t.strip("'\"`,;()[]{}<>")
        if "://" in t0 or "=" in t0 and not IP_RE.match(t0.split("=")[-1]):
            t0 = t0.split("=")[-1] if "=" in t0 and "://" not in t0 else t0
        cand = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", t0, flags=re.I)
        cand = cand.split("/")[0] if not IP_RE.match(cand) else cand
        cand = cand.rsplit("@", 1)[-1]
        cand = re.sub(r":\d{1,5}$", "", cand).lower().rstrip(".")
        if IP_RE.match(cand):
            try:
                ipaddress.ip_network(cand, strict=False)
                out.add(cand)
            except ValueError:
                pass
            continue
        m = HOST_RE.match(cand)
        if not m or m.group(1).lower() in FILE_EXT:
            continue
        if os.path.exists(t0) or os.path.exists(t):
            continue
        if "/" in t0 or scanner_present or "://" in t:
            out.add(cand)
        elif re.search(r"(?:^|\s)(?:curl|wget|http|https|xh|dig|host|nslookup|whois|openssl|ssh|ping|traceroute)\s", cmd) and t0 == t.strip("'\""):
            out.add(cand)
    return out, lists


def verdict_for(t, eng, infra, assets):
    """in | out | infra | local | unknown | known-not-in-scope"""
    if "/" in t:  # CIDR literal: every address must be in scope
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return "unknown"
        if net.is_loopback:
            return "local"
        if not eng:
            return "unknown"
        for r in eng.scope.get("in", []):
            if r["type"] in ("cidr", "ip"):
                try:
                    if net.subnet_of(ipaddress.ip_network(r["value"], strict=False)):
                        return "in"
                except (ValueError, TypeError):
                    pass
        return "unknown"
    if is_local(t):
        return "local"
    if eng:
        v, _ = L.scope_verdict(t, eng.scope)
        if v in ("in", "out"):
            return v
    if is_infra(t, infra):
        return "infra"
    if assets.get(t) and not assets[t].get("in_scope"):
        return "known-not-in-scope"
    return "unknown"


def block(msg, eng=None, record=None):
    if eng and record is not None:
        audit(eng, dict(record, decision="block", reason=msg.split("\n")[0]))
    sys.stderr.write("SCOPE GUARD — blocked.\n" + msg + "\n")
    sys.exit(2)


def audit(eng, rec):
    try:
        os.makedirs(eng.p("logs"), exist_ok=True)
        with open(eng.p("logs", "audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(dict(rec, at=L.now()), ensure_ascii=False) + "\n")
    except OSError:
        pass


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}
    try:
        eng = L.current(required=False)
    except SystemExit:
        eng = None
    infra = infra_hosts(eng)
    assets = eng.assets() if eng else {}

    if tool in ("WebFetch", "WebSearch"):
        url = ti.get("url", "")
        if url:
            v = verdict_for(L.norm_host(url), eng, infra, assets)
            if v in ("out", "known-not-in-scope"):
                block(f"{L.norm_host(url)} is {v.replace('-', ' ')} for the active engagement. Do not fetch it.")
        sys.exit(0)
    if tool != "Bash":
        sys.exit(0)
    cmd = ti.get("command", "")
    if not cmd.strip():
        sys.exit(0)

    scanners = has_tool(cmd, SCANNERS)
    fetchers = has_tool(cmd, FETCHERS)
    brute = has_tool(cmd, BRUTE)
    load = has_tool(cmd, LOAD)
    interp = bool(re.search(r"\b(python3?|node|ruby|perl|php|go run|bash -c|sh -c)\b", cmd)) and bool(URL_RE.search(cmd))
    if has_tool(cmd, ["msfconsole", "msfvenom"]):
        interp = True
    if not (scanners or fetchers or brute or load or interp):
        sys.exit(0)
    targets, lists = targets_in(cmd, bool(scanners or brute or load))
    rec = {"cmd": cmd[:2000], "tools": scanners + fetchers + brute + load, "targets": sorted(targets)}

    invoked = set(scanners + fetchers + brute + load + has_tool(cmd, ["msfconsole", "msfvenom"]))
    for rx, why in FORBIDDEN:
        m = re.search(rx, cmd, re.S)
        if m and (invoked & set(re.findall(r"[a-z0-9_.]+", rx.split(".*")[0].replace("\\b", "")))):
            block(why, eng, rec)
    verdicts = {t: verdict_for(t, eng, infra, assets) for t in targets}
    remote = [t for t, v in verdicts.items() if v not in ("local",)]
    rec["verdicts"] = verdicts

    if load and remote:
        block(f"{', '.join(load)} is a load generator. Availability testing is out of bounds on bug bounty programmes "
              "unless the policy says otherwise in writing. For a race condition use the single-packet technique in checklist/race.md.", eng, rec)
    if brute and remote:
        ok = bool(eng and (eng.meta.get("facts", {}).get("bruteforce-ok") or {}).get("v"))
        if not ok:
            block(f"{', '.join(brute)} is a credential brute forcer. Programmes forbid it unless the policy allows it; "
                  "if this one does, record it: scripts/sane fact set @eng bruteforce-ok=1 --ev '<the policy sentence>'", eng, rec)

    bad_out = sorted(t for t, v in verdicts.items() if v in ("out", "known-not-in-scope"))
    if bad_out:
        block("Out of scope: " + ", ".join(bad_out) + ".\nThe programme excludes these or they are not in its scope. Nothing is sent to them, not even a GET.\n"
              "Check any host with: scripts/sane scope check <host>", eng, rec)

    plain_get = bool(fetchers) and not scanners and not re.search(
        r"(?:\s-X\s*(?!GET\b)[A-Z]+|\s--request[ =](?!GET\b)|\s-d\b|\s--data|\s--json\b|\s-F\b|\s--form|\s-T\b|\s--upload-file|\s--post-(?:data|file)|\s--method[ =](?!GET\b)|\sPOST\s|\sPUT\s|\sDELETE\s|\sPATCH\s)", cmd)
    unknown = sorted(t for t, v in verdicts.items() if v == "unknown")
    if unknown and not eng and (scanners or not plain_get):
        block("No engagement is active, so nothing is in scope: " + ", ".join(unknown) + ".\n"
              "Start one first: scripts/sane new <programme> --handle <h1 handle>, then import the scope (playbook PB-00, PB-01).", eng, rec)
    if unknown and (scanners or interp or not plain_get):
        block("Not in scope: " + ", ".join(unknown) + ".\n"
              "Active tools and state-changing requests go only to hosts the scope lists. If the host is in the programme's scope, add the rule "
              "(scripts/sane scope add in <value>) citing the policy. If it is reference material or your own infrastructure, add it to "
              + (eng.p("allow-infra.txt") if eng else "scripts/allow-infra.txt") + ".", eng, rec)

    for lf in lists:
        if os.path.isfile(lf) and eng:
            bad, n = [], 0
            for line in open(lf, encoding="utf-8", errors="replace"):
                h = L.norm_host(line)
                if not h or n > 20000:
                    continue
                n += 1
                v = verdict_for(h, eng, infra, assets)
                if v not in ("in", "local"):
                    bad.append(h)
            if bad:
                block(f"{lf} contains {len(bad)} host(s) that are not in scope, e.g. {', '.join(bad[:5])}.\n"
                      f"Filter it first: scripts/sane scope filter < {lf} > {lf}.inscope", eng, rec)

    in_scope_hit = any(v == "in" for v in verdicts.values()) or bool(VAR_HOST.search(cmd) and (scanners or fetchers))
    if eng and in_scope_hit:
        if not eng.meta.get("authorisation", {}).get("confirmed") and any(v == "in" for v in verdicts.values()):
            block("Authorisation is not recorded for this engagement. Complete playbook PB-00 first:\n"
                  "  scripts/sane set authorised=yes basis='<invitation / policy accepted by ...>'", eng, rec)
        rate = float(eng.meta.get("rate_limit_rps", 5))
        for s in scanners:
            spec = RATE_FLAGS.get(s)
            if not spec:
                continue
            rxs, hint, mult = spec
            m = next((re.search(rx, cmd) for rx in rxs if re.search(rx, cmd)), None)
            if not m:
                block(f"{s} has no rate limit. The programme rate is {rate:g} requests/second: add {hint}.", eng, rec)
            if mult and m.groups() and m.group(1) and not (s == "nmap" and m.re.pattern.startswith("-T")):
                if float(m.group(1)) > rate * mult + 0.01:
                    block(f"{s} rate {m.group(1)} exceeds the engagement ceiling ({rate * mult:g}). Use {hint}.", eng, rec)
        if "nuclei" in scanners and not re.search(r"\s-(?:id|t|templates|tags|w|workflows|as|automatic-scan|template-id|tc|im)\b", cmd):
            block("nuclei without -id, -t or -tags runs every template against the target. Restrict it to what the fingerprint justifies:\n"
                  "  scripts/sane cve <host>   prints the matched CVE ids and the exact nuclei line.", eng, rec)
        need = eng.meta.get("required_headers", [])
        if need and (fetchers or set(scanners) & {"httpx", "nuclei", "ffuf", "katana", "sqlmap", "dalfox", "feroxbuster", "gobuster", "arjun", "wfuzz", "dirsearch"}):
            names = [h.split(":")[0].strip() for h in need]
            if not (re.search(r"HDR\[@\]|\$\{?HDRF\b", cmd) or all(n.lower() in cmd.lower() for n in names)):
                block("This programme requires the header(s) " + ", ".join(names) + " on every request.\n"
                      f'Start the command with  source "{eng.p("env.sh")}"  and pass  "${{HDR[@]}}"  to curl or  $HDRF  to httpx/nuclei/ffuf/katana.', eng, rec)
    if eng and (scanners or fetchers) and remote:
        audit(eng, dict(rec, decision="allow"))
    sys.exit(0)


if __name__ == "__main__":
    main()

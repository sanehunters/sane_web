#!/usr/bin/env python3
"""Adversarial cases for scripts/scope_guard.py. Builds a throwaway engagement, feeds the guard hook payloads and
checks each decision. Run directly, or through scripts/selftest.sh.

Scope used:  in  *.demo.example, 203.0.113.0/24      out  admin.demo.example      rate 10/s
"""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
S = [sys.executable, os.path.join(ROOT, "scripts", "sane")]
GUARD = [sys.executable, os.path.join(ROOT, "scripts", "scope_guard.py")]

# (expected, command, why)   expected: "allow" | "block"
CASES = [
    # --- hosts that are not in scope
    ("block", "curl -s -X POST https://evil.org/api -d a=1", "state-changing request to an unknown host"),
    ("block", "curl -s https://admin.demo.example/", "even a GET to an explicitly out-of-scope host"),
    ("block", "curl -s https://ADMIN.demo.example./login", "out-of-scope host, case and trailing dot"),
    ("block", "curl -s -X POST https://app.demo.example@evil.org/x", "userinfo trick: the real host is evil.org"),
    ("block", "wget --post-data a=1 http://evil.org/", "wget POST to an unknown host"),
    ("block", "T=https://evil.org; curl -s -X PUT $T/api/users/1", "target hidden in a variable assignment"),
    ("block", "python3 -c \"import requests; requests.post('https://evil.org/x', data={})\"", "inline script with an unknown URL"),
    ("block", "httpx -u https://evil.org -rl 5", "scanner on an unknown host"),
    ("block", "nmap --max-rate 50 -p 80,443 10.0.0.0/8", "CIDR that is not inside the scope"),
    ("block", "nmap --max-rate 50 198.51.100.7", "IP outside the in-scope range"),
    ("block", "echo admin.demo.example | httpx -rl 5", "out-of-scope host piped to a scanner"),
    ("block", "ffuf -u https://app.demo.example/FUZZ -w w.txt -rate 5 -H 'Host: admin.demo.example'", "out-of-scope virtual host through the Host header"),
    ("block", "curl -s https://app.demo.example/ -H 'Host: internal.evil.org' -X POST -d a=1", "unknown virtual host through the Host header"),
    # --- in scope, but the rules of engagement are not met
    ("block", "ffuf -u https://app.demo.example/FUZZ -w w.txt", "fuzzer without a rate limit"),
    ("block", "ffuf -u https://app.demo.example/FUZZ -w w.txt -rate 500", "fuzzer above the programme rate"),
    ("block", "nuclei -u https://app.demo.example -rl 5", "nuclei with its whole template set"),
    ("block", "nmap -sV app.demo.example", "port scanner without a rate"),
    ("block", "nmap -T4 app.demo.example", "port scanner at an aggressive timing template"),
    ("block", "sqlmap -u 'https://app.demo.example/?id=1' --batch", "sqlmap without a delay"),
    ("block", "sqlmap -u 'https://app.demo.example/?id=1' --delay 1 --os-shell", "sqlmap OS shell"),
    ("block", "sqlmap -u 'https://app.demo.example/?id=1' --delay 1 --dump-all", "sqlmap bulk dump"),
    ("block", "sqlmap -u 'https://app.demo.example/?id=1' --delay 1 --risk 3", "sqlmap risk 3"),
    ("block", "hydra -l admin -P rockyou.txt app.demo.example http-post-form", "credential brute forcer"),
    ("block", "wrk -t8 -c400 -d30s https://app.demo.example/", "load generator"),
    ("block", "nmap --max-rate 20 --script dos app.demo.example", "nmap dos scripts"),
    ("block", "nuclei -u https://app.demo.example -tags dos -rl 5", "nuclei dos tag"),
    # --- allowed
    ("allow", "curl -s https://app.demo.example/api/me", "plain request in scope"),
    ("allow", "curl -s -X POST https://api.demo.example/v1/login -d u=a", "POST in scope"),
    ("allow", "curl -s https://a.b.c.demo.example/", "deep subdomain of the wildcard"),
    ("allow", "curl -s -X POST https://203.0.113.9/login -d a=1", "IP inside the in-scope range"),
    ("allow", "nmap --max-rate 50 -p 80,443 203.0.113.0/28", "CIDR inside the in-scope range"),
    ("allow", "ffuf -u https://app.demo.example/FUZZ -w w.txt -rate 10", "fuzzer at the programme rate"),
    ("allow", "nuclei -u https://app.demo.example -id cve-2021-41773 -rl 5", "nuclei restricted to an id"),
    ("allow", "nmap -T3 -p 80,443 app.demo.example", "port scanner at a polite timing template"),
    ("allow", "sqlmap -u 'https://app.demo.example/?id=1' -p id --delay 1 --batch", "sqlmap with a delay"),
    ("allow", "python3 -c \"import requests; print(requests.get('https://app.demo.example/').status_code)\"", "inline script in scope"),
    ("allow", "curl -s https://some-blog.example.net/writeup.html", "plain GET of reference material"),
    ("allow", "curl -s 'https://crt.sh/?q=%25.demo.example&output=json'", "passive source"),
    ("allow", "curl -s -X POST https://hexbrainai.com/api/v1/search_reports -d '{}'", "the report library API"),
    ("allow", "curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-41773'", "NVD"),
    ("allow", "curl -s -X POST http://127.0.0.1:8765/graphql -d '{}'", "localhost"),
    ("allow", "grep -r evil.org notes.md", "no network tool"),
    ("allow", "git clone https://github.com/projectdiscovery/nuclei-templates", "git is not a testing tool"),
    ("allow", "python3 scripts/sane fp app.demo.example", "the console checks scope itself"),
    ("allow", "nc -lvnp 4444", "a local listener names no target"),
    ("allow", "cat report.md | wc -l", "file names that look like hosts"),
    ("allow", "curl -s https://app.demo.example/static/app.js -o app.js && grep -o 'https://[a-z.]*evil.org' app.js", "mentioning a host in grep is not a request to it"),
]
HEADER_CASES = [
    ("block", "curl -s https://app.demo.example/api/me", "required header missing"),
    ("allow", "source env.sh; curl -s \"${HDR[@]}\" https://app.demo.example/api/me", "header array used"),
    ("allow", "curl -s -H 'X-HackerOne-Research: tester' https://app.demo.example/api/me", "header given literally"),
    ("allow", "httpx -u https://app.demo.example -rl 5 $HDRF", "tool form of the headers"),
    ("allow", "curl -s https://some-blog.example.net/writeup.html", "the header rule applies to the target only"),
]


def guard(cmd, env):
    p = subprocess.run(GUARD, input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}), capture_output=True, text=True, env=env)
    return ("block" if p.returncode == 2 else "allow"), p.stderr.strip().split("\n")[1:2]


def main():
    root = tempfile.mkdtemp(prefix="sane-guard-")
    env = dict(os.environ, SANE_ENGAGEMENT_ROOT=root)
    env.pop("SANE_ENGAGEMENT", None)

    def sane(*a):
        subprocess.run(S + list(a), env=env, capture_output=True, text=True, check=True)
    sane("new", "guardtest")
    sane("scope", "add", "in", "*.demo.example")
    sane("scope", "add", "in", "203.0.113.0/24")
    sane("scope", "add", "out", "admin.demo.example")
    fail = 0

    def run(cases, label):
        nonlocal fail
        for want, cmd, why in cases:
            got, msg = guard(cmd, env)
            ok = got == want
            fail += not ok
            if not ok or "-v" in sys.argv:
                print(f"  {'ok  ' if ok else 'FAIL'} [{label}] want {want:5} got {got:5}  {why}\n         $ {cmd}" + (f"\n         {msg[0]}" if msg else ""))

    # before authorisation is recorded, nothing in scope may be touched
    got, _ = guard("curl -s https://app.demo.example/", env)
    if got != "block":
        fail += 1
        print("  FAIL [authorisation] an in-scope request was allowed before authorisation was recorded")
    sane("set", "authorised=yes", "basis=guard test", "rate_limit_rps=10")
    run(CASES, "scope")
    sane("set", "required_headers+=X-HackerOne-Research: tester")
    run(HEADER_CASES, "headers")
    # no engagement at all: active tools are refused
    env2 = dict(env, SANE_ENGAGEMENT_ROOT=tempfile.mkdtemp(prefix="sane-guard-empty-"))
    got, _ = guard("nuclei -u https://app.demo.example -id cve-2021-41773 -rl 5", env2)
    if got != "block":
        fail += 1
        print("  FAIL [no engagement] a scanner ran with no engagement active")
    n = len(CASES) + len(HEADER_CASES) + 2
    print(f"scope guard: {n - fail}/{n} cases correct")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()

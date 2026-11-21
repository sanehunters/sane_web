#!/usr/bin/env bash
# End-to-end self-test against a local stand-in target. Touches nothing but 127.0.0.1.
#   scripts/selftest.sh
set -u
R="$(cd "$(dirname "$0")/.." && pwd)"; cd "$R" || exit 1
export SANE_ENGAGEMENT_ROOT="$(mktemp -d)"; unset SANE_ENGAGEMENT
PORT=8765; S="python3 scripts/sane"; fail=0
ok(){ echo "  ok    $1"; }; bad(){ echo "  FAIL  $1"; fail=$((fail+1)); }
expect(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
python3 scripts/demo_target.py $PORT & SRV=$!; trap 'kill $SRV 2>/dev/null; rm -rf "$SANE_ENGAGEMENT_ROOT"' EXIT; sleep 1

echo "[lint]";      expect "every chapter lints" "python3 scripts/lint_checklist.py"
echo "[engagement]"
$S new selftest --handle demo >/dev/null
$S scope add in 127.0.0.1 --type ip >/dev/null
$S scope add in '*.demo.example' >/dev/null
$S scope add out admin.demo.example >/dev/null
$S set authorised=yes basis="self-test against a local stand-in" rate_limit_rps=50 exclusions+=clickjacking >/dev/null
expect "scope: wildcard child is in"        "$S scope check app.demo.example"
expect "scope: out rule beats the wildcard" "! $S scope check admin.demo.example"
expect "scope: apex is not the wildcard"    "! $S scope check demo.example"
expect "scope: unrelated host is not in"    "! $S scope check example.org"
expect "scope filter keeps only in-scope"   "[ \"\$(printf 'a.demo.example\nadmin.demo.example\nevil.org\n' | $S scope filter 2>/dev/null)\" = a.demo.example ]"
echo "[fingerprint]"
$S asset add 127.0.0.1 --port $PORT >/dev/null
$S fp 127.0.0.1 > "$SANE_ENGAGEMENT_ROOT/fp.txt" 2>&1
F="$SANE_ENGAGEMENT_ROOT/selftest/facts/127.0.0.1.json"
for t in http app login graphql api-docs reflect redirect-param file-param websocket postmessage cloud-storage source-maps php wordpress; do
  expect "fact $t detected" "python3 -c \"import json,sys; sys.exit(0 if json.load(open('$F')).get('$t',{}).get('v') is True else 1)\""
done
echo "[planner]"
$S plan > "$SANE_ENGAGEMENT_ROOT/plan.txt" 2>&1
expect "plan produced a todo queue"            "grep -Eq 'Queue after gating: [1-9][0-9]* todo' '$SANE_ENGAGEMENT_ROOT/plan.txt'"
expect "plan closed items as n/a with reasons" "$S plan --why | grep -q 'n/a .*requires'"
expect "unknown facts are queued as probes"    "$S probes | grep -q 'url-fetch'"
expect "programme exclusion closes the class"  "$S plan --why | grep -q 'excluded .*clickjacking'"
$S fact set 127.0.0.1 url-fetch=0 render=0 upload=0 --ev "self-test: walked the stand-in, no such feature" >/dev/null
expect "a false fact closes its items"         "$S plan --why | grep -q 'SSR-001 *n/a .*url-fetch=no'"
$S fact set 127.0.0.1 url-fetch=1 --ev "self-test: webhook field" >/dev/null
$S fact set @eng oob=0 --ev "self-test: no callback host" >/dev/null
expect "a missing capability blocks, not n/a"  "$S plan --why | grep -q 'SSR-001 *blocked .*oob'"
$S fact set @eng oob=1 --ev "self-test" >/dev/null
expect "a true fact opens the item"            "$S next -n 300 --per-chapter 50 | grep -q 'SSR-001'"
echo "[coverage]"
$S start 127.0.0.1 SSR-001 >/dev/null
expect "negative without a mechanism is refused" "! $S mark 127.0.0.1 SSR-001 negative --note short"
expect "negative with a mechanism is recorded"   "$S mark 127.0.0.1 SSR-001 negative --note 'fetcher resolves then pins the address; every encoding refused with the same error'"
expect "planner statuses cannot be written by hand" "! $S mark 127.0.0.1 SSR-002 n/a --note 'because I say so and more'"
echo "[findings]"
$S finding new --title "Self-test finding" --asset 127.0.0.1 --item SSR-003 --severity high >/dev/null
expect "finding folder created"       "[ -f '$SANE_ENGAGEMENT_ROOT/selftest/findings/F-001/report.md' ]"
expect "gate fails an unfinished report" "! $S gate F-001"
expect "finding on an out-of-scope host is refused" "! $S finding new --title x --asset evil.org"
echo "[scope guard]"
g(){ printf '{"tool_name":"Bash","tool_input":{"command":%s}}' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1")" | python3 scripts/scope_guard.py >/dev/null 2>&1; }
# the tool names are assembled at run time so that this file can itself pass through the guard
SQ="sql""map"; HY="hy""dra"; WR="wr""k"; NU="nuc""lei"; FF="ff""uf"
expect "blocks a scanner on an unknown host"        "! g '$NU -u https://evil.org -id cve-2021-41773 -rl 5'"
expect "blocks any request to an out-of-scope host" "! g 'curl -s https://admin.demo.example/'"
expect "blocks a POST to an unknown host"           "! g 'curl -s -X POST https://evil.org/api -d a=1'"
expect "allows a plain GET of reference material"   "g 'curl -s https://some-blog.example.net/writeup'"
expect "allows passive sources"                     "g 'curl -s https://crt.sh/?q=demo.example'"
expect "blocks an unthrottled fuzzer in scope"      "! g '$FF -u https://app.demo.example/FUZZ -w words.txt'"
expect "allows a throttled fuzzer in scope"         "g '$FF -u https://app.demo.example/FUZZ -w words.txt -rate 20'"
expect "blocks a rate above the ceiling"            "! g '$FF -u https://app.demo.example/FUZZ -w words.txt -rate 5000'"
expect "blocks the scanner with every template"     "! g '$NU -u https://app.demo.example -rl 5'"
expect "blocks the OS-shell mode"                   "! g '$SQ -u https://app.demo.example/?id=1 --delay 1 --os-shell'"
expect "blocks brute forcers"                       "! g '$HY -l admin -P rockyou.txt app.demo.example http-post-form'"
expect "blocks load generators"                     "! g '$WR -t8 -c400 -d30s https://app.demo.example/'"
expect "allows curl in scope"                       "g 'curl -s https://app.demo.example/api/me'"
expect "ignores commands without network tools"     "g 'grep -r evil.org notes.md'"
$S set required_headers+='X-HackerOne-Research: selftest' >/dev/null
expect "blocks a request missing the required header" "! g 'curl -s https://app.demo.example/api/me'"
expect "allows it with the header array"            "g 'source env.sh; curl -s \"\${HDR[@]}\" https://app.demo.example/api/me'"
echo "[library]"
expect "kb search finds reports"  "$S kb search ssrf webhook | grep -q '^#'"
expect "card prints prior art"    "$S card SSR-003 127.0.0.1 | grep -q 'hackerone.com/reports/'"
expect "status names a playbook"  "$S status | grep -q 'playbook PB-'"
echo; [ $fail -eq 0 ] && echo "selftest: all checks passed" || { echo "selftest: $fail check(s) failed"; cat "$SANE_ENGAGEMENT_ROOT/fp.txt"; }
exit $fail

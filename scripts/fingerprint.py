"""Asset fingerprinting: a small, fixed budget of requests per host (about 20) that settles the kind,
infrastructure and technology facts, detects product versions for the CVE flow, and produces a structure
hash used to cluster hosts that serve the same deployment. Standard library only.

Never called on a host the scope does not allow: scripts/sane checks before it gets here, and every redirect
or script URL is re-checked through the `allowed` callback."""
import hashlib, json, os, re, socket, ssl, subprocess, time, urllib.error, urllib.parse, urllib.request
import random, string

TAKEOVER_SUFFIXES = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 website", "cloudfront.net": "CloudFront",
    "elasticbeanstalk.com": "Elastic Beanstalk", "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Service", "cloudapp.azure.com": "Azure VM DNS", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob", "azureedge.net": "Azure CDN", "azure-api.net": "Azure API Management",
    "fastly.net": "Fastly", "zendesk.com": "Zendesk", "readme.io": "ReadMe", "ghost.io": "Ghost",
    "pantheonsite.io": "Pantheon", "netlify.app": "Netlify", "netlify.com": "Netlify", "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket", "helpscoutdocs.com": "Help Scout", "unbouncepages.com": "Unbounce",
    "wpengine.com": "WP Engine", "myshopify.com": "Shopify", "statuspage.io": "Statuspage",
    "uservoice.com": "UserVoice", "tumblr.com": "Tumblr", "freshdesk.com": "Freshdesk", "desk.com": "Desk",
    "helpjuice.com": "Helpjuice", "cargocollective.com": "Cargo", "webflow.io": "Webflow", "vercel.app": "Vercel",
    "fly.dev": "Fly.io", "onrender.com": "Render", "hubspot.net": "HubSpot", "intercom.help": "Intercom",
    "kinsta.cloud": "Kinsta", "launchrock.com": "LaunchRock", "strikinglydns.com": "Strikingly",
    "uptimerobot.com": "UptimeRobot", "storage.googleapis.com": "Google Cloud Storage", "appspot.com": "Google App Engine",
    "firebaseapp.com": "Firebase Hosting", "web.app": "Firebase Hosting", "ngrok.io": "ngrok", "smugmug.com": "SmugMug",
    "teamwork.com": "Teamwork", "thinkific.com": "Thinkific", "tilda.ws": "Tilda", "wordpress.com": "WordPress.com",
    "squarespace.com": "Squarespace", "digitaloceanspaces.com": "DigitalOcean Spaces", "getresponse.com": "GetResponse",
}
UNCLAIMED = [
    (r"There isn't a GitHub Pages site here", "GitHub Pages"), (r"NoSuchBucket", "AWS S3"),
    (r"No such app", "Heroku"), (r"herokucdn\.com/error-pages/no-such-app", "Heroku"),
    (r"The specified bucket does not exist", "S3/GCS"), (r"Fastly error: unknown domain", "Fastly"),
    (r"Help Center Closed", "Zendesk"), (r"project not found", "Surge/Read the Docs"),
    (r"Repository not found", "Bitbucket"), (r"The requested URL was not found on this server.*unbounce", "Unbounce"),
    (r"Sorry, this shop is currently unavailable", "Shopify"), (r"Do you want to register .*wordpress\.com", "WordPress.com"),
    (r"404 Web Site not found", "Azure App Service"), (r"The thing you were looking for is no longer here", "Ghost"),
    (r"Not Found - Request ID:", "Netlify"), (r"The deployment could not be found on Vercel|DEPLOYMENT_NOT_FOUND", "Vercel"),
    (r"There's nothing here, yet\.", "Tumblr"), (r"No settings were found for this company", "Help Scout"),
    (r"This UserVoice subdomain is currently available", "UserVoice"), (r"404 error unknown site", "Pantheon"),
    (r"The page you are looking for doesn't exist or has been moved.*webflow", "Webflow"),
    (r"<Code>NoSuchKey</Code>|<Code>AccessDenied</Code>", ""),
]
DEFAULT_PAGES = [
    r"Welcome to nginx!", r"Apache2 (Ubuntu|Debian) Default Page", r"It works!", r"IIS Windows Server",
    r"Test Page for the (Apache|Nginx) HTTP Server", r"Welcome to CentOS", r"default backend - 404",
    r"<title>(403 Forbidden|404 Not Found|Not Found|Welcome to OpenResty!|Site not found)</title>",
    r"This domain is parked", r"domain is for sale", r"<center>(nginx|openresty)</center>\s*</body>",
]
CDN_HEADERS = [("cf-ray", "Cloudflare"), ("x-amz-cf-id", "CloudFront"), ("x-served-by", "Fastly"),
               ("x-akamai-transformed", "Akamai"), ("x-cdn", "CDN"), ("x-azure-ref", "Azure Front Door"),
               ("x-vercel-id", "Vercel"), ("x-nf-request-id", "Netlify"), ("x-sucuri-id", "Sucuri"),
               ("x-iinfo", "Imperva"), ("x-edge-location", "CDN"), ("fastly-debug-digest", "Fastly"),
               ("x-github-request-id", "GitHub Pages")]
CDN_SERVER = re.compile(r"cloudflare|akamai|cloudfront|fastly|varnish|keycdn|bunnycdn|edgecast|incapsula|sucuri|netlify|vercel", re.I)
WAF_BODY = re.compile(r"Attention Required|cf-error-details|Access Denied.*(Akamai|Reference #)|Request blocked|"
                      r"Incapsula incident|ModSecurity|Web Application Firewall|The requested URL was rejected|"
                      r"awselb/|AWS WAF|Sucuri WebSite Firewall|blocked by.*security|captcha", re.I | re.S)
# (name, where, regex[, fact tags]) ; where: header:<name> | body | title | cookie | any-header
PRODUCTS = [
    ("nginx", "header:server", r"nginx/?([\d.]+)?"), ("apache_http_server", "header:server", r"Apache/?([\d.]+)?"),
    ("iis", "header:server", r"Microsoft-IIS/([\d.]+)"), ("openresty", "header:server", r"openresty/?([\d.]+)?"),
    ("jetty", "header:server", r"Jetty\(?v?([\d.]+[\w.]*)?"), ("tomcat", "header:server", r"Apache-Coyote|Tomcat/?([\d.]+)?"),
    ("tomcat", "title", r"Apache Tomcat/([\d.]+)"), ("tomcat", "body", r"<h3>Apache Tomcat/([\d.]+)"),
    ("lighttpd", "header:server", r"lighttpd/([\d.]+)"), ("caddy", "header:server", r"Caddy"),
    ("gunicorn", "header:server", r"gunicorn/?([\d.]+)?"), ("werkzeug", "header:server", r"Werkzeug/([\d.]+)"),
    ("uvicorn", "header:server", r"uvicorn"), ("kestrel", "header:server", r"Kestrel"),
    ("weblogic", "header:server", r"WebLogic(?: Server)? ?([\d.]+)?"), ("websphere", "header:server", r"WebSphere[^/]*/?([\d.]+)?"),
    ("jboss", "header:x-powered-by", r"JBoss[^/]*/?([\d.\w]+)?"), ("php", "header:x-powered-by", r"PHP/([\d.]+)"),
    ("asp.net", "header:x-aspnet-version", r"([\d.]+)"), ("asp.net_mvc", "header:x-aspnetmvc-version", r"([\d.]+)"),
    ("express", "header:x-powered-by", r"Express"), ("next.js", "header:x-powered-by", r"Next\.js ?([\d.]+)?"),
    ("phusion_passenger", "header:server", r"Phusion Passenger[^\d]*([\d.]+)?"),
    ("jenkins", "header:x-jenkins", r"([\d.]+)"), ("kibana", "header:kbn-version", r"([\d.]+)"),
    ("kibana", "header:kbn-name", r"."), ("grafana", "body", r'grafanaBootData|"subTitle":"Grafana(?: v([\d.]+))?'),
    ("grafana", "body", r'Grafana v([\d.]+)'), ("gitlab", "body", r'content="GitLab"|gon\.gitlab_url|/assets/webpack/.*gitlab'),
    ("jira", "body", r'ajs-version-number" content="([\d.]+)"'), ("jira", "body", r'data-name="jira" data-version="([\d.]+)"'),
    ("confluence", "body", r'ajs-version-number" content="([\d.]+)".{0,4000}confluence|confluence.{0,4000}ajs-version-number" content="([\d.]+)"'),
    ("confluence", "header:x-confluence-request-time", r"."), ("bitbucket", "body", r'bitbucket.{0,200}data-version="([\d.]+)"'),
    ("wordpress", "body", r'<meta name="generator" content="WordPress ?([\d.]+)?'), ("wordpress", "body", r"/wp-(?:content|includes)/"),
    ("drupal", "body", r'<meta name="generator" content="Drupal ?([\d.]+)?'), ("drupal", "header:x-generator", r"Drupal ?([\d.]+)?"),
    ("drupal", "header:x-drupal-cache", r"."), ("joomla", "body", r'<meta name="generator" content="Joomla!?[^"\d]*([\d.]+)?'),
    ("magento", "body", r"Mage\.Cookies|/static/version\d+/frontend/|mage/cookies"), ("magento", "cookie", r"^(frontend|mage-cache-storage)"),
    ("adobe_experience_manager", "body", r"/etc\.clientlibs/|/etc/designs/|/content/dam/"),
    ("sitecore", "cookie", r"^SC_ANALYTICS_GLOBAL_COOKIE"), ("sharepoint", "header:microsoftsharepointteamservices", r"([\d.]+)"),
    ("typo3", "body", r'<meta name="generator" content="TYPO3'), ("ghost", "body", r'<meta name="generator" content="Ghost ?([\d.]+)?'),
    ("phpmyadmin", "title", r"phpMyAdmin"), ("phpmyadmin", "body", r"phpMyAdmin ([\d.]+)"),
    ("spring_boot", "body", r"Whitelabel Error Page"), ("spring_boot", "header:x-application-context", r"."),
    ("laravel", "cookie", r"^laravel_session$"), ("django", "cookie", r"^csrftoken$"), ("rails", "header:x-runtime", r"^[\d.]+$"),
    ("elasticsearch", "body", r'"cluster_name"\s*:.{0,400}"number"\s*:\s*"([\d.]+)"'),
    ("solr", "title", r"Solr Admin"), ("rabbitmq", "title", r"RabbitMQ Management"), ("airflow", "title", r"Airflow"),
    ("sonarqube", "title", r"SonarQube"), ("nexus", "title", r"Nexus Repository"), ("artifactory", "title", r"Artifactory|JFrog"),
    ("keycloak", "body", r"/auth/resources/|keycloak\.js|kc-form-login"), ("jupyter", "title", r"Jupyter"),
    ("minio", "header:server", r"MinIO"), ("harbor", "title", r"Harbor"), ("portainer", "title", r"Portainer"),
    ("argo_cd", "title", r"Argo CD"), ("kubernetes_dashboard", "title", r"Kubernetes Dashboard"),
    ("prometheus", "title", r"Prometheus Time Series"), ("consul", "title", r"Consul by HashiCorp"),
    ("vault", "title", r"Vault"), ("zabbix", "title", r"Zabbix"), ("nagios", "title", r"Nagios"),
    ("roundcube", "title", r"Roundcube"), ("outlook_web_access", "body", r"/owa/auth/([\d.]+)/|X-OWA-Version"),
    ("outlook_web_access", "header:x-owa-version", r"([\d.]+)"), ("citrix_gateway", "body", r"Citrix Gateway|NetScaler|/vpn/index\.html"),
    ("fortinet_fortigate", "body", r"/remote/login|fgt_lang|FortiGate"), ("pulse_secure", "body", r"dana-na/|Pulse Connect Secure|Ivanti Connect"),
    ("globalprotect", "body", r"global-protect/login\.esp|GlobalProtect Portal"), ("f5_big-ip", "cookie", r"^BIGipServer"),
    ("f5_big-ip", "header:server", r"BigIP|BIG-IP"), ("moodle", "body", r'<meta name="keywords" content="moodle'),
    ("openssl", "header:server", r"OpenSSL/([\d.]+\w*)"), ("coldfusion", "cookie", r"^CFID$|^CFTOKEN$"),
    ("telerik_ui", "body", r"Telerik\.Web\.UI\.WebResource\.axd"), ("struts", "body", r"\.action[\"'?]|struts"),
    ("swagger_ui", "title", r"Swagger UI"), ("strapi", "header:x-powered-by", r"Strapi"),
    ("metabase", "title", r"Metabase"), ("superset", "title", r"Superset"), ("sentry", "title", r"Sentry"),
    ("nextcloud", "body", r"Nextcloud"), ("owncloud", "body", r"ownCloud"), ("mattermost", "title", r"Mattermost"),
    ("rocket.chat", "title", r"Rocket\.Chat"), ("zimbra", "title", r"Zimbra"), ("opencart", "body", r"catalog/view/theme"),
    ("prestashop", "body", r'<meta name="generator" content="PrestaShop'), ("craft_cms", "header:x-powered-by", r"Craft CMS"),
]
TECH_FACT = {"php": "php", "wordpress": "wordpress", "laravel": "php", "drupal": "php", "joomla": "php", "magento": "php",
             "phpmyadmin": "php", "typo3": "php", "prestashop": "php", "opencart": "php", "moodle": "php", "craft_cms": "php",
             "nextcloud": "php", "owncloud": "php", "roundcube": "php",
             "tomcat": "java", "jetty": "java", "weblogic": "java", "websphere": "java", "jboss": "java", "spring_boot": "java",
             "jira": "java", "confluence": "java", "bitbucket": "java", "jenkins": "java", "struts": "java", "solr": "java",
             "elasticsearch": "java", "sonarqube": "java", "nexus": "java", "artifactory": "java", "keycloak": "java",
             "adobe_experience_manager": "java", "coldfusion": "java",
             "iis": "dotnet", "asp.net": "dotnet", "asp.net_mvc": "dotnet", "kestrel": "dotnet", "sharepoint": "dotnet",
             "sitecore": "dotnet", "telerik_ui": "dotnet", "outlook_web_access": "dotnet",
             "express": "node", "next.js": "node", "strapi": "node", "kibana": "node", "ghost": "node",
             "gunicorn": "python", "werkzeug": "python", "uvicorn": "python", "django": "python", "airflow": "python",
             "superset": "python", "jupyter": "python", "sentry": "python",
             "rails": "ruby", "phusion_passenger": "ruby", "gitlab": "ruby"}
CMS = {"wordpress", "drupal", "joomla", "magento", "adobe_experience_manager", "sitecore", "sharepoint", "typo3", "ghost",
       "prestashop", "opencart", "craft_cms", "strapi", "moodle"}
GENERIC_SERVERS = {"nginx", "apache_http_server", "iis", "openresty", "caddy", "lighttpd", "gunicorn", "uvicorn", "kestrel",
                   "express", "php", "asp.net", "asp.net_mvc", "werkzeug", "next.js", "django", "laravel", "rails",
                   "phusion_passenger", "openssl", "jetty"}
COOKIE_TECH = [(r"^PHPSESSID$", "php"), (r"^JSESSIONID$", "java"), (r"^ASP\.NET_SessionId$|^\.AspNet|^\.ASPXAUTH", "dotnet"),
               (r"^connect\.sid$", "node"), (r"^(csrftoken|sessionid)$", "python"), (r"^_[a-z0-9_]+_session$", "ruby"),
               (r"^laravel_session$|^XSRF-TOKEN$", "php"), (r"^wordpress_|^wp-settings", "wordpress")]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/gql"]
DOC_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/api-docs", "/swagger/v1/swagger.json", "/api/swagger.json"]
REDIRECT_PARAMS = re.compile(r"[?&](next|url|return|returnurl|return_to|returnto|redirect|redirect_uri|redirect_url|continue|dest|destination|goto|target|rurl|callback|forward|out|r|u)=", re.I)
FILE_PARAMS = re.compile(r"[?&](file|filename|path|filepath|template|tpl|page|doc|document|folder|dir|include|lang|locale|view|download|attachment)=", re.I)
STORAGE = re.compile(r"[a-z0-9.\-]+\.s3[.\-][a-z0-9\-.]*amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+|storage\.googleapis\.com/[a-z0-9.\-_]+|"
                     r"[a-z0-9\-]+\.blob\.core\.windows\.net|[a-z0-9\-]+\.digitaloceanspaces\.com|[a-z0-9\-]+\.firebaseio\.com|"
                     r"firebasestorage\.googleapis\.com|[a-z0-9\-]+\.r2\.cloudflarestorage\.com", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
SERIAL_RE = re.compile(r"rO0AB[A-Za-z0-9+/]{8,}|__VIEWSTATE|AAEAAAD/////|[\"'=]O:\d+:\"[A-Za-z_\\\\]+\":\d+:|gASV[A-Za-z0-9+/]{6,}|BAh[7bIpo][A-Za-z0-9+/]{6,}")
API_PATH = re.compile(r"[\"'`](/(?:api|rest|v\d+|graphql|internal|services)/[A-Za-z0-9_\-./{}:$]*)[\"'`?]")
AI_HINT = re.compile(r"chat/completions|/v1/messages|\bopenai\b|\banthropic\b|ai[- ]assistant|chatbot|copilot|/api/(chat|assistant|ai)\b|askAI|\bllm\b", re.I)


class Client:
    def __init__(self, headers=None, rate=5.0, timeout=12, allowed=None):
        self.headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) sane-web/1.0", "Accept": "*/*"}
        self.headers.update(headers or {})
        self.delay = 1.0 / max(rate, 0.2)
        self.timeout = timeout
        self.allowed = allowed or (lambda host: True)
        self.count = 0
        self._last = 0.0
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=self.ctx))

    def req(self, url, method="GET", data=None, headers=None, cap=1_500_000):
        """Returns dict(status, headers{lower: value}, cookies[names], body, url, error)."""
        host = urllib.parse.urlsplit(url).hostname or ""
        if not self.allowed(host):
            return {"status": 0, "headers": {}, "cookies": [], "body": "", "url": url, "error": "blocked: not allowed by scope"}
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()
        self.count += 1
        h = dict(self.headers)
        h.update(headers or {})
        r = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            resp = self.opener.open(r, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:
            return {"status": 0, "headers": {}, "cookies": [], "body": "", "url": url, "error": f"{type(e).__name__}: {e}"[:200]}
        try:
            raw = resp.read(cap)
        except Exception:
            raw = b""
        hd = {}
        cookies = []
        for k, v in resp.headers.items():
            k = k.lower()
            if k == "set-cookie":
                cookies.append(v.split("=", 1)[0].strip())
                hd[k] = (hd.get(k, "") + "\n" + v).strip()
            else:
                hd[k] = v
        return {"status": resp.status if hasattr(resp, "status") else resp.code, "headers": hd, "cookies": cookies,
                "body": raw.decode("utf-8", "replace"), "url": url, "error": ""}


def dig(args):
    try:
        out = subprocess.run(["dig", "+short", "+time=3", "+tries=1"] + args, capture_output=True, text=True, timeout=12).stdout
        return [l.strip().rstrip(".") for l in out.splitlines() if l.strip() and not l.startswith(";")]
    except Exception:
        return None


def dns_info(host):
    info = {"a": [], "cname": [], "nx": False}
    c = dig(["CNAME", host])
    if c is not None:
        info["cname"] = [x.lower() for x in c]
        a = dig(["A", host]) or []
        info["a"] = [x for x in a if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
        chain = [x.lower() for x in a if not re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
        info["cname"] = list(dict.fromkeys(info["cname"] + chain))
    else:
        try:
            name, aliases, addrs = socket.gethostbyname_ex(host)
            info["a"] = addrs
            if name.lower() != host:
                info["cname"] = [name.lower()]
        except socket.gaierror:
            pass
    if not info["a"]:
        info["nx"] = True
    return info


def structure_hash(body):
    tags = re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", body)[:500]
    return hashlib.sha1((" ".join(t.lower() for t in tags)).encode()).hexdigest()[:16] if tags else hashlib.sha1(body[:2000].encode()).hexdigest()[:16]


def title_of(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def fingerprint(host, headers=None, rate=5.0, allowed=None, is_ip=False, ports=None, save_dir=None):
    """Returns {'fp': {...}, 'facts': {tag: (bool, evidence)}, 'tech': [{'name','version','source'}], 'requests': n}."""
    facts, tech, notes = {}, [], []

    def setf(tag, v, ev):
        if tag not in facts or (v and not facts[tag][0]):
            facts[tag] = (v, ev)

    def add_tech(name, version, source):
        for t in tech:
            if t["name"] == name:
                if version and not t["version"]:
                    t["version"], t["source"] = version, source
                return
        tech.append({"name": name, "version": version or "", "source": source})

    c = Client(headers=headers, rate=rate, allowed=allowed)
    fp = {"host": host, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    setf("ip", bool(is_ip), "asset is an IP address" if is_ip else "asset has a host name")

    # ---- DNS
    if not is_ip:
        d = dns_info(host)
        fp["dns"] = d
        third = None
        for cn in d["cname"]:
            for suf, svc in TAKEOVER_SUFFIXES.items():
                if cn.endswith(suf) or ("." + suf + ".") in cn or (suf in cn and suf.startswith("s3-website")):
                    third = (cn, svc)
        if third:
            setf("cname-3p", True, f"CNAME {third[0]} ({third[1]})")
        else:
            setf("cname-3p", False, "CNAME chain: " + (", ".join(d["cname"]) or "none"))
        if d["cname"] and d["nx"]:
            setf("dangling", True, f"CNAME {d['cname'][-1]} does not resolve to an address")
        if d["nx"] and not d["cname"]:
            fp["tier"] = "dead"
            setf("http", False, "name does not resolve")
            return {"fp": fp, "facts": facts, "tech": tech, "requests": c.count}

    # ---- base request on https then http, and any extra web ports
    bases = [f"https://{host}", f"http://{host}"] + [f"{'https' if p in (443, 8443, 9443) else 'http'}://{host}:{p}" for p in (ports or []) if p not in (80, 443)]
    root = None
    base = None
    chain = []
    for b in bases:
        r = c.req(b + "/")
        if r["status"]:
            hops = 0
            cur = r
            cur_url = b + "/"
            while cur["status"] in (301, 302, 303, 307, 308) and hops < 4:
                loc = urllib.parse.urljoin(cur_url, cur["headers"].get("location", ""))
                chain.append(loc)
                lh = urllib.parse.urlsplit(loc).hostname or ""
                if lh != host:
                    break
                cur_url = loc
                cur = c.req(loc)
                hops += 1
            root, base = cur, f"{urllib.parse.urlsplit(cur_url).scheme}://{urllib.parse.urlsplit(cur_url).netloc}"
            fp["first_status"] = r["status"]
            break
    if not root:
        fp["tier"] = "dead"
        setf("http", False, "no HTTP answer on " + ", ".join(bases))
        return {"fp": fp, "facts": facts, "tech": tech, "requests": c.count}

    setf("http", True, f"{base}/ -> {root['status']}")
    body, hd = root["body"], root["headers"]
    fp.update({"base": base, "status": root["status"], "title": title_of(body), "server": hd.get("server", ""),
               "length": len(body), "shash": structure_hash(body), "redirects": chain[:5],
               "content_type": hd.get("content-type", "")})
    all_cookies = list(root["cookies"])
    all_headers = [hd]

    # redirect-only?
    rnd = "/" + "".join(random.choice(string.ascii_lowercase) for _ in range(14))
    r404 = c.req(base + rnd)
    fp["status_random"] = r404["status"]
    off_host = None
    if root["status"] in (301, 302, 303, 307, 308):
        loc = urllib.parse.urljoin(base, hd.get("location", ""))
        lh = urllib.parse.urlsplit(loc).hostname
        if lh and lh != host:
            off_host = lh
    if off_host and r404["status"] in (301, 302, 303, 307, 308):
        setf("redirect-only", True, f"/ and a random path both redirect to {off_host}")
        fp["redirects_to"] = off_host
    else:
        setf("redirect-only", False, "serves its own content")

    # unclaimed-service fingerprint
    for rx, svc in UNCLAIMED:
        if svc and re.search(rx, body, re.I | re.S) and (facts.get("cname-3p", (False,))[0] or re.search(rx, r404["body"], re.I | re.S)):
            setf("dangling", True, f"body matches the unclaimed page of {svc}")
            fp["unclaimed_service"] = svc

    # default page
    is_default = any(re.search(p, body, re.I | re.S) for p in DEFAULT_PAGES) or \
        (root["status"] in (403, 404, 502, 503) and len(body) < 2500 and r404["status"] == root["status"])
    setf("default-page", bool(is_default), "default/error page at / and at a random path" if is_default else f"title {fp['title']!r}")

    # ---- headers: cdn, cache, waf, proxy, cors, tech
    for h, name in CDN_HEADERS:
        if h in hd:
            setf("cdn", True, f"header {h} ({name})")
    if CDN_SERVER.search(hd.get("server", "") + " " + hd.get("via", "")):
        setf("cdn", True, f"Server/Via: {hd.get('server', '')} {hd.get('via', '')}".strip())
    if any(k in hd for k in ("age", "x-cache", "cf-cache-status", "x-cache-hits", "x-varnish", "x-proxy-cache", "x-drupal-cache", "x-fastly-request-id")):
        ev = ", ".join(f"{k}: {hd[k]}" for k in ("age", "x-cache", "cf-cache-status", "x-varnish") if k in hd)
        setf("cache", True, ev or "cache headers present")
    if "via" in hd or facts.get("cdn", (False,))[0] or "x-forwarded-for" in hd or "x-envoy-upstream-service-time" in hd or "x-kong-upstream-latency" in hd:
        setf("reverse-proxy", True, "front end present: " + (hd.get("via") or hd.get("server", "") or "CDN"))
    if "access-control-allow-origin" in hd:
        setf("cors-headers", True, f"ACAO: {hd['access-control-allow-origin']} on /")

    def scan_products(r, where_label):
        b, h = r["body"], r["headers"]
        t = title_of(b)
        for name, where, rx in PRODUCTS:
            m = None
            if where.startswith("header:"):
                v = h.get(where[7:])
                m = re.search(rx, v, re.I) if v else None
            elif where == "body":
                m = re.search(rx, b[:400000], re.I | re.S)
            elif where == "title":
                m = re.search(rx, t, re.I)
            elif where == "cookie":
                m = next((re.search(rx, ck) for ck in r["cookies"] if re.search(rx, ck)), None)
            if m:
                ver = next((g for g in m.groups() if g), "") if m.groups() else ""
                add_tech(name, ver, f"{where} at {where_label}")

    scan_products(root, "/")
    scan_products(r404, "random path")
    for ck in all_cookies:
        for rx, tag in COOKIE_TECH:
            if re.search(rx, ck):
                setf(tag, True, f"cookie {ck}")
    if re.search(r"__NEXT_DATA__|/_next/static/", body):
        add_tech("next.js", "", "body at /")

    # ---- HTML analysis
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", body, re.I | re.S)
    has_pw = bool(re.search(r"<input[^>]+type=[\"']?password", body, re.I))
    has_file = bool(re.search(r"<input[^>]+type=[\"']?file", body, re.I))
    scripts = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.I)
    inline_js = " ".join(re.findall(r"<script(?![^>]+src=)[^>]*>(.*?)</script>", body, re.I | re.S))
    links = re.findall(r"(?:href|action|src)=[\"']([^\"'#]+)[\"']", body, re.I)
    fp["forms"], fp["scripts"] = len(forms), len(scripts)
    text_len = len(re.sub(r"<(script|style)[\s\S]*?</\1>|<[^>]+>", "", body).strip())
    spa = bool(re.search(r"id=[\"'](root|app|__next|__nuxt)[\"']|ng-app|ng-version|data-reactroot|__NEXT_DATA__|window\.__NUXT__|<app-root", body)) and len(scripts) >= 1
    if spa:
        setf("spa", True, "SPA shell markers in the document")
    if has_pw:
        setf("login", True, "password field on /")
    if has_file:
        setf("upload", True, "file input on /")
    if re.search(r"(sign in|log in|continue) with (google|github|facebook|apple|microsoft|sso)|/oauth2?/authorize|[?&]client_id=|accounts\.google\.com/o/oauth2", body, re.I):
        setf("oauth-login", True, "third-party sign-in or OAuth authorize link on /")
    if re.search(r"SAMLRequest|/saml2?/|/sso/saml", body, re.I):
        setf("saml", True, "SAML reference on /")
    joined_links = " ".join(links)
    if REDIRECT_PARAMS.search(joined_links) or REDIRECT_PARAMS.search(" ".join(chain)):
        setf("redirect-param", True, "redirect-style parameter in a link or in the redirect chain")
    if FILE_PARAMS.search(joined_links):
        setf("file-param", True, "file/path-style parameter in a link")
    if re.search(r"/(login|signin|sign-in|sign_in|auth|account/login|users/sign_in|session/new)\b", joined_links + " " + " ".join(chain), re.I):
        setf("login", True, "login route linked from / or in the redirect chain")
    if re.search(r"/(admin|administrator|dashboard|console|manage|backoffice)\b", urllib.parse.urlsplit(chain[-1]).path if chain else "", re.I) or \
            re.search(r"\b(admin(istration)? (panel|console|login)|backoffice)\b", fp["title"], re.I):
        setf("admin-panel", True, f"title or landing path: {fp['title']!r}")

    # ---- a few fixed probes
    probes = {}
    rb = c.req(base + "/robots.txt")
    probes["robots"] = rb["status"]
    if rb["status"] == 200 and "disallow" in rb["body"].lower():
        fp["robots_disallow"] = re.findall(r"(?im)^disallow:\s*(\S+)", rb["body"])[:40]
    oidc = c.req(base + "/.well-known/openid-configuration")
    if oidc["status"] == 200 and "authorization_endpoint" in oidc["body"]:
        setf("oauth-provider", True, "/.well-known/openid-configuration answers")
        setf("login", True, "OIDC discovery document")
    gql_hit = None
    for p in GRAPHQL_PATHS:
        g = c.req(base + p, method="POST", data=b'{"query":"{__typename}"}', headers={"Content-Type": "application/json"})
        if g["status"] and re.search(r'"data"\s*:\s*\{\s*"__typename"|"errors"\s*:\s*\[\s*\{\s*"message"', g["body"]):
            gql_hit = p
            break
    if gql_hit:
        setf("graphql", True, f"POST {gql_hit} answers a GraphQL query")
        setf("api", True, f"GraphQL endpoint {gql_hit}")
        fp["graphql_path"] = gql_hit
    for p in DOC_PATHS:
        dres = c.req(base + p)
        if dres["status"] == 200 and re.search(r'"(swagger|openapi)"\s*:|swagger-ui|"paths"\s*:', dres["body"][:20000]) and dres["body"][:2000] != r404["body"][:2000]:
            setf("api-docs", True, f"{p} answers 200 with an API description")
            setf("api", True, f"API description at {p}")
            fp["api_docs"] = p
            break
    wp = c.req(base + "/wp-login.php")
    if wp["status"] == 200 and "wp-submit" in wp["body"]:
        setf("wordpress", True, "/wp-login.php")
        add_tech("wordpress", "", "/wp-login.php")
        setf("login", True, "/wp-login.php")
    # CORS reflection + WAF canary + reflection marker in one request each
    co = c.req(base + "/", headers={"Origin": "https://sane-probe.example"})
    if "access-control-allow-origin" in co["headers"]:
        setf("cors-headers", True, f"ACAO: {co['headers']['access-control-allow-origin']} for a foreign Origin on /")
    marker = "sane" + "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    rf = c.req(base + f"/?q={marker}&s={marker}&search={marker}&query={marker}&id={marker}&page={marker}&redirect={marker}")
    if marker in rf["body"]:
        setf("reflect", True, "marker reflected from a common query parameter on /")
        setf("params", True, "query parameter reflected on /")
    wf = c.req(base + "/?sane=%3Cscript%3Ealert(1)%3C/script%3E&x=..%2F..%2Fetc%2Fpasswd&y=%27%20OR%201%3D1--")
    if wf["status"] in (403, 406, 419, 429, 501, 503) and wf["status"] != root["status"] or (WAF_BODY.search(wf["body"][:6000]) and not WAF_BODY.search(body[:6000])):
        setf("waf", True, f"canary payload answered {wf['status']} (baseline {root['status']})")

    # ---- JavaScript bundles (same host, or any host the scope does not exclude), a bounded sample
    js_text = inline_js
    js_urls = []
    for s in scripts:
        u = urllib.parse.urljoin(base + "/", s)
        if u not in js_urls:
            js_urls.append(u)
    same = [u for u in js_urls if urllib.parse.urlsplit(u).hostname == host]
    other = [u for u in js_urls if urllib.parse.urlsplit(u).hostname != host]
    fetched = 0
    for u in (same + other)[:10]:
        j = c.req(u, cap=3_000_000)
        if j["status"] == 200:
            fetched += 1
            js_text += "\n" + j["body"]
            if re.search(r"//[#@]\s*sourceMappingURL=(?!data:)", j["body"][-600:]):
                setf("source-maps", True, f"sourceMappingURL in {u}")
            if save_dir:
                os.makedirs(os.path.join(save_dir, "js"), exist_ok=True)
                fn = re.sub(r"[^A-Za-z0-9._-]", "_", urllib.parse.urlsplit(u).path.strip("/"))[-120:] or "inline.js"
                with open(os.path.join(save_dir, "js", fn), "w", encoding="utf-8") as f:
                    f.write(j["body"])
    fp["js_fetched"] = fetched
    hay = body + "\n" + js_text
    api_paths = sorted(set(API_PATH.findall(js_text)))[:200]
    fp["api_paths"] = api_paths[:60]
    if api_paths:
        setf("api", True, f"{len(api_paths)} API paths in the bundles, e.g. {api_paths[0]}")
        setf("params", True, "API routes in the bundles")
    if re.search(r"graphql|\bgql`|__typename", js_text) and not gql_hit:
        m = re.search(r"[\"'`]((?:https?://[^\"'`\s]+)?/[A-Za-z0-9_\-./]*graphql[A-Za-z0-9_\-./]*)[\"'`]", js_text)
        fp["graphql_hint"] = m.group(1) if m else "referenced in bundles"
        notes.append("GraphQL is referenced in the bundles but the standard paths did not answer: settle `graphql` by hand")
    if re.search(r"wss?://|new WebSocket\(|socket\.io|sockjs|signalr|ActionCable", js_text):
        setf("websocket", True, "WebSocket client code in the bundles")
    if re.search(r"addEventListener\(\s*[\"']message[\"']|\.postMessage\(|onmessage\s*=", js_text):
        setf("postmessage", True, "message listener or postMessage call in the bundles")
    sm = STORAGE.search(hay)
    if sm:
        setf("cloud-storage", True, f"storage host in page or bundles: {sm.group(0)}")
    jm = JWT_RE.search(hay + " " + hd.get("set-cookie", ""))
    if jm or re.search(r"jwt|id_token|access_token|Bearer ", js_text):
        setf("jwt", True, "JWT in a response or cookie" if jm else "token handling (jwt/access_token/Bearer) in the bundles")
    if SERIAL_RE.search(hay + " " + hd.get("set-cookie", "")):
        setf("serialized", True, "serialized-object marker in page, bundle or cookie")
    if AI_HINT.search(hay):
        setf("ai-feature", True, "LLM/assistant endpoint or widget referenced")
    if re.search(r"type=[\"']file[\"']|multipart/form-data|FormData\(\)|dropzone|uploadFile|presigned", js_text, re.I):
        setf("upload", True, "upload code in the bundles")
    if re.search(r"/(login|signin|sign-in|auth/login|oauth/token|session)\b|password", js_text, re.I) and spa:
        setf("login", True, "authentication routes in the bundles")
    if re.search(r"redirect_uri|response_type=|/oauth2?/authorize|openid", js_text):
        setf("oauth-login", True, "OAuth client parameters in the bundles")
    if REDIRECT_PARAMS.search(js_text[:2_000_000]):
        setf("redirect-param", True, "redirect-style parameter in the bundles")

    # ---- http version
    try:
        hv = subprocess.run(["curl", "-sk", "-o", "/dev/null", "--http2", "-m", "10", "-w", "%{http_version}", base + "/"],
                            capture_output=True, text=True, timeout=15).stdout.strip()
        c.count += 1
        if hv:
            setf("http2", hv.startswith("2") or hv.startswith("3"), f"curl negotiated HTTP/{hv}")
    except Exception:
        pass

    # ---- derive kind
    for t in tech:
        tag = TECH_FACT.get(t["name"])
        if tag:
            setf(tag, True, f"{t['name']} ({t['source']})")
        if t["name"] in CMS:
            setf("cms", True, f"{t['name']} ({t['source']})")
        if t["name"] == "spring_boot":
            setf("spring", True, t["source"])
        if t["name"] not in GENERIC_SERVERS or t["version"]:
            setf("known-product", True, f"{t['name']} {t['version']}".strip() + f" ({t['source']})")
    json_root = "json" in fp["content_type"] or body.lstrip()[:1] in ("{", "[")
    if json_root:
        setf("api", True, "/ returns JSON")
    dynamic = bool(all_cookies) or has_pw or bool(forms) or spa or json_root or bool(api_paths) or \
        any(facts.get(t, (False,))[0] for t in ("login", "graphql", "api-docs", "reflect", "upload", "wordpress"))
    red_only = facts.get("redirect-only", (False,))[0]
    if red_only or is_default:
        setf("app", False, "redirect-only" if red_only else "default page")
        setf("static", False, "redirect-only" if red_only else "default page")
        fp["tier"] = "redirect" if red_only else "default"
    elif dynamic:
        setf("app", True, "; ".join(x for x in [f"cookies {all_cookies[:3]}" if all_cookies else "", "password field" if has_pw else "",
                                                f"{len(forms)} forms" if forms else "", "SPA" if spa else "",
                                                "API paths in bundles" if api_paths else ""] if x) or "dynamic markers")
        setf("static", False, "dynamic markers present")
        fp["tier"] = "api" if (json_root and not forms and not spa) else "app"
    else:
        setf("static", True, f"no cookies, forms, SPA shell or API paths; {text_len} characters of text")
        setf("app", False, "no dynamic markers found without authentication (re-check after browsing)")
        fp["tier"] = "static"
    fp["notes"] = notes
    return {"fp": fp, "facts": facts, "tech": tech, "requests": c.count}

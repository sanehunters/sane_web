#!/usr/bin/env python3
"""A local stand-in target for scripts/selftest.sh: a login form, a GraphQL endpoint, an OpenAPI file and a
reflected parameter, on 127.0.0.1 only. It exists to exercise the fingerprinter and planner offline."""
import http.server, json, sys, urllib.parse

PAGE = """<!doctype html><html><head><title>Demo Shop</title><meta name="generator" content="WordPress 6.1.1"></head>
<body><div id="root"></div><form method="post" action="/login"><input name="user"><input type="password" name="pw"></form>
<a href="/go?next=/home">continue</a><a href="/download?file=report.pdf">report</a>
<script src="/static/app.js"></script><p>q=%s</p></body></html>"""
JS = """const api="/api/v1/users/{id}";fetch("/api/v1/orders");window.addEventListener("message",e=>{});
const ws=new WebSocket("wss://127.0.0.1/ws");const b="https://demo-uploads.s3.amazonaws.com/x";//# sourceMappingURL=app.js.map"""


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="text/html", extra=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Server", "nginx/1.18.0")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            self.send(200, PAGE % q.get("q", [""])[0], extra={"Set-Cookie": "PHPSESSID=abc; HttpOnly"})
        elif u.path == "/static/app.js":
            self.send(200, JS, "application/javascript")
        elif u.path == "/openapi.json":
            self.send(200, json.dumps({"openapi": "3.0.0", "paths": {"/api/v1/users/{id}": {}}}), "application/json")
        else:
            self.send(404, "<html><head><title>Not here</title></head><body>nope</body></html>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if self.path == "/graphql":
            self.send(200, json.dumps({"data": {"__typename": "Query"}}), "application/json")
        else:
            self.send(404, "nope")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()

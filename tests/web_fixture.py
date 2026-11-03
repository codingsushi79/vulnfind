"""A deliberately vulnerable local website for testing `vulnfind web`.

Run standalone:  python3 tests/web_fixture.py 8090   then   vulnfind web http://127.0.0.1:8090 --active
"""

import html
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = """<!doctype html><html><head><title>Shop</title>
<meta name="generator" content="WordPress 4.9.8">
<script src="/static/jquery-1.12.4.min.js"></script>
<script src="/static/app.js"></script>
<script src="https://cdn.thirdparty.example/widget.js"></script>
</head><body>
<!-- TODO remove: admin password is in /config -->
<a href="/about">About</a> <a href="/search?q=shoes">Search</a> <a href="/item?id=1">Item</a>
<a href="/go?next=/home">Home</a> <a href="/safe-search?q=x">Safe</a> <a href="/logout">Log out</a> <a href="mailto:x@example.com">mail</a>
<form action="/login" method="get"><input name="user"><input type="password" name="pw"></form>
</body></html>"""

APP_JS = """(function(){var cfg={region:"us-east-1",key:"AKIAQ3EGRQFAKE7DEMO1"};window.cfg=cfg;})();
//# sourceMappingURL=app.js.map"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"
    sys_version = ""
    soft404 = False
    requested = []  # every path+query the scanner asked for (tests inspect this)

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/7.2.1")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(200, "", extra={"Allow": "GET, POST, OPTIONS, TRACE, PUT"})

    def do_GET(self):
        type(self).requested.append(self.path)
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        path = u.path
        if self.soft404:
            return self._send(200, "<html><body>Welcome! Everything is fine.</body></html>")
        if path == "/":
            return self._send(200, INDEX, extra={"Set-Cookie": "sessionid=abc123def456; Path=/"})
        if path == "/about":
            return self._send(200, "<html><body><a href='/'>home</a> About us</body></html>")
        if path == "/search":
            return self._send(200, f"<html><body>Results for {q.get('q', '')}</body></html>")  # unescaped!
        if path == "/safe-search":
            return self._send(200, f"<html><body>Results for {html.escape(q.get('q', ''))}</body></html>")
        if path == "/item":
            if "'" in q.get("id", ""):
                return self._send(500, "<html><body>You have an error in your SQL syntax; check the manual</body></html>")
            return self._send(200, "<html><body>Item 1</body></html>")
        if path == "/go":
            return self._send(302, "", extra={"Location": q.get("next", "/")})
        if path == "/login":
            return self._send(200, "<html><body>bad login</body></html>")
        if path == "/logout":
            return self._send(200, "<html><body>logged out</body></html>")
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/static/app.js.map":
            return self._send(200, json.dumps({"version": 3, "sources": ["src/app.ts"], "mappings": "AAAA"}), "application/json")
        if path == "/static/jquery-1.12.4.min.js":
            return self._send(200, "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */!function(){}();", "application/javascript")
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if path == "/.env":
            return self._send(200, "APP_ENV=production\nDB_PASSWORD=hunter2hunter2\n", "text/plain")
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin-backup/\n", "text/plain")
        return self._send(404, "<html><body><h1>Not Found</h1><pre>Traceback (most recent call last):\n  File \"app.py\"</pre></body></html>")


class Soft404Handler(Handler):
    soft404 = True


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def shutdown(self):
        super().shutdown()
        self.server_close()


def serve(handler=Handler, port: int = 0):
    srv = _Server(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


if __name__ == "__main__":
    srv, url = serve(port=int(sys.argv[1]) if len(sys.argv) > 1 else 8090)
    print(f"vulnerable test site on {url}  (Ctrl-C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()

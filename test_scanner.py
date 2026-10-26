"""Offline tests using local vulnerable and hardened HTTP servers."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import scanner


class Vulnerable(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Server", "Apache/2.4.1")
        self.send_header("Set-Cookie", "sid=abc123")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a): pass


class Hardened(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        for k, v in {"Content-Security-Policy": "default-src 'self'",
                     "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                     "Referrer-Policy": "no-referrer", "Permissions-Policy": "geolocation=()"}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a): pass


def serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/"


def test_vulnerable_server_flagged():
    srv, url = serve(Vulnerable)
    r = scanner.scan(url)
    srv.shutdown()
    titles = " ".join(f.title for f in r.findings)
    assert any(f.severity == "CRITICAL" for f in r.findings)
    assert "WITH credentials" in titles
    assert "Missing header: Content-Security-Policy" in titles
    assert "missing HttpOnly" in titles
    assert r.grade in ("D", "F")


def test_hardened_server_scores_well():
    srv, url = serve(Hardened)
    r = scanner.scan(url)
    srv.shutdown()
    assert not any(f.check == "cors" for f in r.findings)
    assert r.score >= 80


def test_unreachable_target():
    r = scanner.scan("http://127.0.0.1:1/", timeout=2)
    assert r.error and r.grade == "N/A"


def test_permission_flag_required():
    assert scanner.main(["http://127.0.0.1:1/"]) == 2

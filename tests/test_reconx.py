import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from reconx import report
from reconx.core import run_assessment
from reconx.modules import network, web
from reconx.safety import ScopeError, parse_target, require_lab_scope


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class ReconXTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_parse_target(self):
        t = parse_target("127.0.0.1:3000")
        self.assertEqual((t["host"], t["port"], t["is_ip"]), ("127.0.0.1", 3000, True))
        for bad in ("", "ftp://x.com", "http://u:p@x.com", "http://x.com:99999"):
            with self.assertRaises(ScopeError):
                parse_target(bad)

    def test_lab_scope(self):
        require_lab_scope("127.0.0.1")
        with mock.patch("reconx.safety.resolve_ips", return_value=["8.8.8.8"]):
            with self.assertRaises(ScopeError):
                require_lab_scope("example.com")

    def test_authorization_required(self):
        with self.assertRaises(ScopeError):
            run_assessment(self.url, ["web"], authorized=False)

    def test_web_findings(self):
        titles = [f["title"] for f in web.scan_web(self.url)["findings"]]
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Permissive CORS policy", titles)
        self.assertTrue(any("Cookie 'sid'" in t for t in titles))
        self.assertTrue(any("Server header" in t for t in titles))

    def test_network_scan(self):
        result = network.scan_network("127.0.0.1", [self.port, 1])
        self.assertEqual([p["port"] for p in result["open_ports"]], [self.port])

    def test_port_parsing(self):
        self.assertEqual(network.parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])
        with self.assertRaises(ValueError):
            network.parse_ports("0")
        with self.assertRaises(ValueError):
            network.parse_ports("1-5000")

    def test_full_run_and_reports(self):
        a = run_assessment(self.url, ["dns", "tls", "web", "network"], authorized=True,
                           ports=[self.port])
        self.assertIn("dns", a["errors"])   # IP target
        self.assertIn("tls", a["errors"])   # not https
        with tempfile.TemporaryDirectory() as tmp:
            jp, hp = report.save_reports(a, tmp)
            self.assertEqual(json.loads(jp.read_text())["tool"], "ReconX")
            self.assertIn("ReconX Assessment Report", hp.read_text())

    def test_html_escaping(self):
        a = {"tool": "ReconX", "target": "x", "host": "x", "results": [{"module": "web", "findings": [{
            "module": "web", "title": "<script>alert(1)</script>", "severity": "low",
            "confidence": "high", "location": "x", "evidence": "x", "impact": "x",
            "recommendation": "x"}]}], "errors": {}}
        self.assertNotIn("<script>alert(1)</script>", report.render_html(a))

    def test_dashboard(self):
        import app as dash
        client = dash.app.test_client()
        page = client.get("/").get_data(as_text=True)
        token = page.split('name="csrf" value="')[1].split('"')[0]
        bad = client.post("/scan", data={"csrf": "wrong", "target": self.url})
        self.assertEqual(bad.status_code, 400)
        noauth = client.post("/scan", data={"csrf": token, "target": self.url, "modules": "web"})
        self.assertEqual(noauth.status_code, 400)
        self.assertIn("Authorization", noauth.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()

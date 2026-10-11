"""
The local UI server's guards (glitched.web), against a real server on a free
port: only this page, with the start-up key, on 127.0.0.1, can use the API.
No database needed - only /api/state and static files are requested.
"""

import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from glitched import web

TOKEN = "test-token-123"


class WebGuardsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        cls.port = cls.server.server_address[1]
        cls.server.RequestHandlerClass = web.make_handler(web.Api("postgresql://unused/none"), TOKEN, cls.port)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        merged = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        conn.request(method, path, body=body, headers=merged)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response, data

    def cookie(self):
        return {"Cookie": f"{web.COOKIE}={TOKEN}"}

    def test_no_key_no_access(self):
        for path in ("/", "/api/state", "/app.js"):
            self.assertEqual(self.request("GET", path)[0].status, 403, path)

    def test_wrong_key_refused(self):
        self.assertEqual(self.request("GET", "/?token=wrong")[0].status, 403)
        self.assertEqual(self.request("GET", "/api/state", {"Cookie": f"{web.COOKIE}=wrong"})[0].status, 403)

    def test_key_becomes_a_strict_cookie(self):
        response, _ = self.request("GET", f"/?token={TOKEN}")
        self.assertEqual(response.status, 303)
        cookie = response.getheader("Set-Cookie")
        for part in (f"{web.COOKIE}={TOKEN}", "HttpOnly", "SameSite=Strict"):
            self.assertIn(part, cookie)

    def test_foreign_host_refused(self):
        # DNS rebinding: another site's name pointing at 127.0.0.1.
        response, _ = self.request("GET", "/api/state", {"Host": f"evil.example:{self.port}", **self.cookie()})
        self.assertEqual(response.status, 421)

    def test_cross_origin_writes_refused(self):
        response, _ = self.request("POST", "/api/acknowledge",
                                   {"Origin": "http://evil.example", "Content-Type": "application/json",
                                    **self.cookie()}, body=b'{"accept": true}')
        self.assertEqual(response.status, 403)

    def test_with_key(self):
        response, data = self.request("GET", "/api/state", self.cookie())
        self.assertEqual(response.status, 200)
        self.assertIn("acknowledged", json.loads(data))
        response, data = self.request("GET", "/", self.cookie())
        self.assertEqual(response.status, 200)
        self.assertIn(b"Glitched", data)
        self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))

    def test_no_files_outside_the_page(self):
        for path in ("/../web.py", "/%2e%2e/web.py", "/..%2fweb.py", "/web_static/../web.py"):
            self.assertEqual(self.request("GET", path, self.cookie())[0].status, 404, path)

    def test_library_and_photos(self):
        response, data = self.request("GET", "/api/library", self.cookie())
        self.assertEqual(response.status, 200)
        self.assertGreaterEqual(len(json.loads(data)), 6)
        response, data = self.request("GET", "/library/renders/arm.png", self.cookie())
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "image/png")

    def test_uploads_must_be_images(self):
        # Checked before the database is touched (there is none here).
        upload = {"Content-Type": "image/png", **self.cookie()}
        response, data = self.request("POST", "/api/robots/1/image", upload,
                                      body=b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>')
        self.assertEqual(response.status, 400)
        self.assertIn(b"PNG, JPEG or WebP", data)

    def test_uploads_have_a_size_limit(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/api/robots/1/image", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("Cookie", f"{web.COOKIE}={TOKEN}")
        conn.putheader("Content-Length", str(9 * 1024 * 1024))
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 413)
        conn.close()

    def test_page_files_are_fixed_at_start_up(self):
        # A running server keeps serving the page that matches its code, even if files change on disk.
        static = web.load_static()
        self.assertIn("index.html", static)
        self.assertIn("library/library.json", static)
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        port = server.server_address[1]
        server.RequestHandlerClass = web.make_handler(web.Api("postgresql://unused/none"), TOKEN, port,
                                                      static={**static, "app.js": b"// the version at start-up"})
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/app.js", headers={"Host": f"127.0.0.1:{port}", "Cookie": f"{web.COOKIE}={TOKEN}"})
            self.assertEqual(conn.getresponse().read(), b"// the version at start-up")
        finally:
            server.shutdown()
            server.server_close()

    def test_acknowledging_needs_the_box_ticked(self):
        response, data = self.request("POST", "/api/acknowledge",
                                      {"Content-Type": "application/json", **self.cookie()}, body=b"{}")
        self.assertEqual(response.status, 400)


if __name__ == "__main__":
    unittest.main()

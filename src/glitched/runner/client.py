"""
Talking to the console: JSON over HTTPS, outbound only (the runner never
listens on a port). Certificates are verified; plain HTTP is accepted only
when pairing explicitly allowed it (local development).
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

import glitched
from glitched.runner import PROTOCOL

USER_AGENT = f"glitched-runner/{glitched.__version__}"


class ConsoleError(Exception):
    def __init__(self, status: int, message: str, body: dict | None = None):
        super().__init__(message)
        self.status, self.message, self.body = status, message, body or {}


def check_console_url(url: str, allow_http: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.netloc or parts.path not in ("", "/"):
        raise ValueError(f"the console address should look like https://console.example.com, not {url!r}")
    if parts.scheme == "http" and not allow_http:
        raise ValueError("the console address must use https (--allow-http is for local development only)")
    return f"{parts.scheme}://{parts.netloc}"


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would carry the runner's token to another address."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl} refused", headers, fp)


class Client:
    def __init__(self, console: str, token: str | None = None, allow_http: bool = False):
        self.console = check_console_url(console, allow_http)
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                                                  _NoRedirects())

    def post(self, path: str, body: dict[str, Any], timeout: float = 40) -> tuple[int, dict[str, Any]]:
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT,
                   "X-Glitched-Runner-Protocol": str(PROTOCOL)}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(f"{self.console}{path}", data=json.dumps(body).encode(), headers=headers,
                                         method="POST")
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read(1024 * 1024)
                return response.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            try:
                data = json.loads(exc.read(64 * 1024) or b"{}")
            except (json.JSONDecodeError, OSError):
                data = {}
            raise ConsoleError(exc.code, data.get("error") or f"the console answered {exc.code}", data) from None

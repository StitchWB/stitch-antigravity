"""Google OAuth 2.0 authorization-code flow with PKCE over a loopback redirect.

Zone-1: plain stdlib only (no stitch_backend imports, no third-party deps).
The loopback receiver binds 127.0.0.1 on an ephemeral port; Google redirects
the browser to ``http://127.0.0.1:<port>/callback`` once the user completes
the sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import urllib.parse
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPE = "openid email profile"
CALLBACK_PATH = "/callback"


def generate_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` with the S256 method."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(
    config: dict[str, Any], *, redirect_uri: str, state: str, code_challenge: str
) -> str:
    query = {
        "client_id": config["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": config.get("scope") or DEFAULT_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    base = str(config.get("auth_url") or AUTHORIZE_URL)
    return f"{base}?{urllib.parse.urlencode(query)}"


def exchange_code(
    config: dict[str, Any], *, code: str, redirect_uri: str, code_verifier: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Trade the authorization code for tokens at the token endpoint."""
    body = {
        "client_id": config["client_id"],
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if config.get("client_secret"):
        body["client_secret"] = config["client_secret"]
    req = urllib.request.Request(
        str(config.get("token_url") or TOKEN_URL),
        data=urllib.parse.urlencode(body).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or not data.get("access_token"):
        raise ValueError("token endpoint returned no access_token")
    return data


class LoopbackReceiver:
    """One-shot localhost HTTP server receiving the OAuth redirect.

    The callback runs on the request-handler thread (ThreadingHTTPServer),
    so ``stop()`` may be called from inside it without deadlocking
    ``serve_forever``.
    """

    def __init__(
        self, on_callback: Callable[[str, str, str], None]
    ) -> None:
        self._on_callback = on_callback
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="oauth-loopback", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._thread = None

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        receiver = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != CALLBACK_PATH:
                    self.send_response(404)
                    self.end_headers()
                    return
                params = urllib.parse.parse_qs(parsed.query)
                code = params.get("code", [""])[0]
                state = params.get("state", [""])[0]
                error = params.get("error", [""])[0]
                # Invoke the callback BEFORE answering so the page reflects
                # the outcome and tests observe the terminal state right
                # after urlopen returns.
                receiver._on_callback(state, code, error)
                body = (
                    b"<html><body><p>You can close this tab and return to"
                    b" Stitch.</p></body></html>"
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        return _Handler

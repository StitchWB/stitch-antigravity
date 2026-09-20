"""Antigravity auth service — Google OAuth flow + auth-file scanning.

The plugin runs out-of-process (stdio JSON-RPC, single-threaded sync serve
loop); the OAuth loopback callback arrives on the receiver's HTTP handler
thread, so session transitions are guarded by ``_state_lock``.

Wire constraint (vendored rpc_server._send_response): any result dict with a
top-level ``error`` key becomes a JSON-RPC error response — the host surfaces
it as RpcCallError, never a traceback.  ``auth_flow_start`` uses this for the
``oauth_not_configured`` case.  Every OTHER command must therefore keep the
``error`` key out of its results; flow failures surface via ``errorMessage``.

The auth-file scanner reads STITCH_AUTH_DIR / STITCH_CONFIG_DIR from the
environment: the plugin child runs with a sandbox-scoped USERPROFILE, so the
real home dirs are resolved and injected by the core
(``antigravity_child_env`` in the hub).  Without them the scan returns [].
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import oauth

logger = logging.getLogger(__name__)

PROVIDER_ID = "antigravity"
PROVIDER_NAME = "Antigravity"
OAUTH_PROVIDER_NAME = "Google"

_OAUTH_CONFIG_FILE = "oauth_config.json"
_SESSION_FILE = "oauth_session.json"
_AUTH_FILE_NAME = "antigravity-oauth.json"
_SESSION_TTL_SECONDS = 600
_EXPIRY_SOON_SECONDS = 24 * 60 * 60

_state_lock = threading.Lock()
_data_dir: Path | None = None
_session: dict[str, Any] | None = None
_receiver: oauth.LoopbackReceiver | None = None


def configure(data_dir: str) -> None:
    """Bind the plugin data dir (called from the plugin.init handler)."""
    global _data_dir, _session
    _stop_receiver()
    with _state_lock:
        _session = None
        _data_dir = Path(data_dir) if data_dir else None
        if _data_dir is not None:
            _data_dir.mkdir(parents=True, exist_ok=True)


# ── OAuth config ─────────────────────────────────────────────────────────────


def _load_oauth_config() -> dict[str, Any] | None:
    if _data_dir is None:
        return None
    try:
        raw = json.loads((_data_dir / _OAUTH_CONFIG_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or not str(raw.get("client_id", "")).strip():
        return None
    return raw


def get_oauth_config(params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Display data for the core OAuthFlowWizard."""
    return {
        "providerId": PROVIDER_ID,
        "providerName": PROVIDER_NAME,
        "oauthProviderName": OAUTH_PROVIDER_NAME,
        "configured": _load_oauth_config() is not None,
    }


# ── Session persistence (transient — JSON in the plugin data dir) ────────────


def _write_session(session: dict[str, Any]) -> None:
    if _data_dir is None:
        return
    try:
        (_data_dir / _SESSION_FILE).write_text(
            json.dumps(session, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        logger.warning("failed to persist oauth session", exc_info=True)


# ── Auth flow ────────────────────────────────────────────────────────────────


def auth_flow_start(params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Start the Google OAuth flow: bind the loopback receiver, return the
    authorize URL.  Clean structured error when no client creds are
    configured."""
    global _session, _receiver
    config = _load_oauth_config()
    if config is None:
        detail_dir = str(_data_dir) if _data_dir is not None else "<no data dir>"
        return {
            "error": "oauth_not_configured",
            "detail": (
                f"missing or incomplete {_OAUTH_CONFIG_FILE} (client_id) in {detail_dir}"
            ),
        }

    _stop_receiver()
    verifier, challenge = oauth.generate_pkce()
    oauth_state = secrets.token_urlsafe(16)

    with _state_lock:
        _session = None
    receiver = oauth.LoopbackReceiver(
        lambda state, code, error: _on_callback(state, code, error)
    )
    receiver.start()
    redirect_uri = f"http://127.0.0.1:{receiver.port}{oauth.CALLBACK_PATH}"

    now = int(time.time())
    session: dict[str, Any] = {
        "session_id": f"ag_{uuid.uuid4().hex[:16]}",
        "oauth_state": oauth_state,
        "phase": "pending",
        "error": None,
        "port": receiver.port,
        "code_verifier": verifier,
        "created_at": now,
        "expires_at": now + _SESSION_TTL_SECONDS,
    }
    with _state_lock:
        _session = session
        _receiver = receiver
    _write_session(session)

    url = oauth.build_authorize_url(
        config,
        redirect_uri=redirect_uri,
        state=oauth_state,
        code_challenge=challenge,
    )
    return {
        "sessionId": session["session_id"],
        "authUrl": url,
        "state": "pending",
        "callbackPort": receiver.port,
        "expiresAt": session["expires_at"],
    }


def auth_flow_status(params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Poll the current flow session.  Never raises; unknown session ids get
    phase ``unknown``."""
    params = params or {}
    session_id = str(params.get("sessionId") or params.get("session_id") or "")
    with _state_lock:
        session = _session
    if session is None or (session_id and session["session_id"] != session_id):
        return {
            "sessionId": session_id,
            "provider": PROVIDER_ID,
            "phase": "unknown",
            "state": "",
            "expiresAt": 0,
        }
    if session["phase"] == "pending" and session["expires_at"] <= int(time.time()):
        with _state_lock:
            session["phase"] = "expired"
        _write_session(session)
    result: dict[str, Any] = {
        "sessionId": session["session_id"],
        "provider": PROVIDER_ID,
        "phase": session["phase"],
        "state": session["oauth_state"],
        "expiresAt": session["expires_at"],
    }
    if session.get("error"):
        result["errorMessage"] = session["error"]
    return result


def auth_flow_cancel(params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cancel the pending flow: stop the loopback server, mark cancelled.
    Terminal phases (token_ready/failed/expired) are left untouched."""
    _stop_receiver()
    with _state_lock:
        session = _session
        if session is not None and session["phase"] == "pending":
            session["phase"] = "cancelled"
    if session is not None:
        _write_session(session)
    return {"cancelled": True}


def _stop_receiver() -> None:
    global _receiver
    with _state_lock:
        receiver = _receiver
        _receiver = None
    if receiver is not None:
        receiver.stop()


def _on_callback(state: str, code: str, error: str) -> None:
    with _state_lock:
        session = _session
    if session is None:
        return
    if error:
        _finish(session, phase="failed", error=error)
        return
    if state != session["oauth_state"]:
        _finish(session, phase="failed", error="state_mismatch")
        return
    config = _load_oauth_config()
    if config is None:
        _finish(session, phase="failed", error="oauth_not_configured")
        return
    redirect_uri = f"http://127.0.0.1:{session['port']}{oauth.CALLBACK_PATH}"
    try:
        tokens = oauth.exchange_code(
            config,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=session["code_verifier"],
        )
    except Exception as exc:  # noqa: BLE001 — surfaced as the flow error
        _finish(session, phase="failed", error=str(exc))
        return
    expires_at = int(time.time()) + int(tokens.get("expires_in", 3600))
    _write_auth_file(tokens, expires_at)
    _finish(session, phase="token_ready")


def _finish(session: dict[str, Any], *, phase: str, error: str | None = None) -> None:
    with _state_lock:
        session["phase"] = phase
        session["error"] = error
    _write_session(session)
    _stop_receiver()


def _write_auth_file(tokens: dict[str, Any], expires_at: int) -> None:
    target_dir = os.environ.get("STITCH_AUTH_DIR", "").strip()
    root = Path(target_dir) if target_dir else _data_dir
    if root is None:
        return
    payload: dict[str, Any] = {
        "provider": PROVIDER_ID,
        "token": tokens["access_token"],
        "expiresAt": expires_at,
    }
    if tokens.get("refresh_token"):
        payload["refreshToken"] = tokens["refresh_token"]
    try:
        root.mkdir(parents=True, exist_ok=True)
        path = root / _AUTH_FILE_NAME
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        logger.warning("failed to write antigravity auth file", exc_info=True)


# ── Auth-file scanning ────────────────────────────────────────────────────────


def _scan_dirs() -> list[Path]:
    dirs: list[Path] = []
    for var in ("STITCH_AUTH_DIR", "STITCH_CONFIG_DIR"):
        raw = os.environ.get(var, "").strip()
        if raw:
            dirs.append(Path(raw))
    return dirs


def _expiry_status(expires_at: int | None) -> str:
    if expires_at is None:
        return "unknown"
    now = int(time.time())
    if expires_at <= now:
        return "expired"
    if expires_at <= now + _EXPIRY_SOON_SECONDS:
        return "expiring"
    return "valid"


def _format_expiry(expires_at: int | None) -> str:
    if expires_at is None:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(expires_at))


def list_auth_files(params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Scan the injected auth/config dirs for Antigravity auth JSON files."""
    rows: list[dict[str, Any]] = []
    for root in _scan_dirs():
        if not root.is_dir():
            continue
        for f in sorted(root.iterdir()):
            if not f.is_file() or f.suffix != ".json":
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            if str(data.get("provider", "")).lower() != PROVIDER_ID:
                continue
            token = data.get("token") or data.get("apiKey") or data.get("api_key") or ""
            if not token:
                continue
            raw_expiry = data.get("expiresAt") or data.get("expires_at")
            expires_at = raw_expiry if isinstance(raw_expiry, (int, float)) else None
            rows.append({
                "path": str(f),
                "expiresAt": _format_expiry(int(expires_at)) if expires_at else "",
                "status": _expiry_status(int(expires_at) if expires_at else None),
            })
    return rows

"""RPC entry point for the stitch-antigravity service plugin.

Spawned by ``ServicePluginHost`` as ``python -m stitch_antigravity``.
Implements the JSON-RPC 2.0 line protocol via ``RpcPluginServer``
(imported from ``autoreg.plugin.rpc`` when available, otherwise from
the vendored ``_vendor/rpc_server.py`` copy).

Commands are served under the ``plugin.stitch-antigravity.*`` namespace.
"""

from __future__ import annotations

from typing import Any

from . import service

try:
    from autoreg.plugin.rpc import RpcPluginServer
except ImportError:
    from ._vendor.rpc_server import RpcPluginServer


class _Ctx:
    """Mutable container for plugin.init handshake state."""

    db_path: str = ""
    data_dir: str = ""


ctx = _Ctx()


def _handle_init(params: dict[str, Any]) -> dict[str, Any]:
    """Store handshake params and return them as the init result."""
    ctx.db_path = str(params.get("db_path", ""))
    ctx.data_dir = str(params.get("data_dir", ""))
    service.configure(ctx.data_dir)
    return {
        "plugin_id": params.get("plugin_id", ""),
        "db_path": ctx.db_path,
        "data_dir": ctx.data_dir,
        "capabilities": [],
    }


def _handle_migrate_db(params: dict[str, Any]) -> dict[str, Any]:
    """No-op migration (storage.sqlite=false). Returns version ack."""
    return {
        "from_version": params.get("from_version", 0),
        "to_version": params.get("to_version", 1),
    }


def _handle_auth_flow_start(params: dict[str, Any]) -> dict[str, Any]:
    return service.auth_flow_start(params)


def _handle_auth_flow_status(params: dict[str, Any]) -> dict[str, Any]:
    return service.auth_flow_status(params)


def _handle_auth_flow_cancel(params: dict[str, Any]) -> dict[str, Any]:
    return service.auth_flow_cancel(params)


def _handle_list_auth_files(params: dict[str, Any]) -> list[dict[str, Any]]:
    return service.list_auth_files(params)


def _handle_get_oauth_config(params: dict[str, Any]) -> dict[str, Any]:
    return service.get_oauth_config(params)


def main() -> None:
    """Register handlers and serve the JSON-RPC loop."""
    server = RpcPluginServer()
    server.set_init_handler(_handle_init)
    server.register("_migrate_db", _handle_migrate_db)
    server.register("auth_flow_start", _handle_auth_flow_start)
    server.register("auth_flow_status", _handle_auth_flow_status)
    server.register("auth_flow_cancel", _handle_auth_flow_cancel)
    server.register("list_auth_files", _handle_list_auth_files)
    server.register("get_oauth_config", _handle_get_oauth_config)
    server.serve()


if __name__ == "__main__":
    main()

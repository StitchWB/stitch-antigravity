# stitch-antigravity

Service plugin for [Stitch Manager](https://github.com/StitchWB/Stitch-Manager):
Google OAuth sign-in (authorization-code flow with PKCE over a loopback
redirect) for Antigravity, plus scanning of local Antigravity auth files.

## Commands (`plugin.stitch-antigravity.*`)

| Command            | readonly | Description                                              |
| ------------------ | :------: | -------------------------------------------------------- |
| `auth_flow_start`  |    no    | Start the OAuth flow; returns `authUrl` + callback port. |
| `auth_flow_status` |   yes    | Poll the flow phase (`pending` → `token_ready` / ...).   |
| `auth_flow_cancel` |    no    | Cancel the pending flow; stops the loopback server.      |
| `list_auth_files`  |   yes    | List detected Antigravity auth files.                    |
| `get_oauth_config` |   yes    | Provider display data + whether OAuth is configured.     |

## OAuth configuration

`auth_flow_start` returns a structured `oauth_not_configured` error until
client credentials exist in `<plugin data dir>/oauth_config.json`:

```json
{
  "client_id": "….apps.googleusercontent.com",
  "client_secret": "… (optional for public clients)",
  "scope": "openid email profile (optional override)"
}
```

On completion the received tokens are written as an auth file into the
core-injected `STITCH_AUTH_DIR` (or the plugin data dir as a fallback).

## Layout

- `plugin.json` — manifest (schema `stitch.plugin/v2`, kind `service`)
- `stitch_antigravity/` — package (`__main__.py` RPC handlers, `service.py`
  flow/session logic, `oauth.py` Google OAuth + loopback receiver,
  `_vendor/rpc_server.py` vendored JSON-RPC server)

# Protocol Notes

This document records protocol decisions made while implementing `chat`.

## V1 Framing

Application packets use the V1 binary header from `spec.md`:

```text
+----------+----------+-------------+----------------+
| version  | type     | length      | payload        |
| uint8    | uint8    | uint32 BE   | length bytes   |
+----------+----------+-------------+----------------+
```

The implementation validates version, packet type, and payload length before using a packet.

## Local Identity

`chat init <username>` creates a long-term Ed25519 account identity with libsodium:

- `identity.key`: raw `crypto_sign_SECRETKEYBYTES`, mode `0600`
- `identity.pub`: raw `crypto_sign_PUBLICKEYBYTES`
- `config.toml`: username and local server URL placeholder

The default config directory is `~/.config/chat` on Linux and
`~/Library/Application Support/chat` on macOS. Tests can override it with
`CHAT_CONFIG_DIR`.

The displayed fingerprint is a BLAKE2b hash of the Ed25519 public key, formatted
as uppercase colon-separated hex.

## Control Server V1

`chat-server` exposes a WebSocket protocol named `chat-control-v1` on port
`8787` by default. The current V1 server keeps users in memory and supports:

- `register`: `{ "type": "register", "username": "...", "public_key": "<hex Ed25519 pk>" }`
- `hello`: `{ "type": "hello", "username": "..." }`
- `auth_response`: `{ "type": "auth_response", "signature": "<hex detached signature>" }`
- `user_lookup`: `{ "type": "user_lookup", "username": "..." }`

The server answers `hello` with an `auth_challenge` containing 32 random bytes in
hex. The client must sign those exact challenge bytes with its Ed25519 account
secret key. Only authenticated WebSocket sessions can use `user_lookup`.

This implementation does not persist server registrations yet; that belongs with
the later production storage work. The control server still never accepts or
stores chat plaintext.

## Daemon Presence

`chatd` now loads the local identity and `server_url` from `config.toml`, opens a
WebSocket client connection, and performs the development control-plane flow:

1. `register` with username and Ed25519 public key.
2. `hello` with username.
3. Sign the server challenge using `crypto_sign_detached`.
4. Enter the online state after `auth_ok`.

Because server registrations are still in memory, `chatd` accepts
`user already exists` during the register phase and continues to authentication.
Future persistence will remove the need to re-register after every server start.

## Local IPC

`chat` talks to `chatd` over a Unix domain socket. The path is resolved in this
order:

1. `CHAT_SOCKET_PATH` when set, useful for tests.
2. `$XDG_RUNTIME_DIR/chatd.sock`.
3. `<chat config dir>/chatd.sock`.

The first implemented command is:

```text
STATUS
```

The daemon responds with one line:

```text
ONLINE alex
CONNECTING alex
OFFLINE alex
```

The socket file is created with mode `0600` and removed when `chatd` exits
normally.

`OPEN_CHAT <username>` is also accepted by `chatd`. It sends a server-backed
`chat_request` when the daemon is online and keeps the CLI socket open until the
peer accepts or the server reports the peer offline:

```text
USER_OFFLINE nathan
USER_ONLINE nathan
ERROR daemon_not_online
```

The CLI maps `USER_ONLINE` to the current step-7 limitation:
`<peer> is online, but the connection could not be established.` ICE is the next
missing piece.

## Signalling Relay

The control server now relays authenticated signalling JSON between online
users. Supported message types:

```text
chat_request
chat_accept
chat_reject
ice_credentials
ice_candidate
ice_done
ice_gathering_done
chat_end
chat_cancel
```

Every relayed message must include:

```json
{
  "type": "chat_request",
  "from": "alex",
  "to": "nathan",
  "session_id": "random-session-id"
}
```

The server verifies that `from` matches the authenticated WebSocket session
before forwarding. If the destination is unknown or offline, the sender receives
`{"type":"error","code":"peer_offline"}`. The server does not inspect ICE payload
fields beyond the routing metadata and still never receives chat plaintext.

`chatd` currently accepts incoming `chat_request` automatically by replying with
`chat_accept`, which matches the V1 shortcut before contact prompts and ICE are
implemented.

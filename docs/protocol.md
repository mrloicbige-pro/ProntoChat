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
- `contacts.db`: pinned peer Ed25519 public keys, mode `0600`

The default config directory is `~/.config/chat` on Linux and
`~/Library/Application Support/chat` on macOS. Tests can override it with
`CHAT_CONFIG_DIR`.

The displayed fingerprint is a BLAKE2b hash of the Ed25519 public key, formatted
as uppercase colon-separated hex.

`chat fingerprint <username>` prints the fingerprint of a contact already pinned
in `contacts.db`.

## Contact Pinning

The V1 daemon uses trust-on-first-use contact pinning. The first time a peer is
seen in a valid `chat_request` or `chat_accept`, `chatd` records:

```text
username hex_ed25519_public_key
```

On later connections, the received identity key must match the pinned key. A
change is rejected and the CLI reports:

```text
SECURITY ERROR:
nathan's identity key changed.
Connection refused.
```

The daemon never overwrites an existing pin automatically.

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

After an encrypted P2P session is established, losing the control connection
does not close the local IPC client or ICE transport. Messages and clean session
shutdown continue end to end while `chatd` reconnects in the background.

## Network Configuration

ICE works without extra configuration on local/LAN host candidates. Optional
STUN/TURN settings can be added to `config.toml` when testing across NATs:

```toml
stun_server = "stun.example.net"
stun_port = "3478"

turn_server = "turn.example.net"
turn_port = "3478"
turn_username = "temporary-user"
turn_password = "temporary-password"
ice_force_relay = "true"
```

`chatd` configures STUN only when both `stun_server` and `stun_port` are
present. TURN is configured only when all four TURN fields are present. No
public STUN server or permanent TURN password is hardcoded.
`ice_force_relay` is optional and accepts `true` or `false`; enabling it without
a complete TURN configuration is rejected. It is intended for relay validation
and privacy-sensitive deployments.

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
`chat_request` when the daemon is online and keeps the CLI socket open until ICE
and the crypto handshake complete, ICE fails, or the server reports the peer
offline:

```text
USER_OFFLINE nathan
ENCRYPTED_SESSION nathan direct
ENCRYPTED_SESSION nathan relay
ICE_FAILED nathan
ERROR daemon_not_online
```

The CLI reports `ENCRYPTED_SESSION` as a direct encrypted P2P connection and
then keeps the IPC socket open for the terminal chat loop.
The final token is the selected ICE network mode: `direct` for host/server-
reflexive/peer-reflexive paths, or `relay` when the selected pair uses TURN.

During an active chat, the CLI writes one-line commands on that same socket:

```text
SEND_MESSAGE hello nathan
CLOSE_CHAT
```

EOF on stdin and `Ctrl+C` both send `CLOSE_CHAT` before the CLI exits.

The daemon writes incoming events back to the CLI:

```text
MESSAGE alex hello nathan
CHAT_CLOSED alex
ERROR send_failed
```

This first interactive milestone intentionally supports single-line terminal
messages. Newlines inside one user message are not part of the V1 IPC format.

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
  "session_id": "random-session-id",
  "public_key": "<hex Ed25519 pk>"
}
```

The server verifies that `from` matches the authenticated WebSocket session
before forwarding. For `chat_request` and `chat_accept`, it also verifies that
`public_key` matches the sender's registered Ed25519 identity. If the
destination is unknown or offline, the sender receives
`{"type":"error","code":"peer_offline"}`. The server does not inspect ICE
payload fields beyond the routing metadata and still never receives chat
plaintext.

`chatd` currently accepts incoming `chat_request` automatically by replying with
`chat_accept`, which matches the V1 shortcut before contact prompts are
implemented.

## ICE Rendezvous

`chatd` owns one `NiceAgent` at a time, matching the V1 constraint of a single
active conversation. The initiator starts ICE in controlling mode after
`chat_accept`; the receiver starts ICE in controlled mode after accepting the
incoming request.

ICE negotiation and the authenticated crypto setup both have daemon-side
deadlines. If either phase times out, `chatd` reports `ICE_FAILED <peer>` to the
waiting CLI and tears down the session state.

The daemon tracks the active conversation with an explicit state machine:

```text
IDLE -> REQUESTING -> ICE_NEGOTIATING -> ICE_CONNECTED -> CRYPTO_HANDSHAKE -> SECURE
SECURE -> CLOSING -> CLOSED
... -> FAILED
```

Application packets are accepted only in compatible states. In particular,
encrypted `CHAT_PKT_MESSAGE` and `CHAT_PKT_CLOSE` packets are rejected before
`SECURE`.

For the current development milestone, `chatd` exchanges a complete libnice SDP
blob in the relayed `ice_credentials` message:

```json
{
  "type": "ice_credentials",
  "from": "alex",
  "to": "nathan",
  "session_id": "...",
  "sdp": "<base64url SDP>"
}
```

UPnP and ICE-TCP are disabled for now to keep local/LAN candidate gathering
fast and deterministic. STUN and TURN relay settings are loaded from
`config.toml` when present.

The current ICE target is direct UDP host-candidate connectivity. A manual
`test_ice_loopback` build target verifies two libnice agents in one process;
the full daemon validation uses two temporary identities, two `chatd` instances,
and one `chat-server`.

## Crypto Handshake

The account identity remains Ed25519 and is used only for signatures. Each chat
session generates a fresh `crypto_kx` keypair and exchanges one binary handshake
message over the ICE data channel:

```text
+----------------------+--------------------------+
| ephemeral KX public  | Ed25519 detached sig     |
| 32 bytes             | crypto_sign_BYTES        |
+----------------------+--------------------------+
```

The signature is over a BLAKE2b transcript containing:

- protocol domain: `ProntoChat crypto-kx v1`
- signer role: initiator or responder
- signer account public key
- peer account public key
- signalling session id
- signer ephemeral KX public key

After both sides verify the peer signature, the initiator uses
`crypto_kx_client_session_keys()` and the responder uses
`crypto_kx_server_session_keys()`. The resulting TX key on one side must match
the RX key on the other side. Temporary KX secret keys are wiped after
derivation.

`common/crypto` also wraps `crypto_secretstream_xchacha20poly1305` for the
per-direction message streams. The initial stream header is sent once per
direction before encrypted `CHAT_PKT_MESSAGE` payloads. `CHAT_PKT_CLOSE`
carries an encrypted empty `TAG_FINAL` payload and closes the session on both
sides.

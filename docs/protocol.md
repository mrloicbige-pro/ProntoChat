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

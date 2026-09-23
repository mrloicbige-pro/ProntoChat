# ProntoChat Server

This archive contains the Linux presence server and its systemd service.

## Fedora runtime dependencies

```bash
sudo dnf install libwebsockets libsodium
```

## Install

```bash
sudo ./install.sh
systemctl status chat-server.service
```

The server listens on TCP port 8787. For the public deployment, keep that port
behind Caddy and proxy `pronto-chat.duckdns.org` to `127.0.0.1:8787`.

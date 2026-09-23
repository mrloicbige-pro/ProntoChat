# ProntoChat Server

This archive contains the Linux presence server and its systemd service.

## Install

```bash
sudo ./install.sh
```

The installer handles Fedora dependencies and enables the system service. The
server listens on TCP port 8787. For the public deployment, keep that port behind
Caddy and proxy `pronto-chat.duckdns.org` to `127.0.0.1:8787`.

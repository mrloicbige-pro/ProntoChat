# ProntoChat Client

This archive contains the Linux client commands `chat` and `chatd`.

## Fedora runtime dependencies

```bash
sudo dnf install glib2 libnice libsodium libwebsockets
```

## Install

```bash
./install.sh
export PATH="$HOME/.local/bin:$PATH"
chat init <username>
systemctl --user enable --now chatd.service
chat status
```

New identities connect to `wss://pronto-chat.duckdns.org` automatically.
Existing identities can be updated with:

```bash
chat config server wss://pronto-chat.duckdns.org
systemctl --user restart chatd.service
```

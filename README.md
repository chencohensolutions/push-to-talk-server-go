# ptt-server

A self-hosted server for a push-to-talk messenger. Phones enroll with it through a one-time code or QR code and
connect with mutual TLS; they find it again through the BitTorrent DHT when its address changes. Users pair by QR code, and the server
routes libsignal envelopes between their phones over a WebSocket, queued until each device takes them. Later phases
add push wake-ups, groups, talk clips and live audio through a LiveKit server running beside it. The server only
ever routes and stores ciphertext.

The phone app is [push-to-talk-kmp](https://github.com/chencohensolutions/push-to-talk-kmp). Much of this server is
copied from [journal-server-go](https://github.com/chencohensolutions/journal-server-go).

## Quick start

```bash
go build -o ptt-server .
./ptt-server setup --dir ~/ptt-server          # config.json, this server's own CA and TLS certificate
cd ~/ptt-server && /path/to/ptt-server          # run it; in another console in the same folder:
ptt-server user add hen
ptt-server enroll-code hen                     # scan the QR code with the app
ptt-server devices
```

## Docs

- [docs/install.md](docs/install.md): setup, the Windows service, ports
- [docs/authentication.md](docs/authentication.md): users, enrollment, device numbers, revocation, the admin API
- [docs/discovery.md](docs/discovery.md): the server's id, the DHT record, port mapping
- [docs/messaging.md](docs/messaging.md): identity keys and prekeys, pairing, `/ws` and the message queue

## License

[AGPL-3.0](LICENSE).

# Installing the server

ptt-server is one Go program with no cgo, for Windows, macOS and Linux. There is no installer or release build yet:
build it from source and set up its folder with `ptt-server setup`.

```bash
go build -o ptt-server .            # ptt-server.exe on Windows
./ptt-server setup --dir ~/ptt-server --user hen --address myhome.example.org
cd ~/ptt-server && /path/to/ptt-server              # run it (Ctrl+C stops it and removes the router's mapping)
ptt-server enroll-code hen          # in another console, from the same folder: scan the QR code with the app
```

The program changes to its own folder when the current one has no `config.json` but its own folder has one
(`auth.UseInstallFolder`), so a copy kept in the server folder runs from anywhere.

## Setup

`ptt-server setup` makes or completes a server folder. It writes only inside `--dir`; files already there are kept,
so it can run again at any time and only adds what is missing.

```
ptt-server setup --dir <folder> [--user <name>] [--import-ca <folder>] [--address <name or IP>]... [--port <port>]
ptt-server setup --dir <folder> --move-from <old server folder>
```

| What | Made |
|---|---|
| `config.json` | the certificates' paths, `"enrolled_only": true`, `public_url` (from the first `--address`, else this PC's first private IPv4 address; none when it has none) and `port` when not the default 56400 |
| `users.json` | with the `--user` given; more with `ptt-server user add` once the server runs |
| `certs/ca.pem`, `certs/ca-key.pem` | this server's own CA (RSA 4096, CN `ptt-server-ca`, 10 years; package `certs`), or the one `--import-ca` names |
| `certs/server.pem`, `certs/server-key.pem` | the TLS certificate (RSA 2048, `serverAuth`, 825 days, the most iOS takes) for `localhost`, the host name, every private IPv4 address and each `--address` |

The server writes `admin.token` at every start, `ptt.db` (prekeys and the message queue, SQLite) and `pairs.json`
(pairs and blocks) as they are needed, and `devices.json` / `devices.revoked.json` once a device enrolls.

- **Each server has its own CA.** Phones enroll by the QR code, which pins the server's key, and keep its CA from
  `enrollDevice` / `serverInfo.caCertificate`. Keep `certs/ca-key.pem` private and backed up: a new CA means every
  device enrolls again.
- When `config.json` is there but its CA is missing, setup refuses rather than make another (that would lock every
  device out): put the files back, give `--import-ca`, or `--new-ca` to start again.
- A server certificate that doesn't list an `--address` (or a new LAN address) is kept with a note; phones enrolled by
  QR code check the key, not the names, so they still connect. `--reissue-server-cert` makes it again (the old files
  are kept as `.bak`), with a **new key**, which changes the server's id: phones must enroll again.
- `--move-from <old folder>` copies `config.json`, the certificates, `users.json`, `devices.json`,
  `devices.revoked.json`, `pairs.json` and `ptt.db` from a server moved from another PC (stop it first); the old
  folder is only read, and `admin.token` isn't copied.

## A second server for testing

A test server beside the real one runs from its own folder (`ptt-server setup --dir <folder> --port 56410`) with its
own `admin_addr`, and with the router left to the real server:

```jsonc
  "port": "56410",
  "admin_addr": "127.0.0.1:8092",
  "port_mapping": false,   // the real server maps the router's port; a test server mustn't take it over
  "discovery": false       // optional: don't publish the test server in the DHT
```

## The Windows service

On Windows, in an administrator's console in the server folder:

```bat
ptt-server service install     :: the PttServer service, started at boot, restarted if it stops on an error,
                               :: and a firewall rule for the TCP port in config.json
ptt-server service start | stop | uninstall
```

The service runs from the program's folder and writes its log to `server.log` there (at most 20 MB, then
`server.log.old`). Keep the server folder readable only by SYSTEM and Administrators, since it holds `certs/ca-key.pem`
and `admin.token`:

```bat
icacls C:\PttServer /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F
icacls C:\PttServer\* /reset /T /C
```

On macOS and Linux run it with launchd or systemd from the server folder.

## Ports

| Port | Who listens | Open to the internet |
|---|---|---|
| TCP 56400 (`port`) | ptt-server: GraphQL on `/query`, the WebSocket on `/ws` (later `/blob`, `/rtc`) | Yes: the server maps it on the router itself (docs/discovery.md), or forward it by hand |
| TCP 127.0.0.1:8082 (`admin_addr`) | the admin API | No, loopback only |
| UDP 7882, TCP 7881 | LiveKit's media, from phase 5b | Yes, same number outside and inside |

56400 is next to Journal's 56398, so both servers can run on one PC.

## Versions

`version/VERSION` is the day of the build, `2026.11.21` (`.2`, `.3` for another the same day). `ptt-server version`
prints it with the build's commit from the Go build info.

## What is not here from Journal

journal-server-go has much this server intentionally leaves out: media storage, uploads and previews, search, faces,
OCR, the indexes and ONNX Runtime, libvips and libjxl, copies, peers and swaps, bundle downloads, the Windows
installer, releases and self-update. ptt-server is a delivery service for ciphertext (see the plan), so none of them
applies; releases and self-update may come back later in their own phase.

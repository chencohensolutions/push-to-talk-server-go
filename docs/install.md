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

## Email

The server sends no email. Invites go from the inviter's phone to the friend's (docs/authentication.md, "Invites"):
the link and its passcode leave through the phone's own mail app or any chat app, so there is no mail account,
password or Google grant to set up here.

A server set up before 2026-11-22 may have `smtp` or `gmail` in `config.json`, from when it emailed invite codes. It
still starts; its log says the key is no longer used. Remove the key, delete `gmail-client.json`, `gmail.token` and
`smtp.password` from the server folder, and, if `ptt-server mail-login` was run, remove ptt-server under **Google
Account → Security → Your connections to third-party apps**.

## Push (FCM)

Phones that aren't connected are woken through Firebase Cloud Messaging (docs/messaging.md, "Push"). The server
needs the Firebase project's **service-account key**: in the Firebase console, Project settings › Service accounts ›
Generate new private key. That downloads a JSON file named like `<project>-firebase-adminsdk-<id>.json`. Put it in
the server folder and name it in `config.json`:

```jsonc
  "fcm": {
    "service_account_file": "talk-3e556-firebase-adminsdk-fbsvc-0cbb81ebe6.json"
    // "project_id": "talk-3e556"   optional: default the file's project_id
  }
```

- **The key is a secret.** Anyone with it can send pushes to every phone of the app. Keep it only in the server
  folder (readable by SYSTEM and Administrators on Windows, as below), never in git: `.gitignore` leaves out
  `*-firebase-adminsdk-*.json`. `setup --move-from` doesn't copy it; copy it by hand. If it leaks, delete the key in
  the console (Google Cloud › IAM › Service accounts › the firebase-adminsdk account › Keys) and make a new one.
- The server signs in with the key itself (an RS256-signed JWT traded at Google's token endpoint for an hour's access
  token, standard library only) and sends to `https://fcm.googleapis.com/v1/projects/<project>/messages:send`. It
  needs outbound HTTPS to `oauth2.googleapis.com` and `fcm.googleapis.com`; nothing comes in.
- Without `fcm` the server runs with no push and says so at start ("Push: off"); phones then receive only while
  connected, and `serverInfo.push` is false. A key file that can't be read stops the server at start, so a typo
  doesn't turn push off unnoticed.
- `fcm.endpoint` (default `https://fcm.googleapis.com`) is for tests.

## LiveKit

The live talk path (phase 5b, docs/messaging.md "Live talk") runs a stock **livekit-server** beside ptt-server: one
node, no Redis, no TURN. ptt-server signs the phones' room tokens after its own checks, passes LiveKit's signalling
through `/rtc` on its own port (so only enrolled devices reach it), takes cut-off devices out of rooms with LiveKit's
room API, and runs livekit-server itself, starting it again when it exits. Without `"livekit"` in config.json the
server runs as before and talk goes by the clip path only.

- **config.json**: `"livekit": {}` turns it on with the defaults; setup writes it for a new server. Fields:
  `binary` (default: `livekit-server.exe` / `livekit-server` beside ptt-server when it is there; `"none"` runs
  nothing), `config_file` (`livekit.yaml`), `keys_file` (`livekit.keys`), `url` (`http://127.0.0.1:7880`),
  `tcp_port` (7881), `udp_port` (7882).
- **`ptt-server setup`** (run it again after adding `"livekit"`) makes `livekit.keys`, LiveKit's API key and secret
  as `key: secret` (a secret, gitignored, never in chat), and `livekit.yaml`: signalling on `127.0.0.1:7880`, media on
  TCP 7881 and UDP 7882, `use_external_ip: true` (LiveKit finds the public address by STUN). Files already there are kept.
  `livekit.yaml` holds no keys: ptt-server gives LiveKit the ones in `livekit.keys` in the `LIVEKIT_KEYS`
  environment variable when it starts it. (Not `key_file`: on Windows LiveKit refuses any key file, because Go
  reports every file there as readable by others. A `livekit.yaml` from before 2026-11-22 names `key_file:
  livekit.keys`; delete that line. If you start LiveKit yourself, set `LIVEKIT_KEYS` to the line in `livekit.keys`.)
- **The program**: download livekit-server from LiveKit's GitHub releases (1.13.x at the plan's review; there are
  Windows, macOS and Linux builds; it is Go and also builds from source) and put it beside ptt-server, or run
  `ptt-server livekit update`. Its log lines go into ptt-server's log, prefixed `LiveKit:`. ptt-server's own
  release downloads carry the LiveKit it was tested with.
- **Upgrading LiveKit**: `ptt-server livekit update [version]`, from the server folder (package `livekit`,
  `update.go`). It asks GitHub for LiveKit's latest release (or that version), downloads the archive for this OS and
  processor, checks it against the release's checksums file, checks that the program in it runs and reports the
  version it should, then puts it in place, keeping the old one as `livekit-server(.exe).old`. It then calls the
  running server's `restartLiveKit` (admin API), which stops LiveKit and starts the new one at once: live talk and
  calls drop for a few seconds, messages and push don't. If the server isn't running, it starts the new one when it
  starts. LiveKit is a separate program (not a library in ptt-server) so that it upgrades this way, without a new
  ptt-server, and so that a crash in it doesn't take messaging down; the two meet only at LiveKit's room API and its
  tokens. To go back, run it with the old version number.
- **The router and firewall**: the server maps UDP 7882 and TCP 7881 with the same numbers outside (package
  `portmap`, `Exact`), since LiveKit tells the phones its own port numbers. On Windows, allow them in Windows
  Defender Firewall for livekit-server.exe as for ptt-server.

## The Windows service

On Windows, in an administrator's console in the server folder:

```bat
ptt-server service install     :: the PttServer service, started at boot, restarted if it stops on an error,
                               :: and a firewall rule for the TCP port in config.json
ptt-server service start | stop | uninstall
```

The service runs from the program's folder and writes its log to `server.log` there (at most 20 MB, then
`server.log.old`). Keep the server folder readable only by SYSTEM and Administrators, since it holds `certs/ca-key.pem`,
`admin.token` and the FCM service-account key:

```bat
icacls C:\PttServer /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F
icacls C:\PttServer\* /reset /T /C
```

On macOS and Linux run it with launchd or systemd from the server folder.

## Ports

| Port | Who listens | Open to the internet |
|---|---|---|
| TCP 56400 (`port`) | ptt-server: GraphQL on `/query`, the WebSocket on `/ws`, `/blob`, and LiveKit's signalling passed through on `/rtc` | Yes: the server maps it on the router itself (docs/discovery.md), or forward it by hand |
| TCP 127.0.0.1:8082 (`admin_addr`) | the admin API | No, loopback only |
| outbound HTTPS | ptt-server to `oauth2.googleapis.com` and `fcm.googleapis.com`, with `fcm` set | Outbound only |
| TCP 127.0.0.1:7880 (`livekit.url`) | LiveKit's signalling and room API | No, loopback only: phones reach it through `/rtc` |
| UDP 7882, TCP 7881 | LiveKit's media | Yes, same number outside and inside (the server maps them with its own port) |

56400 is next to Journal's 56398, so both servers can run on one PC.

## Versions

`version/VERSION` is the day of the build, `2026.11.21` (`.2`, `.3` for another the same day). `ptt-server version`
prints it with the build's commit from the Go build info.

## What is not here from Journal

journal-server-go has much this server intentionally leaves out: media storage, uploads and previews, search, faces,
OCR, the indexes and ONNX Runtime, libvips and libjxl, copies, peers and swaps, bundle downloads, the Windows
installer, releases and self-update. ptt-server is a delivery service for ciphertext (see the plan), so none of them
applies; releases and self-update may come back later in their own phase.

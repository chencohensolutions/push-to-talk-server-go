# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Push-to-talk server (Go)

`ptt-server`: a self-hosted server that phones enroll with (mTLS client certificates, as Journal), that they find
again through the BitTorrent DHT when its address changes, and that will relay end-to-end encrypted messages, talk
clips and LiveKit tokens. The phone app lives in `../push-to-talk-kmp`. **Read the plan first**:
[Push-to-talk: architecture and phased plan](https://claude.ai/artifact/CPewKaHcVw4FeLyKthu2Cm). It records the
decisions (one shared server, libsignal end to end, LiveKit beside the server for live audio, FCM to wake phones)
and the phases. The server only ever routes and stores ciphertext.

Much of the code is copied from `journal-server-go` (enrollment, certificates, admin API, discovery, port mapping);
keep the two recognisable, so a fix in one can be carried to the other.

The docs describe what is built, and must be kept in step with the code in the same change:

- [docs/authentication.md](docs/authentication.md): users (`users.json`, `user add` / `user remove` / `users`),
  enrollment (one-time codes, the `ptt://enroll` QR code, certificate issuing, renewal), device numbers, the device
  registry, revocation, the admin API, the public API.
- [docs/discovery.md](docs/discovery.md): the server's id and fingerprint, its addresses, the sealed DHT record
  (salt `ptt-server/v1`), how a phone reconnects, and port mapping (package `portmap`, TCP and UDP).
- [docs/messaging.md](docs/messaging.md): identity keys and prekeys (`uploadPrekeys`, `prekeyBundles`,
  `replaceIdentityKey`), pairing tokens and `pairs.json` (`confirmPair`, `unpair`, `block`, `contacts`), the `/ws`
  protocol (`proto/ptt.proto`) with its Send rules (NOT_PAIRED, STALE_DEVICES, BLOCKED), the queue in `ptt.db`,
  linking (PROVISIONING) and what revocation does to a socket.
- [docs/install.md](docs/install.md): `ptt-server setup`, the Windows service, ports, versions, and what Journal has
  that this server intentionally leaves out (media, search, faces, copies, peers and swaps, indexes, ONNX, vips, jxl,
  bundle downloads, installer, releases, self-update).

**Phases.** Phase 1: enroll and find the server. Phase 2 (built too): identity keys and prekeys, `/ws` with the
message queue, pairing, linking a phone, invites (one link that enrolls a friend by their verified email and pairs
them). Phase 3 FCM (the registry already reserves `fcm_token` and
`notifications_enabled`); 4 groups; 5a clips and floor control; 5b LiveKit (`/rtc`, `talkToken`, UDP 7882 and TCP
7881 in `serverPorts`).

**Platforms.** The owner's server is a Windows PC, development happens on a Mac, and the server should run on
Windows, macOS and Linux: no cgo, Windows-safe file names, per-OS files (`*_windows.go`, `*_other.go`). CI runs
`go vet` and `go test` on Linux and Windows (`.github/workflows/test.yml`).

## Commands

```bash
go build ./... && go vet ./... && go test ./...   # what CI runs; the tests take a few seconds
go test ./enroll -run TestDeviceNumbers           # one test
go tool gqlgen generate                           # after editing graph/schema/*.graphql
go tool gqlgen generate --config gqlgen.admin.yml # after editing graph/admin/schema/*.graphql
go run . setup --dir <folder> [--user <name>] [--address <host>]   # make a server folder (docs/install.md)
go run .                                          # serve https://0.0.0.0:56400 (needs config.json + certs/)
go run . user add <name> | user remove <name> | users              # admin commands: the server must be running
go run . enroll-code <user> | devices [user] | revoke <serial>
go run . id | discovery                           # this server's id; check the DHT and the router from here
```

After editing `proto/ptt.proto`, regenerate `proto/pttv1/ptt.pb.go` (committed). protoc comes from Maven Central,
which is reachable where GitHub releases may not be; protoc-gen-go is pinned as a tool in go.mod:

```bash
curl -fLo bin/protoc https://repo1.maven.org/maven2/com/google/protobuf/protoc/4.33.2/protoc-4.33.2-linux-x86_64.exe
chmod +x bin/protoc                               # osx-aarch_64 / windows-x86_64 for the Mac and Windows
go build -o bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go
bin/protoc --plugin=protoc-gen-go=bin/protoc-gen-go --go_out=. \
  --go_opt=module=github.com/chencohensolutions/push-to-talk-server-go proto/ptt.proto
```

- The admin commands read `config.json` and `admin.token` in the current folder (or beside the program), so run them
  from the server folder.
- `config.json`, `certs/`, `users.json`, `devices.json`, `devices.revoked.json`, `pairs.json`, `invites.json`, `ptt.db` and
  `admin.token` are gitignored local state. `config.example.json` shows the shape. A second server for testing runs
  from its own folder with its own `port` and `admin_addr`, and `"port_mapping": false` so it leaves the router to
  the real one (docs/install.md).
- **After changing the public schema or `proto/ptt.proto`**, the client must get the copy: in `../push-to-talk-kmp`
  sync the `.graphqls` files from `graph/schema/` and the `.proto` file, and commit them there.
- The DHT record format is shared with the client: `TestASealedRecordFixtureOpens` in `discovery/` holds a fixture
  the client's tests open too. Change both together.

## Architecture

**Two GraphQL schemas, one binary.** `main.go` loads `config.json` (`auth.LoadConfig`, which refuses unknown keys)
and dispatches: no args serves, `setup` and `service` run before there is a config, `id` / `discovery` work from the
config alone, the rest (`admincli.go`) are GraphQL clients of the running server's admin API. `serve.go` is startup,
the `server` struct (config, users, enrollment, pairs, database, relay, discovery) and the routing table (`newMux`:
`/query` and `/ws`); `middleware.go` has `identify`, `limitBody` and deadlines. The public schema (`graph/schema/*.graphql`, generated into
`graph/generated` and `graph/model`, resolvers in `graph/resolver/`) is on `:56400` with mTLS. The admin schema
(`graph/admin/`, `admin.go`) is plain HTTP on a loopback-only address with a bearer token the server rewrites into
`admin.token` on every start; admin operations never appear on `/query`. Generated files are gqlgen output (don't
edit); resolver bodies in `*.resolvers.go` are ours, and gqlgen carries them over.

**Access is deny by default.** TLS (`tlsConfigFor`, shared with the tests) uses `VerifyClientCertIfGiven` so
enrolling phones connect without a certificate, and offers HTTP/2. `identify` maps the certificate's CN to a user in
`users.json`, rejects revoked serials and, with `enrolled_only`, serials the registry doesn't list.
`auth.RequireUserUnlessPublic` lets anonymous requests reach only root fields marked `@public` (the two enrollment
fields); introspection is blocked too. Resolvers get the user with `auth.FromContext(ctx)` and the device through
`Resolver.device(ctx)` (the registry entry of the certificate's serial).

**Packages.**
- `auth`: `AppConfig` and its defaults, `Users` (`users.json`, atomic writes), the request context, `@public`.
- `enroll`: codes (in memory, hashed, single use, rate limited per IP or IPv6 /64), the issuer (CN = the code's user,
  P-256 only), the `Registry` (`devices.json` plus `devices.revoked.json`; device numbers picked under its lock),
  `Service.Enroll` / `Renew`.
- `certs`: the CA and server certificate setup makes, without OpenSSL.
- `discovery`: server ids, `Fingerprint`, the DHT key, the sealed record, the publisher, STUN, `Own` addresses.
- `portmap`: UPnP IGD and NAT-PMP, a `Mapper` of `{proto, port}` that maps, renews and removes.
- `store`: SQLite (`ptt.db`, modernc.org/sqlite, pure Go): the devices' public keys and one-time prekeys, and the
  message queue, one row per (recipient device, envelope).
- `invite`: invites (`invites.json`, hashed codes, 7 days), the email codes (memory), and redeeming one: a new user
  named from the verified email and enrolled (`enrollWithInvite`), or an enrolled one (`acceptInvite`); both get a
  pairing token of the inviter.
- `mail`: the email codes, over SMTP (`smtp` in config.json) or to the log.
- `contacts`: `pairs.json` (pairs, pairings waiting for both confirmations, blocks) and the pairing tokens (memory).
- `relay`: who may reach whom, the Send checks (`Send`), the active devices, `/ws` (`ServeHTTP`,
  github.com/coder/websocket), `Revoked` (closes sockets, drops keys and queues) and the hourly `Sweep`.
- `proto`: `ptt.proto` and its generated Go code in `proto/pttv1` (google.golang.org/protobuf).
- `version`: `version/VERSION`.

## Conventions

- Tests run against a real server: `newTestEnv` in `serve_test.go` starts the public API over TLS and the admin API
  on loopback with their own CA and files, and the helpers (`addUser`, `enrollmentCode`, `device`, `graphql`) go
  through the same calls a phone and the commands make. New features get a test there, not only unit tests.
  `serve_messaging_test.go` adds `phone`, `uploadKeys`, `socket` (a device's `/ws`, frames kept until asked for)
  and `pair` (the QR code flow).
- The server never holds plaintext or a private key: what a device sends is ciphertext, and keys are public halves
  checked for size only. Anything new that routes must go through `relay.Relay.Send`'s rules.
- Every security property Journal has stays: rate limits, hashed codes, deny by default, `enrolled_only`, the revoked
  file, loopback-only admin, request size limits. A new root field needs a certificate unless it is deliberately
  `@public`.
- Files the server keeps are written through a temp file and a rename (`auth.WriteAtomic`, `enroll.writeAtomic`).
- Comments and docs say what the code does and why, in plain sentences; dates of decisions are kept where they
  explain something.
- Commit messages: a short summary line, then what changed and why.

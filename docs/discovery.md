# Finding the server

A home server has no fixed IP and often no host name. ptt-server is known by its **id** instead, as Journal's server
is ([journal-server-go docs/peers.md](https://github.com/chencohensolutions/journal-server-go/blob/main/docs/peers.md),
"Finding the host"): the sha256 of its key, which every connection checks. An address is only a hint. When none of
the addresses a phone knows answers, it looks the server up in the BitTorrent DHT. Nothing is relayed: the server must
be reachable at one of the addresses it publishes (its port mapped on the router, by itself or by hand, or IPv6).

The code is Journal's `discovery/` and `portmap/` packages, copied; the salt and key derivation strings are this
server's own, so a ptt-server record can't be mistaken for a Journal one.

## Who the server is

- **Fingerprint**: the sha256 of the server certificate's SubjectPublicKeyInfo, 64 hex digits
  (`discovery.Fingerprint`). It changes only when the server's key does (`setup --reissue-server-cert` makes a new
  key, so phones must enroll again after it).
- **Id**: the same 32 bytes as people type them, base32 in 8 groups of 7 with a check letter after each 13 (Syncthing's
  device id format, `discovery.FormatID` / `ParseID`): `43COG24-FQKTOON-…`.
- **DHT key**: an ed25519 key made from the server's TLS key (`discovery.KeyFor`: HKDF-SHA256 of the key's PKCS#8,
  info `ptt dht key v1`), so it needs no file of its own.

`ptt-server id` prints all three. The phone learns them from the enrollment QR code (`fingerprint=`, `key=`) and from
`serverInfo.discovery` afterwards.

## Where the server is

Every 5 minutes the server works out its addresses (`discovery.Own`), the most likely first:

1. `public_url` from config.json, when set;
2. the router's outside address and port, when the router forwards one to the server (below);
3. its public IPv4 address at `port`, from a STUN server (`discovery.STUNServers`);
4. its global IPv6 addresses;
5. its LAN addresses, for phones at home.

The phone gets them in the QR code (`address=`, at most 6) and in `serverInfo.discovery.addresses`.

## The DHT record

The server publishes its addresses in the BitTorrent DHT as a BEP 44 mutable item (`discovery.Publisher`, `Node`):

- at start, every 45 minutes (nodes forget a record after about two hours), and within 5 minutes of a change;
- under the DHT key, with salt `ptt-server/v1`, `seq` = the record's time in Unix seconds, signed by the DHT key;
- the value is the record sealed with XChaCha20-Poly1305: key = HKDF-SHA256(fingerprint bytes, no salt,
  info `ptt dht seal v1`), a random 24-byte nonce in front, the salt as additional data. The plain record is JSON:
  `{"v":1,"a":["https://203.0.113.7:56400", …],"t":"2026-11-21T12:00:00Z"}`. The DHT's nodes and crawlers see an
  opaque blob, not a home IP; only who knows the server (its phones) can open it. At most 1000 bytes: the last
  addresses are left out if more don't fit.
- The server joins the DHT passively: it answers no other node, and sends a few UDP packets per publish.

`discovery/discovery_test.go` keeps a sealed record as a fixture (`TestASealedRecordFixtureOpens`); the client's
`DhtClient` tests open the same bytes, so a change on either side fails a test.

`ptt-server discovery` checks it from this network: it lists the routers that map ports, prints the addresses it
found, publishes them and looks them up again. `"discovery": false` in config.json publishes nothing (and the QR
code then has no `key=`).

## How a phone reconnects

The app (push-to-talk-kmp `ServerFinder`, copied from Journal's client) tries the address that worked last, then the
others it knows; when none answers it looks the server up in the DHT under the key and fingerprint, and tries the
addresses found. Every connection checks the server's key against the fingerprint (or the certificate against the
CA kept at enrollment), never the host name, so a new IP works and another server at an old address is refused
(`serve_discovery_test.go`, `TestAPhoneReconnectsAfterTheAddressChanges`).

## Opening the router

The server asks the home router to forward its ports to this machine (package `portmap`), so nobody has to forward
them by hand:

- At start it looks for routers with UPnP IGD (SSDP; WANIPConnection 2 and 1, WANPPPConnection) and NAT-PMP on the
  default gateway at once, and maps each port on the first that maps any, for an hour (a router that takes only
  permanent mappings gets one). It renews at half the lease, looks for a router again every 10 minutes while it has
  none, and removes the mappings when the server stops, before the process ends.
- A `portmap.Mapper` maps a list of `{proto, port}`, **TCP or UDP**. In phase 1 the list is the server's own TCP
  `port` (`serverPorts` in `discover.go`). Phase 5b adds LiveKit's UDP 7882 and TCP 7881.
- When another machine holds the outside port, the next four are asked for and the one granted is published. A port
  marked `Exact` (LiveKit's, which tells phones its own port number) is never moved: it is mapped to the same number
  outside or not at all, and a NAT-PMP router that grants another number is asked to remove it again.
- A port the router refuses is logged and asked for again at the next renewal; the others stay mapped.
- The router's outside address for the server's TCP port goes first after `public_url` in the published addresses.
- **Carrier-grade NAT.** When the router's outside address isn't public (100.64.0.0/10 or a private range), the
  mapping can't help: the log says so once, with what to do (ask the provider for a public IPv4 address, or use IPv6),
  and that address isn't published.
- `"port_mapping": false` in config.json turns it off.

What it doesn't do: relay through a third machine (behind carrier-grade NAT the server is found but can't be reached).

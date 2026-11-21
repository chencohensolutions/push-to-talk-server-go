# Keys, pairing and messages

From phase 2 the server is a delivery service for libsignal ciphertext. The phones make every key; the server keeps
the **public** identity keys and prekeys, checks who may reach whom, and queues envelopes it can't open until each
device takes them. It never sees plaintext or a private key. The plan's "End-to-end encryption" section explains
the design; this page is what the server does.

```
Phone of dana                         ptt-server                              Phones of hen
─────────────                         ──────────                              ─────────────
                                                          ◀─────  uploadPrekeys (each device)
                                                          ◀─────  pairingToken → QR code with hen, identity key,
                                                                  token, a secret
scans the QR code
prekeyBundles(hen, routingToken) ───▶  one bundle per device of hen
checks the signatures against the
identity key from the QR code
/ws Send, one envelope per device,
  each with routing_token       ───▶  token is hen's, unused: route it ─────▶ /ws Envelope (pair request)
                                                                  checks the secret
confirmPair(hen)               ───▶  WAITING          ◀─────  confirmPair(dana)
                               ◀───  PAIRED envelope  ─────▶  PAIRED envelope, pair in pairs.json
/ws Send ⇄ Envelope, Ack       ◀──▶  queue (ptt.db)   ◀──▶    /ws Send ⇄ Envelope, Ack
```

## Keys

Every key is libsignal's serialized form, base64 in GraphQL. The server checks sizes, not signatures: verifying an
XEdDSA signature over a prekey needs libsignal, and the phones check them against the identity key they got from the
QR code anyway (`relay/keys.go`).

| Key | Kept in | Size |
|---|---|---|
| The user's identity key | `users.json` (`identity_key`, `identity_key_set_at`) | 33 bytes, `0x05` and 32 |
| Per device: registration id | `ptt.db`, `device_keys` | 1 to 16380 |
| Per device: signed EC prekey (id, public, signature) | `ptt.db`, `device_keys` | 33 + 64 bytes |
| Per device: last-resort Kyber prekey (id, public, signature) | `ptt.db`, `device_keys` | 1569 + 64 bytes |
| Per device: one-time EC prekeys (id, public) | `ptt.db`, `one_time_prekeys` | 33 bytes |
| Per device: one-time Kyber prekeys (id, public, signature) | `ptt.db`, `one_time_prekeys` | 1569 + 64 bytes |

Key ids are 0 to 16777215. The plan put the prekeys in `devices.json`; they are in SQLite instead, because a fetch
uses one up and the server would otherwise rewrite the whole registry on every fetch.

- **`uploadPrekeys(input)`**: `identityKey` must be the user's. The first device that uploads sets it; another one is
  refused `IDENTITY_KEY_MISMATCH`, so a second phone must be linked (below) to get it. A device's first upload needs
  `signedPrekey` and `kyberLastResortPrekey` (`MISSING_KEYS`); later uploads may leave them out and only add
  one-time prekeys, at most 100 of each kind per call and 500 held. An id the server holds is replaced. Answers
  `prekeyCount`.
- **`prekeyCount`**: `{ oneTimePrekeys oneTimeKyberPrekeys refillBelow }`; a phone uploads more when either is
  under `refillBelow` (20). Phones also replace the signed prekey weekly with an upload that carries it.
- **`prekeyBundles(user, routingToken)`**: `{ user identityKey devices { deviceNumber registrationId signedPrekey
  prekey kyberPrekey { … lastResort } } }`, one bundle per **active device** of the user: enrolled, not revoked, not
  expired, and with keys uploaded. The caller's own device is left out. Each fetch uses up one one-time EC prekey
  (`prekey` is null when none is left) and one one-time Kyber prekey (the last-resort one, `lastResort: true`, when
  none is left), lowest id first. Allowed for the caller's own user (its other devices), a contact neither blocked,
  or with a pairing token of `user` (5 fetches per token); `NOT_PAIRED`, `BLOCKED` or `UNKNOWN_USER` otherwise.
- **`replaceIdentityKey(identityKey)`**: after every phone of a user was lost and enrolled again. Refused
  `OTHER_DEVICES_ACTIVE` while another device of the user still has keys (revoke the old phones first). It drops the
  keys stored for the user's devices (they were signed by the old key) and sends each contact's devices an
  `IDENTITY_KEY_CHANGED` envelope whose `ciphertext` is the raw bytes of the new 33-byte key (not encrypted: it is
  public); their apps show "security key changed".
- `me.identityKey` is the user's identity key, null before the first upload.

## Pairing and contacts

Who may reach whom is in `pairs.json` (`pairs_file`; package `contacts`, written through a temp file and a rename):

```json
{
  "pairs":   [{ "users": ["dana", "hen"], "since": "2026-11-21T10:00:00Z" }],
  "pending": [{ "users": ["eve", "hen"], "introduced_at": "…", "confirmed": ["eve"] }],
  "blocks":  [{ "user": "dana", "blocked": "eve", "at": "…" }]
}
```

- **`pairingToken`** → `{ token expiresAt }`: 128 random bits (22 characters, base64url) for the caller's user, valid
  10 minutes, single use, kept in memory as a hash. At most 10 unused at once (`RATE_LIMITED`). The phone puts it in
  the Add contact QR code beside the user name, the identity key and a secret that never reaches the server. The
  code's format, `ptt://pair?v=1&u&k&t&s&f`, is the app's and is defined in push-to-talk-kmp's `docs/design.md`;
  the server only ever sees the token.
- **The pair request**: the scanning phone fetches `prekeyBundles(user, routingToken)` and sends one Send whose
  envelopes for that user all carry `routing_token`. The server routes it although the two aren't paired, uses the
  token up, takes it out of the envelopes, and records a pairing waiting in `pending`.
- **`confirmPair(user)`** → `WAITING` or `PAIRED`: each side confirms once its phone checked the other (the secret,
  the names). It needs a pairing waiting between the two from the last 7 days (`NO_PAIRING` otherwise, so nobody pairs
  without a QR code). When both confirmed, the pair is recorded and every device of both gets a `PAIRED` envelope
  naming the other in `sender_user`.
- **`unpair(user)`**: removes the pair and any pairing waiting; a new QR code is needed to pair again.
- **`block(user)` / `unblock(user)`**: a block refuses everything between the two, both ways: Sends (`BLOCKED`), prekey
  bundles, pair requests with a token, `confirmPair`. The pair itself is kept, so `unblock` brings it back.
- **`contacts`** → `[{ user identityKey since blocked devices { deviceNumber registrationId } }]`: the paired users,
  with their active devices. **`blocked`** is the users the caller blocked. **`devices`** → `[{ deviceNumber name
  registrationId registeredAt current }]` is the caller's own user's enrolled devices (`registrationId` null until a
  device uploaded keys).

Groups (phase 4) will add "shares a group" to who may reach whom.

## /ws

`GET /ws` upgrades to a WebSocket over the same mTLS port, **over HTTP/1.1** (the server offers HTTP/2 for
`/query`; a WebSocket client asks for `http/1.1`, as OkHttp does). It needs an enrolled device's certificate: `401`
without one, `403` for a certificate outside the registry. Every message is binary, one `ptt.v1.Frame`
([proto/ptt.proto](../proto/ptt.proto), generated into `proto/pttv1`).

| Frame | Way | What |
|---|---|---|
| `Envelope` | server → device | `id sender_user sender_device recipient_user recipient_device type ciphertext server_timestamp` |
| `Ack { ids }` | device → server | the envelopes are stored on the phone; the server deletes them from the queue |
| `Send { client_id envelopes }` | device → server | one message, one envelope per device |
| `SendResult { client_id status envelope_ids devices detail }` | server → device | `ACCEPTED`, or why not |
| `Ping { id }` / `Pong { id }` | either way | answered with the same id |
| `QueueEmpty` | server → device | everything queued at connect was sent; what follows is live |

Envelope types: `PREKEY_MESSAGE`, `MESSAGE`, `SENDER_KEY_MESSAGE` (libsignal's), `PROVISIONING` (linking), and two
the server makes, `IDENTITY_KEY_CHANGED` and `PAIRED`.

**The rules of a Send** (`relay.Relay.Send`), checked in this order:

1. Well formed (`INVALID`): at least one envelope and at most 254, each naming a recipient device, with a ciphertext,
   of a type a device sends, no device twice, not the sending device, and **one other user** at most. A
   `PROVISIONING` envelope goes alone, to an enrolled device of the sender's own user (which may have no keys yet;
   `UNKNOWN_USER` when it isn't enrolled).
2. Each ciphertext is at most 256 KB (`TOO_LARGE`); a frame is at most 4 MB, or the server closes the connection.
3. The other user exists (`UNKNOWN_USER`), neither blocked the other (`BLOCKED`), and they are paired, or every
   envelope for that user carries the same unused pairing token of that user (`NOT_PAIRED`).
4. The envelopes cover **exactly** the active devices of the recipient and the sender's other active devices, so all
   the sender's phones show what was sent (`STALE_DEVICES`, like Signal's mismatched devices). An envelope's optional
   `recipient_registration_id` must be the device's current one. The refusal lists the active devices of both users
   (`devices { user devices { device_number registration_id } }`); the phone fetches bundles for new devices, drops
   sessions with gone ones, and sends again.
5. Every recipient device's queue has room (`QUEUE_FULL`: 10000 envelopes or 256 MB). Then all envelopes are queued
   in one transaction, or none.

The server fills in `id` (32 hex digits), `sender_user`, `sender_device` (from the certificate) and
`server_timestamp`, removes `routing_token` and `recipient_registration_id`, and answers `ACCEPTED` with the ids in
the order of the envelopes.

**Connection.** A device has one connection: a second one closes the first with code `4001`. On connect the server
sends the device's queue, oldest first, then `QueueEmpty`, then each envelope as it is queued. An envelope that isn't
acknowledged stays queued and comes again on the next connection (not on the same one). The server pings a quiet
connection every minute and drops it after 30 seconds without a pong.

**Revocation takes effect at once.** `ptt-server revoke` and `user remove` call `relay.Relay.Revoked`: the device's (or
user's) `/ws` closes with code `4003`, its queue and keys are deleted, so it leaves every active device list at once,
and Sends that still name it are refused `STALE_DEVICES`. A removed user's pairs, blocks and tokens go too. `unpair`
and `block` apply to the next Send. A sweep at start and every hour does the same for devices whose certificate was
revoked or expired otherwise.

## The queue

`ptt.db` (`database_file`), SQLite through `modernc.org/sqlite` (pure Go, no cgo), one row per (recipient device,
envelope): the envelope frame as it will be sent, its id and when it was queued (package `store`). A row goes when
its device acknowledges it, when the device is revoked, or after `queue_days` (default 30) without being taken. The
database runs in WAL mode; the server writes the log back into `ptt.db` when it stops.

## What the server sees

Who is paired with whom and who blocked whom, who sends to whom and when, how big each envelope is, the type of each
(a pair request is told apart by its token), the public keys, and the IP addresses. Never the content: text,
receipts, typing, sync messages and key messages are all ciphertext of the same kinds.

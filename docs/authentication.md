# Authentication

ptt-server authenticates every device with **mutual TLS**: a device proves who it is with a client certificate signed
by the server's own CA. There are no passwords, no sessions and no tokens on the network-facing API. This is
Journal's enrollment ([journal-server-go docs/authentication.md](https://github.com/chencohensolutions/journal-server-go/blob/main/docs/authentication.md)),
copied, with users kept in `users.json` and a device number for each device.

A device gets its certificate through **enrollment**: it creates a private key in its own secure hardware, and
trades a one-time enrollment code plus a certificate request for a certificate. The private key never leaves the
device.

```
Server (admin)                                   Phone (push-to-talk app)
──────────────                                   ────────────────────────
ptt-server user add hen
ptt-server enroll-code hen
  → prints address, code "K7QM-4XPD"    ─────▶   user scans the QR code (or types address + code)
    and a QR code (ptt://enroll?…)
                                        ◀─────   query enrollmentPreview(code)          (no client cert)
  code valid for "hen", 8 min left      ─────▶   "Register this device?"
                                                 create EC P-256 key in hardware
                                                 build PKCS#10 request, signed by the key
                                        ◀─────   mutation enrollDevice(input)           (no client cert)
  use up code, sign certificate CN=hen,
  give it the next device number,
  record it in devices.json             ─────▶   store certificate next to the key, keep caCertificate
                                        ◀─────   query me                                (new client cert)
                                                 "Connected"
```

## Users

Users live in `users.json` (`users_file`), not in `config.json`. The server is the file's only writer: the
commands go through its admin API, so the server must be running.

```
$ ptt-server user add hen
Added user hen. Enroll a phone with: ptt-server enroll-code hen
$ ptt-server users
USER   ADDED        DEVICES
hen    2026-11-21   1
$ ptt-server user remove hen
Removed user hen and revoked 1 of its devices
```

- A user name is 1 to 32 letters, digits, `.`, `-` and `_`, not starting with `.` or `-` (`auth.CheckUserName`): it
  is the CN of the user's certificates and may become a file or folder name later.
- `user remove` takes the user out of `users.json` (its certificates are refused from then on, since `identify`
  finds no user) and revokes all its devices, so a user added again by the same name doesn't get them back. A code
  made for the user before is refused too (`enroll.Service.UserExists`).
- Names are unique in any case: `user add Hen` is refused beside `hen` (`auth.Users.Add`), so two users can't look
  the same.
- `users.json` also keeps each user's public identity key (`identity_key`), set by the first device's
  `uploadPrekeys` ([messaging.md](messaging.md)). `user remove` drops it with the user, and the user's pairs, blocks,
  prekeys and queued envelopes go too.
- `presence_hidden` is set when the user hides their presence from contacts (`setPresenceVisible`;
  [messaging.md](messaging.md), "Presence").

## Access rules

| Endpoint | Without client certificate | With a valid client certificate |
|---|---|---|
| `POST /query` (GraphQL) | Only root fields marked `@public` (`enrollmentPreview`, `enrollDevice`). Everything else, including introspection, returns `client certificate required for <field>` with `extensions.code` `UNAUTHORIZED`. | Every field |
| `GET /ws` (WebSocket) | `401` | An enrolled device (`403` for a certificate outside the registry); see [messaging.md](messaging.md) |
| `GET /` (playground) | Only with `"playground": true` in config.json (off by default); it can only call `@public` fields without a certificate | The same |
| Admin API (`admin_addr`) | Loopback only, needs the admin token | n/a |

How it is enforced:

1. **TLS** (`serve.go`, `tlsConfigFor`): `tls.VerifyClientCertIfGiven`. A device that is enrolling connects without
   a certificate. A certificate that *is* sent must chain to `client_ca`, or the handshake fails. HTTP/2 is offered
   beside HTTP/1.1.
2. **HTTP** (`middleware.go`, `identify`): a certificate's subject CN must be a user in `users.json`, its serial must
   not be revoked, and with `"enrolled_only": true` (what setup writes) it must be in the registry, so a certificate
   the CA signed outside enrollment is refused. Otherwise `401`. The user and the certificate's serial go into the
   request context.
3. **Request size** (`limitBody`): a request without a certificate may send at most 64 KB to `/query`, one with a
   certificate 1 MB; a query costs at most 1000 by gqlgen's complexity count. The admin API takes at most 64 KB.
4. **GraphQL** (`auth/access.go`, `RequireUserUnlessPublic`): a root-field middleware. Anonymous requests may only
   reach fields whose schema definition carries `@public`. This is **deny by default**: a new query or mutation
   needs a certificate unless it is marked `@public`. Resolvers read the user with `auth.FromContext(ctx)` and the
   serial with `auth.SerialFromContext(ctx)`.

## Enrollment codes

Created by `ptt-server enroll-code <user>` (`enroll/codes.go`), for a user that is in `users.json`:

- 8 characters from `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U), shown as `K7QM-4XPD`: 40 bits.
- Valid for **10 minutes**, **single use**. Only the user named on the command line can be enrolled with it.
- Input is normalized before lookup: case, dashes and spaces are ignored, `O` reads as `0`, `I`/`L` read as `1`.
- Stored **in memory only**, as the SHA-256 of the normalized code. Restarting the server drops all pending codes.
- `enrollmentPreview` looks a code up without using it. `enrollDevice` uses it up atomically (lookup and delete under
  one lock), so two racing requests cannot both use it. A malformed certificate request is rejected *before* the
  code is used, so a client bug does not burn the code.
- **Guess limit:** 5 wrong codes per client IP per minute (IPv6 counted per /64), counted across
  `enrollmentPreview` and `enrollDevice`. After that both return `RATE_LIMITED` until the minute has passed.
- Wrong, expired and already used codes, and codes of a removed user, all return the same `INVALID_CODE`.

### Enrolling by QR code

The command also prints the server's id and a **QR code** holding

```
ptt://enroll?code=K7QM-4XPD&server=<url>&fingerprint=<sha256 of the server key>&key=<DHT key>&address=<url>…
```

- `server` is `public_url`, or the first address found when it isn't set.
- `fingerprint` is the sha256 of the server certificate's SubjectPublicKeyInfo, 64 hex digits
  (`discovery.Fingerprint`). The app checks the server's key against it from the first connection instead of a CA
  and the host name, so an IP address the certificate doesn't list works.
- `key` is the server's ed25519 DHT key, 64 hex digits (absent with `"discovery": false`), and `address` is repeated
  for each of the server's addresses (at most 6: `public_url`, the router's mapping, the public IPv4 from STUN, IPv6,
  LAN). See [discovery.md](discovery.md).
- The QR code is drawn white on black whatever the terminal's colors; on Windows use Windows Terminal.

### Linking a phone

A phone makes the code for its user's next phone itself: `createLinkCode` answers the same kind of code as
`enroll-code` (10 minutes, single use, only for the caller's user), with no admin step. At most **3** of a user's
link codes wait at once (`RATE_LIMITED`). The phone shows it in its Link a phone QR code (`ptt://link?…`, the
enrollment link's fields plus the phone's own pairing part; the client's docs/design.md, "Linking a phone"). The
new phone enrolls with it as usual and gets the next device number; it then has a certificate but no keys, and asks
the old phone for the user's identity key over `PROVISIONING` envelopes (docs/messaging.md), which the server only
lets through between two devices of one user. The server never sees the identity key: the two phones seal it with a
key from the QR code's secret and an X25519 exchange.

## Invites

An enrolled user invites a friend with one link, `ptt://invite?…`, and a six-digit passcode beside it, that enroll
the friend and pair them with the inviter, so the friend needs no code from the server's owner (package `invite`,
`graph/schema/invite.graphql`). **The server sends no email**: the inviter's phone sends the link and the passcode,
from the user's own mail app or any chat app (owner's decision, 2026-11-22: invitations go from client to client).
So the server holds no mail account or password, and nothing it sends can be spoofed or land in spam.

1. The inviter's phone calls `createInvite(email)`. The server keeps the invite in `invites.json` (`invites_file`):
   a short `id`, the SHA-256 of its code, the SHA-256 of `<id>/<passcode>`, who made it, the email it is for
   (optional, lower case), and when it expires, **7 days** on. The code (128 random bits, base64url) and the
   passcode (six random digits) are answered once, and only their hashes are kept. At most 5 invites wait per user;
   `invites` lists them and `cancelInvite(id)` stops one.
2. The phone builds the link: the server part as in an enrollment link (`server`, `fingerprint`, `key`, `address`),
   the invite `code`, and the inviter's pairing part (`u`, `k`, `s`: user, identity key, secret, as in the Add contact
   QR code, without a token). With an email, `e` too. The passcode is **not** in the link: it goes beside it, in the
   same message or, for more safety, by another way (said aloud, another chat). The app then offers **Email the
   invite** (its mail app, to the email typed) and **Share** (any app); both send the steps, the link and the
   passcode.
3. A friend **not enrolled here** opens the link. `invitePreview(code)` says who it is from and the email it is for.
   The friend types the passcode and their name (and, for an invite without an email, their email if they want), and
   `enrollWithInvite` takes them with the certificate request. The server checks the invite, then the passcode, then
   the email: for an invite with one, it must be that address (compared lower case; else `EMAIL_MISMATCH`, also when
   none is sent); for an invite without one, it is optional. A taken email is `EMAIL_TAKEN`; the email is checked
   after the passcode, so the link alone doesn't tell whether an address has an account here. Then it makes the
   user and the device's certificate in one step, uses up the invite, and answers the certificate and a **pairing
   token of the inviter**.
4. A friend **already enrolled here** calls `acceptInvite(code)` with their certificate instead, and gets the
   pairing token; no passcode is asked, since they are a user of this server already and redeeming only pairs them.
   Their own invite is refused (`OWN_INVITE`), and one for another email than theirs.
5. The friend's phone pairs with the token as with one read from the inviter's QR code ([messaging.md](messaging.md)):
   bundles with the token, the pair request with the secret `s`, `confirmPair`. The inviter's phone knows the secret
   from step 2, so it accepts the request without a tap, and marks the contact "not verified" until the two compare
   safety numbers: the link may have been forwarded.

**Why the passcode isn't in the link.** With it in the link, the link alone would be enough, and anywhere the link
alone ends up (a forwarded message, a link scanner, a chat backup, a screenshot of the QR code) could redeem it. Kept
apart, the link alone does nothing, and an inviter who wants to can send the two by different ways. The cost is six
digits to type. When the friend pastes the whole message into the app, it finds both and fills the passcode in. The
one place the passcode is in the link (`p`) is the QR code the inviter's screen shows face to face: the friend is in
the room, and scanning it is the whole invite. The server never sees the link, so this is the phones' choice.

**The user.** The email is the unique part of an invited user: no two users share one, compared in lower case. **No
email is verified any more**: with an email-bound invite, the email is the one the inviter typed (whoever has the link
and the passcode can redeem it, as anyone they forward the mail to could); with an invite for anyone, it is the one the
friend typed, or none. So an email shows who the inviter meant, not who holds the phone; the safety number does that.
The user name is made from the email's local part, or without an email from the display name, in a–z, 0–9, `.`, `-`
and `_` only, so it can't pass for another in a different script, with a number added when taken (`dana.cohen`,
then `dana.cohen2`; "Dana Cohen" is `dana.cohen` too). `users.json` keeps `email` (when there is one),
`display_name` (the friend's first and last name, free text, at most 64 characters, not unique) and `invited_by`;
`me` and `contacts` answer `displayName`, and `me` the `email`. A friend who typed someone else's address in an
invite for anyone takes that address here: `ptt-server user remove` frees it.

**Limits.** Wrong invite codes and wrong passcodes count against the client address's limit, as enrollment codes
do (5 a minute, then `RATE_LIMITED`). 10 wrong passcodes end the invite, from any addresses: a guess has a 1 in
100,000 chance. The count is in memory, so a restart starts it again (the address limit still holds). Invites made
before 2026-11-22 for an email keep their code as the passcode; those made for anyone had no code and no longer
work. `"invites": false` turns invites off (`INVITES_OFF`).

## Issued certificates

Signed by `client_ca` with `client_ca_key` (`enroll/issuer.go`):

- The request must hold an **EC P-256** key (what Android Keystore and the Secure Enclave create) and be correctly
  self-signed (`INVALID_CSR` otherwise).
- Subject `CN` = the user the code was created for. The subject in the request is ignored.
- Random 128-bit serial; `ExtKeyUsage: clientAuth`; valid **365 days**, never beyond the CA's own expiry;
  `NotBefore` is backdated 5 minutes for device clock skew.
- `enrollDevice` answers the certificate, its serial, the device number and the server's CA (`caCertificate`, PEM).
- **Renewal**: in the last 30 days of its certificate a device makes a new key and calls
  `renewCertificate(csr, keyProtection)` with its current certificate. The server issues a certificate for the same
  user, name and **device number**, recorded with `renewed_from`. The old certificate works until the new one is first
  used (`identify` then revokes it, `Registry.UseRenewal`). A certificate made outside enrollment, or revoked, gets
  `NOT_ENROLLED`; a renewal before the last 60 days, or a sixth renewal of the same certificate, gets `RATE_LIMITED`.

## Device numbers

Every enrolled device gets a small **device number**, 1 to 127, unique among its user's devices
(`enroll.Registry.Add`, `nextNumber`). libsignal uses it as the device id (phase 2), and LiveKit identities are
`user.device` (phase 5b). It is returned by `enrollDevice`, `renewCertificate`, `serverInfo.deviceNumber` and
`me.deviceNumber`, and listed by `ptt-server devices`.

- The number is picked under the registry's lock, so two enrollments at once never share one.
- A renewal keeps the number: the device is the same, only its key changed.
- A new device gets the lowest number the user never had. Only once all 127 were had does it take the lowest number
  no device that isn't revoked holds, so a contact that still knows a revoked phone by its number rarely sees a new
  phone take it. With 127 devices not revoked, enrollment fails (`enroll.ErrTooManyDevices`).
- A certificate outside the registry (only on a server without `enrolled_only`) has device number 0.

## Device registry and revocation

Every enrolled certificate is appended to `devices_file` (default `devices.json`; `enroll/devices.go`, written
atomically): serial, user, device name, device number, key protection, registration and expiry dates, the revocation
date and `renewed_from`, and the device's push registration: `fcm_token` and `notifications_enabled`, set by
`registerPush` ([messaging.md](messaging.md), "Push"), kept by a renewed certificate, cleared when the device is
revoked, and dropped when FCM says the token is gone. A device's public prekeys are in `ptt.db`, not here.

```
$ ptt-server devices
USER   NO.   DEVICE    KEY        REGISTERED   EXPIRES      STATUS   SERIAL
hen    1     Pixel 9   SOFTWARE   2026-11-21   2027-11-21   active   b582e90a5ea9c2a16b60802e95543c85
$ ptt-server revoke b582e90a5ea9c2a16b60802e95543c85
Revoked "Pixel 9", device 1 of user hen (serial b582e90a5ea9c2a16b60802e95543c85)
```

- `revoke` revokes the certificate and every other certificate of the same device (same user and device number:
  what it renewed, and a renewal in flight), `Registry.RevokeDevice`.
- A revoked serial is rejected with `401` on the next connection. Its open `/ws` closes at once (code `4003`), and its
  queue and prekeys are deleted, so senders must leave it out from then on (`relay.Relay.Revoked`, called by the
  admin API after `revoke` and `user remove`).
- Revoked serials are also kept in `devices.revoked.json` beside `devices.json`, read at start, so a lost or replaced
  `devices.json` doesn't bring a revoked phone back; a damaged one stops the server rather than let everyone in.
- `keyProtection` is what the device *reports* (`STRONGBOX`, `TEE`, `SECURE_ENCLAVE`, `SOFTWARE`). The server does not
  verify it (no key attestation), so treat it as informational.

## Admin API and commands

`ptt-server user add | user remove | users | enroll-code | devices | revoke` are thin GraphQL clients of the running
server's admin API (`admin.go`, `admincli.go`, schema in `graph/admin/schema/admin.graphql`). `ptt-server livekit
update` ends with its `restartLiveKit` mutation (docs/install.md, "LiveKit"), and `ptt-server app-update [--push]`
is the `checkAppRelease` mutation (docs/install.md, "App updates").

- Served on `admin_addr` (default `127.0.0.1:8082`, beside Journal's 8081). The server refuses to start if that is
  not a loopback address, so the admin API is never reachable from the network.
- Plain HTTP; every request needs `Authorization: Bearer <token>`. On every start the server writes a new random
  token to `admin_token_file` (default `admin.token`, mode `0600`), and the commands read it from there. On Windows the
  file mode is not enforced, so keep the server folder private to the account that runs it.
- The admin schema is separate from the public one, so admin operations never appear on `/query`.

## The public API

`graph/schema/schema.graphql`, `discovery.graphql` and `messaging.graphql`:

| Field | Certificate | What |
|---|---|---|
| `enrollmentPreview(code)` | no (`@public`) | the user a code is for, and when it expires |
| `enrollDevice(input)` | no (`@public`) | the certificate, device number and CA |
| `renewCertificate(csr, keyProtection)` | yes | a new certificate for the same device |
| `invitePreview(code)`, `enrollWithInvite(input)` | no (`@public`) | redeeming an invite on a new phone ([Invites](#invites)) |
| `createInvite(email)`, `invites`, `cancelInvite(id)`, `acceptInvite(code)` | yes | making invites, and redeeming one on an enrolled phone |
| `serverInfo` | yes | `api`, `version`, `caCertificate`, `renewCertificates`, the caller's `deviceNumber`, and `discovery { fingerprint id key addresses }` |
| `me` | yes | `user`, `deviceNumber`, `deviceName`, `identityKey`, `displayName`, `email`: what the app asks to show "connected" |
| `uploadPrekeys`, `prekeyCount`, `prekeyBundles`, `replaceIdentityKey` | yes | keys ([messaging.md](messaging.md)) |
| `pairingToken`, `confirmPair`, `unpair`, `block`, `unblock`, `contacts`, `blocked`, `devices` | yes | pairing and contacts ([messaging.md](messaging.md)) |

The keys and pairing fields need an enrolled device (`NOT_ENROLLED` for a certificate made outside enrollment).

## Client side (push-to-talk-kmp)

The app copies Journal's client enrollment (`sharedLogic` `enrollment/`, `tls/`): an EC P-256 key in the Android
Keystore (StrongBox when there is one), the PKCS#10 request built in shared Kotlin, OkHttp with a key manager over the
Keystore key. Enrollment requests go out without a client certificate but pin the fingerprint from the QR code. Once
enrolled, the app keeps the CA from `caCertificate` and accepts a server certificate that chains to it (or has the
pinned key) at any address. See the client repo's docs.

## Configuration

```jsonc
{
  "tls_cert": "certs/server.pem",
  "tls_key": "certs/server-key.pem",
  "client_ca": "certs/ca.pem",
  "client_ca_key": "certs/ca-key.pem",          // required: signs enrolled devices
  "enrolled_only": true,                        // only certificates in devices.json (setup writes it)
  "public_url": "https://192.168.50.2:56400",    // optional: first in the QR code and the addresses
  "port": "56400",                              // optional (default)
  "users_file": "users.json",                   // optional (default)
  "devices_file": "devices.json",               // optional (default)
  "pairs_file": "pairs.json",                   // optional (default): pairs and blocks (messaging.md)
  "groups_file": "groups.json",                 // optional (default): who is in which group (messaging.md)
  "blob_dir": "blobs",                          // optional (default): clips and attachments, ciphertext
  "blob_days": 30,                              // optional (default): how long they are kept
  "database_file": "ptt.db",                    // optional (default): prekeys and the message queue
  "queue_days": 30,                             // optional (default): how long an envelope waits for its device
  "admin_addr": "127.0.0.1:8082",               // optional (default), must be loopback
  "admin_token_file": "admin.token",            // optional (default)
  "discovery": true,                            // optional (default): publish the addresses in the DHT
  "port_mapping": true,                         // optional (default): UPnP / NAT-PMP
  "playground": false,                          // optional: serve the GraphQL playground at /
  "invites": true,                              // optional (default): users may invite friends
  "invites_file": "invites.json"                // optional (default)
}
```

Unknown keys are refused at start, so a typo (or a Journal `config.json` with its `users`) is caught. The one
exception is `smtp` and `gmail`, the mail settings of the server before 2026-11-22, when it emailed invite codes: they
are taken and ignored, and the log says to remove them.

`client_ca_key` is the most sensitive file on the server: anyone holding it can mint certificates for any user. Keep
it readable only by the account that runs the server.

## Threat notes

- **Forwarded invite:** whoever has the link and its passcode can redeem it first (once, within 7 days), with the
  email the inviter typed when there is one. The link alone isn't enough (10 wrong passcodes end it). The server
  proves no email address. The inviter's phone shows the new contact as "not verified" until they compare safety
  numbers, and `cancelInvite` stops an invite that went astray.

- **Stolen enrollment code:** usable once, for at most 10 minutes, and only for the user it was made for. If a code
  may have leaked, check `ptt-server devices` and revoke any device you don't recognize.
- **Network attacker during enrollment:** the phone pins the server key from the QR code, so it cannot be tricked into
  sending the code to another server. The CA it keeps afterwards comes over that checked connection.
- **Lost or stolen phone:** `ptt-server revoke <serial>`. The key cannot be extracted from the phone's secure
  hardware. Its `/ws` closes at once and nothing is routed to it any more; the user's other devices and its groups
  replace their sender and talk keys (phases 4 and 5).
- **Anonymous probing:** without a certificate, only the two enrollment fields respond, and they are rate limited.
  The schema cannot be introspected.

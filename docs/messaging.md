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

Members of one group may also send each other one-to-one envelopes, so they can hand out the group's sender keys,
but one-to-one calls and talk stay for contacts (see Talk and Calls).

## Groups

Phase 4 (2026-11-22). Who is in which group is in `groups.json` (`groups_file`; package `groups`, written through a
temp file and a rename):

```json
{ "groups": [{ "id": "3f2a…(32 hex)", "owner": "hen", "members": ["hen", "dana"], "invited": ["noa"],
               "created_at": "…" }] }
```

The server uses it **only to route**. The group's name and picture, and who its members are as far as the phones are
concerned (each with their identity key), go end to end in the owner's group changes, signed by the owner's devices.
A phone gives its sender key only to members the owner's devices named, so a member added by editing `groups.json`
alone gets copies of group messages it can't open: no reader is added that way (the app's tests check that side).

- `groups` lists the caller's groups (member or invited). `createGroup` makes one with the caller as owner and only
  member (at most 200 owned). `inviteToGroup(group, user)`: the owner only (`NOT_OWNER`), and only a contact
  (`NOT_PAIRED`, `BLOCKED`); at most 50 members and invited (`GROUP_FULL`). `acceptGroupInvite` makes an invited user a
  member (`NOT_INVITED` otherwise). `leaveGroup` leaves or declines; the owner can't (`OWNER_CANT_LEAVE`) and deletes
  the group with `deleteGroup` instead. `removeFromGroup(group, user)` is the owner taking a member or invited user
  out. A group the caller isn't in is `NO_GROUP`, so ids can't be probed.
- After every change the devices of everyone concerned (members, invited, and whoever just left or was taken out)
  get a `GROUP_CHANGED` envelope made by the server, with `group` set and no ciphertext; the phone fetches `groups`.
- Members (accepted, not only invited) may fetch each other's `prekeyBundles` and send to each other pairwise without
  being paired: that is how sender keys are handed out. Blocks still apply. Taken out, that ends at once.
- **A group Send** (`Send.group`) holds one `SENDER_KEY_MESSAGE` envelope with no recipient, encrypted once. The
  server copies it to every active device of every member but the sending device, leaving out members who blocked
  the sender or whom it blocked, with `Envelope.group` set. `Send.group_devices` must name exactly those devices (the
  ones the sender gave its sender key to; a registration id of 0 skips that check), or the Send is refused
  `STALE_DEVICES` with each member's devices (sorted by user, the sender's own user with its other devices): the phone
  gives its sender key to the new devices over their pairwise sessions and sends again. A sender that isn't a member,
  or a group that doesn't exist, is `NOT_MEMBER`. `push_kind` applies as for any Send.
- Removing a user (`user remove`) takes it out of every group and deletes the groups it owned, with `GROUP_CHANGED`
  to the others.

## /ws

`GET /ws` upgrades to a WebSocket over the same mTLS port, **over HTTP/1.1** (the server offers HTTP/2 for
`/query`; a WebSocket client asks for `http/1.1`, as OkHttp does). It needs an enrolled device's certificate: `401`
without one, `403` for a certificate outside the registry. Every message is binary, one `ptt.v1.Frame`
([proto/ptt.proto](../proto/ptt.proto), generated into `proto/pttv1`).

| Frame | Way | What |
|---|---|---|
| `Envelope` | server → device | `id sender_user sender_device recipient_user recipient_device type ciphertext server_timestamp` |
| `Ack { ids }` | device → server | the envelopes are stored on the phone; the server deletes them from the queue |
| `Send { client_id envelopes push_kind }` | device → server | one message, one envelope per device; `push_kind` is the wake-up it is worth ("Push" below) |
| `SendResult { client_id status envelope_ids devices detail }` | server → device | `ACCEPTED`, or why not |
| `Ping { id }` / `Pong { id }` | either way | answered with the same id |
| `QueueEmpty` | server → device | everything queued at connect was sent; what follows is live |
| `Presence { user online last_seen }` | server → device | a contact came online or went offline ("Presence" below) |

Envelope types: `PREKEY_MESSAGE`, `MESSAGE`, `SENDER_KEY_MESSAGE` (libsignal's), `PROVISIONING` (linking), and two
the server makes, `IDENTITY_KEY_CHANGED` and `PAIRED`.

**The rules of a Send** (`relay.Relay.Send`), checked in this order:

1. Well formed (`INVALID`): at least one envelope and at most 254, each naming a recipient device, with a ciphertext,
   of a type a device sends, no device twice, not the sending device, and **one other user** at most. A
   `PROVISIONING` envelope goes alone, to an enrolled device of the sender's own user (which may have no keys yet;
   `UNKNOWN_USER` when it isn't enrolled).
2. Each ciphertext is at most 256 KB (`TOO_LARGE`); a frame is at most 4 MB, or the server closes the connection.
3. The other user exists (`UNKNOWN_USER`), neither blocked the other (`BLOCKED`), and they are paired, or every
   envelope for that user carries the same unused pairing token of that user, or they share a group (`NOT_PAIRED`).
   A call invite (`push_kind` `PUSH_CALL`) goes only to a contact: 2026-11-22 (hen), group members who aren't
   contacts call each other in the group.
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

## Push (FCM)

From phase 3 a phone holds no socket in the background: a data-only FCM message wakes it, it connects to `/ws` and
takes its queue. The push carries **only the kind of wake-up**: no ids, no names, no sizes, no content. The server
sends it through FCM's HTTP v1 API with a service account (`fcm` in config.json, docs/install.md); without one the
server runs with no push, says so once in the log, and `serverInfo.push` is false.

**Registering.** `registerPush(token, notificationsEnabled)` → `true` stores the calling device's FCM registration
token and whether it shows notifications in the device registry (`fcm_token`, `notifications_enabled` in
`devices.json`; a renewed certificate keeps them). A phone calls it after enrolling, whenever FCM gives it a new
token, and whenever notifications are turned on or off (by the user, or the system's permission). A null or empty
token removes the registration. A token another device had is taken from it (a reinstalled app on the same phone).
`INVALID_TOKEN` for a token over 4096 characters, or with spaces or control characters. `me.pushRegistered` and
`me.notificationsEnabled` say what the server holds for the calling device. Revoking a device (`revoke`, `user
remove`) clears its token at once, and a token FCM answers as gone (`404` / `UNREGISTERED`, or `403`
`SENDER_ID_MISMATCH`) is dropped from the registry: the phone registers again when it next starts.

**When a push is sent.** When an envelope is queued for a device that is enrolled, has a token, and has no open
`/ws`. A connected device gets the envelope on its socket and no push. The kind comes from the Send:

| `Send.push_kind` | For the recipient's devices | For the sender's own other devices |
|---|---|---|
| unset, `PUSH_SYNC` | `sync` | `sync` |
| `PUSH_MESSAGE` | `message` | `sync` |
| `PUSH_NONE` | nothing | nothing |
| `PUSH_TALK`, `PUSH_CALL` (phases 5a and 5b) | `talk`, `call` | `sync` |

The server can't read the ciphertext, so the sending phone says what it is: `PUSH_MESSAGE` for a message the
recipient is notified of (text, a voice message, a message in a chat that isn't muted), `PUSH_SYNC` for what must
reach a sleeping phone but shows nothing (delivery and read receipts, contact and group changes, a muted chat, key
messages, the PAIRED and pair-request flow), and `PUSH_NONE` for what is stale by the time a phone wakes up
(typing). A Send that leaves it unset is `sync`. The envelopes the server makes (`PAIRED`, `IDENTITY_KEY_CHANGED`)
push `sync`; Presence frames are never queued and never push.

**What FCM gets.** One message per device:

```json
{ "message": {
    "token": "<the device's FCM token>",
    "data": { "kind": "message" },
    "android": { "priority": "HIGH", "collapse_key": "message" } } }
```

| kind | `android.priority` | `android.ttl` | `collapse_key` |
|---|---|---|---|
| `message` | `HIGH` when the device registered notifications as on, `NORMAL` otherwise | FCM's default (4 weeks) | `message` |
| `sync` | `NORMAL` | `86400s` | `sync` |
| `talk` | `HIGH` (notifications on), `NORMAL` otherwise | `30s` | `talk` |
| `call` | `HIGH` (notifications on), `NORMAL` otherwise | `30s` | `call` |
| `app_update` | `NORMAL` | `604800s` (a week) | `app_update` |

`app_update` comes from no Send: the server sends it to every device with a token, connected or not, when it sees a
new release of the app (docs/install.md, "App updates"). The phone then reads `appRelease` and offers the update.

`data.kind` is the only key in `data`, so the app reads it in `onMessageReceived` and connects. FCM lowers the
priority of an app whose high-priority pushes don't end in a notification, which is why the server sends `HIGH` only
to devices that said they show notifications, and only for kinds that show something; the app still checks
`RemoteMessage.getPriority()`.

**Debounce.** A burst of envelopes gives one push per device: the first is sent at once, and for the next 3 seconds
further envelopes for the device only mark that another push is due; at the end of the window one push of the most
urgent kind marked (`call` > `talk` > `message` > `sync`) is sent, unless the device connected meanwhile. FCM's
collapse keys do the rest on the phone's side: ten pending `message` wake-ups are one. A push that fails with `429`
or a `5xx` is tried twice more, a few seconds apart; other failures are logged and dropped (the envelope stays
queued, and the next push or the next connection gets it).

## Presence

A small "who is connected" signal, only between contacts (paired, neither blocked the other):

- **`presence(users)`** → `[{ user online lastSeen }]`: `online` when a device of the user has `/ws` open now;
  otherwise `lastSeen` is when the user's last device disconnected, rounded down to 5 minutes, or null when the
  server hasn't seen the user since it started (it is kept in memory only). Names that aren't contacts of the caller
  are left out of the answer, without an error, so it tells nothing about who exists.
- **The `Presence` frame** on `/ws` (`Frame.presence`: `user online last_seen`): sent live to the connected devices
  of every contact when the user's first device connects (`online: true`) or its last one disconnects (`online:
  false` and `last_seen`). Never queued, never pushed: a phone that was offline asks `presence` when it opens its
  chats.
- **`setPresenceVisible(visible)`** → the setting (`presence_hidden` in `users.json`; `me.presenceVisible`). Hiding
  works both ways: a user who hides theirs is shown to everyone as offline with no `lastSeen`, gets no Presence
  frames, and sees every contact the same way.

## Talk

Phase 5a, the clip path (2026-11-22). The server referees each conversation's floor and keeps each burst's clip; the
audio is AES-256-GCM made by the talker's phone with a key that goes end to end in an encrypted "clip start" message
(an ordinary Send), so the server stores and forwards ciphertext only. Frames on `/ws` (`proto/ptt.proto`):

- **`TalkStart`** `{burst_id, peer | group}`: the phone takes the floor of a one-to-one conversation (a contact only:
  2026-11-22, hen, a fellow group member who isn't a contact is reached in the group) or a group (a member).
  `burst_id` is 32 lowercase hex digits made by the phone; it is the clip's id too. The answer is a `TalkState`: `GRANTED`, `BUSY` (with who holds the floor) or `REFUSED` (`refusal` is
  `NOT_PAIRED`, `BLOCKED`, `NOT_MEMBER`, `UNKNOWN_USER` or `INVALID`). The same TalkStart again is GRANTED again.
- Every other active device of the conversation (the other user's, the talker's own other devices; in a group every
  member's but those blocked either way) gets **`STARTED`**, live only. `peer` is the conversation as that device sees
  it. A device answers with a **`TalkAck`** when it will play the burst. A device without `/ws` gets a `talk` push at
  once; a connected one that sends no TalkAck within 0.5 s is pushed too (`Pusher.Urgent`: its connection may be
  dead without the server knowing yet).
- **`ClipSegment`** `{burst_id, index, last, ciphertext}` from the talker, in order from 0 with no gaps, 1 byte to
  16 KB each: the server appends it to the clip and forwards it to the conversation's connected devices. A segment
  out of order, too large, or from anyone but the talker is answered `REFUSED` (`INVALID`).
- **`TalkEnd`**, the last segment, 60 seconds, or the talker's connection dropping for 3 seconds ends the floor:
  every device of the conversation, the talker's too, gets **`ENDED`** with `RELEASED`, `TIMEOUT` or `DROPPED`. After
  a TalkEnd the clip waits up to 10 seconds for its last segment.
- Floors and bursts live in memory: a restart lets every floor go (clips already stored stay).

Live frames go out through a queue per connection (512 frames); a device too slow to keep up misses some, and reads
the clip over `/blob` instead.

## Live talk

Phase 5b, the live path (2026-11-22). Each conversation has one LiveKit room: `g-<group id>` for a group,
`u-<hash of the two names>` for a pair. The clip path above always runs; a phone in the room hears a burst through
LiveKit at once and skips the clip stream.

- **`talkToken(peer | group)`** signs a LiveKit token for the calling device after the same checks as talking there
  (`NOT_PAIRED`, `BLOCKED`, `NOT_MEMBER`, `UNKNOWN_USER`, `INVALID`), for 10 minutes, for that room only, as identity
  `user.device`: join, publish the microphone, subscribe; no data messages (floor control stays on `/ws`).
  `LIVE_OFF` without LiveKit; `serverInfo.liveTalk` says whether it is there.
- The phone points LiveKit's client at the server's own address with the path **`/rtc`**: ptt-server passes it to
  LiveKit's signalling on loopback, for enrolled devices only (a certificate is required, as on `/ws`).
- Audio goes to LiveKit's media ports, encrypted end to end with LiveKit's frame encryption and the talk keys the
  phones swap in encrypted messages; LiveKit sees room names and timing, never audio.
- Taken out of a group, the user's devices are taken out of the group's room at once; unpairing (when the two share
  no group) and blocking take both out of their pair's room; a revoked device or a removed user is taken out of
  every room. Being in the same group's room, two members who blocked each other still share it: their phones
  don't play each other.

## Calls

Phase 6, server side (2026-11-22). A video call is signalled end to end: the caller's phone sends an encrypted call
invite (an ordinary Send with `push_kind` `PUSH_CALL`, high priority, kept 30 seconds) that carries a new call id and
the call's fresh media key; answers, hang-ups and "Recording" go the same way. The server adds only the room:

- **`callToken(call, peer | group)`**: `call` is the 32 hex digits the caller's phone made. After the same checks as
  talking in that conversation, the server makes the call's own LiveKit room, `c-<call id>`, with at most `livekit.max_call_devices` devices (config.json, 32 by default)
  and a short life once empty, and signs a token for it as for `talkToken`. The first callToken binds the id to its
  conversation; one from another conversation is `INVALID`. Calls are remembered in memory for a day.
- Taken out of the group, unpaired or blocked: out of that conversation's call rooms at once, as from its talk room;
  revoked or removed: out of every room.
## Saved calls

2026-11-22 (hen): this is a family keepsake app, so the server can keep calls for the family to watch later, like
home videos. 18:09 (hen): **only while someone in the call records it**. It holds the ciphertext only, so a kept call
can be played only by the people who were in it.

- **Recording.** `recordCall(call, peer | group)` (same checks as `callToken`, and the caller's device must be in the
  call's LiveKit room now, else `NOT_IN_CALL`) starts the recorder (package `recorder`): ptt-server joins the call's
  room as a hidden participant (`livekit.RecorderIdentity`, a token with no publish rights) that sends nothing, takes
  every participant's audio and the best layer of their video, and writes each stream to a Track blob as the frames
  arrive. Asking again answers the recording that goes on. `stopRecordingCall` (anyone in the room) stops it; it
  also stops when the device that started it leaves the room, when the room empties, after 4 hours, or when the
  server stops. `callToken` alone keeps nothing. The frames stay encrypted end to end with the call's key
  (LiveKit's frame encryption), which the server never has, so the server can't watch. It keeps the streams
  **forever**: they are exempt from `blob_days` until a way to delete them is designed.
- **Everyone in the call is told.** Calls are never kept silently. Once the recorder is in the room, the server sets
  the room's metadata (LiveKit sends it to every phone in the call: `RoomMetadataChanged`) to
  `{"recording": true, "by": "user.device", "startedAt": "<RFC 3339>"}`, and to `{"recording": false}` when it stops.
  Every phone shows a standing "Recording" badge, with who records, while it is true. The recording phone can't hide
  it: the server sets it.
- **A Track blob** (`blobs.Track`) is records (as a clip: a 4-byte big-endian length, then the record) of: 8 bytes
  of big-endian microseconds since the recording began, 1 byte of flags (1 = a key frame), then the frame as the
  sender encrypted it. Its meta names the call, the participant (`user.device`), the media (audio/video) and codec
  (`audio/opus`, `video/VP8`, `video/H264`, `video/H265`). The phones send call audio as RED (RFC 2198: each packet carries the
  Opus frame and a copy of the ones before), made before LiveKit's frame encryption, so its headers are encrypted
  and LiveKit won't strip it for a subscriber that can't take it. The recorder offers `audio/red` first and keeps
  each payload whole as an `audio/red` track; a phone decrypts each frame, then takes its primary block, the last
  (2026-11-22: before this, calls were kept without sound).
- **Event logs.** 2026-11-22 (hen): a saved call also keeps how each phone showed each video, so the crops can be
  replayed. While a call is kept, `logCallEvent(call, peer | group, event)` (a device in the room; 1 to 4096 bytes
  of base64, encrypted end to end with the call's key) appends the event to that device's event log: a Track blob
  of media `events` and codec `application/x-talk-events`, with records timed like the frames (microseconds since
  the recording began, flags 0, the event). The phones log, for example, Fill or Fit and the tile's shape for each
  video they show, and which way their camera is turned. `NOT_RECORDING` when the call isn't kept now. The logs end
  with the recording, and Save as file writes them into the .mkv as a data track.
- **`callRecording(call, peer | group)`** (a query, same checks as `callToken`) answers whether the call is kept now,
  who records it (`by`), when keeping began, and its tracks (blob id, identity, kind, codec, when it began, size, complete) that the caller
  may read. A phone reads each track with `GET /blob/<id>`, decrypts the frames with the call's key, and writes one
  Matroska file: a video and an audio track per person, lined up by `recordingStartedAt`, without re-encoding.
- **Who may read a kept call.** 2026-11-22 (hen): only the people who were in that call, meaning a device of theirs
  sent a stream the recorder kept, and who are still in that conversation, over the same mTLS and permission checks
  as every other blob. A group member who stayed out of the call, or joined the group later, isn't listed its tracks
  by `callRecording` and is refused them on `/blob`. The server holds ciphertext, so it can never watch. (The app's own per-phone "Save this call"
  from phase 6b is separate.)
- **Turning it off.** `serverInfo.keepsCalls` says the server can keep calls, and the call screen offers Record only
  then. Set `"keep_calls": false` in `livekit` to turn keeping off: `keepsCalls` is false and `recordCall` answers
  `RECORDING_OFF`.

## Blobs

Clips, voice messages and attachments are files of ciphertext in the blobs folder (`blob_dir`, default `blobs`; package
`blobs`), each `<id>.blob` beside `<id>.json` (who made it, for which conversation, its size, whether complete). They
are deleted `blob_days` (default 30) after they were made, by the hourly sweep. `/blob/<id>`, over mTLS, enrolled
devices only:

- **GET** by the maker, the other user of its one-to-one conversation, or a member of its group now (blocks apply);
  anyone else gets 404. A file is read once complete (409 before), from an offset with `Range: bytes=N-` (206). A clip
  is read while it grows: records (a 4-byte big-endian length, then a `ClipSegment` without its burst id) are sent
  as they arrive, until its last one, so a late or woken phone plays from the start and catches up. `Blob-Offset`
  (the size the server has) and `Blob-Complete` are answered.
- **HEAD**: the same headers, so a broken upload can go on.
- **PUT** a file (a voice message, an attachment, up to 100 MB) for `?peer=<user>` or `?group=<id>` (the same rule as
  talking there; 403 otherwise). The first PUT gives `Blob-Total`; each PUT's `Blob-Offset` says where its bytes go
  and must be the size the server has (409 with the right `Blob-Offset` otherwise). It is complete when it has
  `Blob-Total` bytes. Only its maker writes it.

## The queue

`ptt.db` (`database_file`), SQLite through `modernc.org/sqlite` (pure Go, no cgo), one row per (recipient device,
envelope): the envelope frame as it will be sent, its id and when it was queued (package `store`). A row goes when
its device acknowledges it, when the device is revoked, or after `queue_days` (default 30) without being taken. The
database runs in WAL mode; the server writes the log back into `ptt.db` when it stops.

## What the server sees

Who is paired with whom and who blocked whom, who sends to whom and when, how big each envelope is, the type of each
(a pair request is told apart by its token), the push kind the sender chose (message, sync, none), the public keys,
each device's FCM token, when each user is connected, and the IP addresses. Google sees that a device was woken, when,
and the kind (`message` or `sync`), nothing else. Never the content: text, receipts, typing, sync messages and key
messages are all ciphertext of the same kinds.

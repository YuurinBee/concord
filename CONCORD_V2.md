# Concord v2

`draft` `optional`

End-to-end encrypted, server-less group chat ("Communities") over Nostr.

This document is the concrete wire specification for the Concord protocol as implemented in
the Vector client. Where [`README.md`](https://github.com/VectorPrivacy/Vector/blob/master/docs/concord/README.md) explains the *philosophy*, this document
gives the exact event kinds, key derivations, encryption envelopes, tag layouts, and
publish/query procedures needed to implement an interoperable client from scratch.

Naming: **Concord** is the protocol; **Communities** is the user-facing feature. A *Community*
is what Discord calls a "server"; a *Channel* is a room within it.

> **Frozen wire format.** Everything in §2–§9 (HKDF labels, canonicalization byte layouts,
> tag names, sub-kind numbers, the protocol version string) is **frozen**. Any change to a
> labeled byte orphans every prior event and forces a migration. Golden test vectors in the
> Vector source pin these values.

> **v2 — gift-wrapped, author-addressed.** Concord v2 wraps every outer wire event in a
> standard [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) **gift wrap**
> (`kind 1059`) carrying a standard **seal** (`kind 13`) and **rumor** inside. The outer wrap
> is **signed by a key deterministically derived from the shared group key** (the channel key
> or server-root key) plus the channel/community id and epoch — the same HKDF inputs that v1
> used to produce a relay-filterable `z` pseudonym, now normalized to a secp256k1 scalar (§3).
> Every member derives the same keypair, so the wrap's **public key is the per-epoch group
> address**: clients query by `authors` instead of by `#z`. Because only a key-holder can
> compute the signing key, an outsider cannot manufacture an event that lands in a member's
> `authors` filter — closing the v1 DoS where anyone could spam a channel's `#z` tag and force
> members to download and trial-decrypt junk. The pubkey rotates per epoch exactly as the v1
> pseudonym did, preserving unlinkability.

---

## 1. Event kinds

Every Concord outer wire event is a standard NIP-59 **gift wrap, `kind 1059`**, signed by the
derived per-epoch group key (§3). Inside it is a standard **seal, `kind 13`**, signed by the
author's real identity, wrapping an unsigned **rumor**. The rumor's kind names the action.

Concord reuses preexisting Nostr kinds for the rumor wherever a clean standard fits, and keeps
a small block in the regular (`3000–9999`) range for actions that have no standard analogue.

| Rumor kind | Name | Plane | Standard reused |
|---|---|---|---|
| **9** | `COMMUNITY_MESSAGE` | append (message) | [NIP-29](https://github.com/nostr-protocol/nips/blob/master/29.md) group chat message |
| **7** | `COMMUNITY_REACTION` | append (reaction) | [NIP-25](https://github.com/nostr-protocol/nips/blob/master/25.md) reaction |
| **5** | `COMMUNITY_DELETE` | append (cooperative delete / hide) | [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) deletion |
| 3302 | `COMMUNITY_EDIT` | append (edit) | — (Concord-specific) |
| 3303 | `COMMUNITY_REKEY` | rekey | — (Concord-specific; ECDH per-recipient blobs) |
| 3306 | `COMMUNITY_PRESENCE` | append (join/leave) | — (Concord-specific) |
| 3307 | *retired* | — | **never reuse** |
| 3308 | `COMMUNITY_CONTROL` | control (authority + metadata) | — (Concord-specific) |
| 3309 | `COMMUNITY_KICK` | append (cooperative kick) | — (Concord-specific) |
| 3310 | `COMMUNITY_WEBXDC` | append (realtime peer signal) | — (Concord-specific) |
| 3311 | `COMMUNITY_TYPING` | append (typing) | — (Concord-specific) |

The block **3300, 3301, 3304, 3305** is **retired** — those v1 sub-kinds are now served by the
reused standard kinds (9, 7, NIP-17 DM, 5). **Never reuse** a retired number.

Two **Concord-specific addressable** kinds (NIP-01 parameterized-replaceable range
`30000–39999`) replace the v1 NIP-78 (`kind 30078`) carriers; Concord defines **no** NIP-78
events:

| Kind | Name | Plane | Notes |
|---|---|---|---|
| **33301** | `COMMUNITY_PUBLIC_INVITE` | invite | addressable; public-invite bundle + revocation tombstone, token-signed (§7.2) |
| **33302** | `COMMUNITY_USER_LIST` | sync | addressable; per-user self-encrypted Community List / Invite List (§8) |

Kinds 33301–33302 are frozen; **never reuse** a number.

Other standard kinds in play:

- **Kind 1059** (NIP-59 gift wrap) — every outer wire event. **Kind 13** (NIP-59 seal) — every
  inner authorship envelope.
- **Kind 14** (NIP-17 private DM) gift-wrapped per NIP-17 carries the **targeted invite bundle**
  (§7.1).
- **Kind 5** (NIP-09 deletion) is also the relay-honored deletion an author publishes to remove
  their own append-plane events (§4.5): a kind-5 rumor wrapped in a fresh gift wrap.

The **owner attestation** is no longer a standalone event of any kind: ownership is proven
*cryptographically* by the **self-certifying `community_id`** (§2, §6.4), with an owner-signed
genesis edition proving secret-key possession. No NIP-78 (kind 30078) event is used anywhere.

The seal's kind is always 13; the rumor's kind names the action. Inner control/edition rumors
are always kind 3308 regardless of sub-kind (§6).

---

## 2. Identities and keys

A Community runs on a small set of keys.

| Key | Bytes | Role |
|---|---|---|
| **Identity key** | secp256k1 keypair | Each member's normal Nostr `npub`. Signs the **seal** (kind 13 → authorship); roster authority is keyed by it. Never on the wire in cleartext. |
| **Server-root key** (`ServerRootKey`) | 32 | The `@everyone` base secret. Gates the control plane + metadata. Held by every member. Always distinct from every channel key. |
| **Channel key** (`ChannelKey`) | 32 | Per-channel symmetric secret. Gates one channel's messages. A member holds one per channel they can read. |
| **Group signing key** (`GroupSigningKey`) | secp256k1 keypair | **Derived** (§3) from a shared group key (channel or server-root) + an id + epoch. Every member derives the same keypair. Signs the outer gift wrap and supplies the NIP-44 conversation key for the wrap+seal ciphertext. Its **pubkey is the per-epoch wire address**. |

Identifiers:

- **`CommunityId`** — a **self-certifying commitment to the owner's identity key** (NOT random,
  NOT a timestamp snowflake): `community_id = SHA-256("concord/v1/community-id" ||
  owner_xonly[32] || owner_salt[32])` (§3.5). Lowercase hex on the wire. Because the id commits
  to `owner_xonly`, anyone holding `(owner_xonly, owner_salt)` can recompute and **verify which
  key minted the community**; forging ownership of an *existing* id is second-preimage resistance
  (infeasible). See §6.4.
- **`OwnerSalt`** — random 32 bytes mixed into `CommunityId` so two communities owned by the same
  npub get distinct ids (and so the id is not a bare hash of a public key). Shipped in metadata
  and invites (§6.4); lowercase hex.
- **`ChannelId`** — random 32 bytes. Lowercase hex.
- **`Epoch`** — `u64`, the read-access clock. Bumps only on a rekey. Serialized **big-endian**
  in HKDF info, decimal string in tags.
- **`GroupAddress`** — the x-only public key of the per-epoch `GroupSigningKey`; the value
  clients place in an `authors` filter. (Replaces v1's `Pseudonym`/`z` tag.)

`CommunityId` is a SHA-256 output and `ChannelId` is random-32, so neither can collide (other
than negligibly) with the all-zero **server-root scope sentinel** (`0x00…00`, 64 hex zeros) used
by rekey scoping (§5); a `CommunityId` that hashes to all-zero is rejected at mint (re-roll the
salt).

There is no longer any single-use ephemeral wire key: the outer signer is the shared, member-
derivable `GroupSigningKey`. (Pairwise NIP-17 invites in §7.1 still use NIP-59's own pairwise
gift-wrap signing key, per that NIP.)

---

## 3. Key derivation (HKDF) — frozen

Every Concord derivation is:

```
HKDF-SHA256(IKM, salt = ∅, info, L = 32)
info = utf8(label) || 0x00 || id32 || epoch_be
```

- `label` — an ASCII purpose string, no terminator.
- `0x00` — a single separator byte.
- `id32` — a raw 32-byte id (channel id, community id, or scope id), **never hex**.
- `epoch_be` — the epoch as `u64` big-endian (8 bytes); **omitted** where noted.

`salt = ∅` means RFC-5869 with no salt (a zero-length salt; equivalent to 32 zero bytes for
HMAC-SHA256). `L = 32` (the expand never fails at this length).

### 3.1 Frozen labels

| Label string | id32 | epoch | Output |
|---|---|---|---|
| `concord/v1/channel-pseudonym` | channel id | yes | channel **group signing key** seed (§3.4) |
| `concord/v1/recipient-pseudonym` | scope id | yes | rekey blob locator |
| `concord/v1/rekey-pseudonym` | channel id | yes | channel-rekey **group signing key** seed |
| `concord/v1/base-rekey-pseudonym` | community id | yes (new epoch) | server-root-rekey **group signing key** seed |
| `concord/v1/public-invite-key` | all-zero | no | public invite NIP-44 decrypt key |
| `concord/v1/public-invite-locator` | all-zero | no | public invite `d`-tag locator |
| `concord/v1/public-invite-signer` | all-zero | no | public invite signing key (→ secp256k1 scalar) |
| `concord/v1/banlist-locator` | community id | no | banlist entity id |
| `concord/v1/grant-locator` | community id (IKM) + member-xonly (in info) | no | per-member grant entity id |
| `concord/v1/invite-links-locator` | community id (IKM) + creator-xonly (in info) | no | per-creator invite-links entity id |
| `concord/v1/dissolved-locator` | community id | no | dissolution tombstone entity id |
| `concord/v1/dissolved-pseudonym` | community id | no | dissolution **group signing key** seed (rotation-stable) |

> **`concord/v1` label prefix.** Every label uses the `concord/v1/…` prefix (the `v1` here is the
> *derivation* version, independent of the `v2` wire/protocol version — the HKDF construction is
> unchanged, only the prefix string differs from earlier drafts). The `*-pseudonym` labels seed a
> **group signing key** (§3.4) rather than a 32-byte `z` value: the seed is fed through the
> scalar-normalization of §3.4 to become a keypair, whose pubkey is the wire address. The labels
> are **frozen** — changing any byte orphans every derived coordinate; the golden vectors in
> Appendix A pin these exact strings.

Notes:

- The **channel group signing key** uses `IKM = channel key`. Every member derives the same
  keypair from the shared channel secret; rotating the epoch rotates the keypair (and thus the
  `authors` address — unlinkability).
- The **control-plane group signing key** (§6.5) reuses the `channel-pseudonym` label/derivation
  but with `IKM = server-root key` and `id32 = community id`. Domain separation rests on the
  distinct IKM (server-root is always ≠ every channel key) — NOT a distinct label.
- The **rekey group signing key** keys off the **server root** (not the channel key), so a member
  can locate a rekey for any epoch holding only the server root — epochs are independently
  recoverable, no forward ratchet.
- The **base-rekey group signing key** keys off the **prior** server root (the only handle a
  member holds before a base rotation).
- For `grant-locator` and `invite-links-locator`, the `info` byte string takes the form
  `label || 0x00 || subject_xonly` (no epoch) while the **IKM is the community id**. (This is
  the `build_info(label, subject_xonly, None)` shape with `IKM = community_id.0`.)

### 3.2 Locator vs. epoch stability

Entity locators (`banlist`, `grant`, `invite-links`, `dissolved`) derive from the **community
id**, not the server-root key, so they are **stable across a server-root rotation**. This is
load-bearing for re-anchoring (§5.3) and dissolution discovery (§9.3): a fresh joiner who only
holds a later epoch's root can still compute these coordinates.

### 3.3 Deriving a secp256k1 scalar from HKDF

`public_invite_signer` must produce a valid secp256k1 secret key. Use reject-and-retry: compute
`HKDF(...info)`; if it is not a valid scalar, append a single incrementing counter byte to
`info` and retry. The reject branch is ~2⁻¹²⁸ rare but the counter keeps it deterministic and
cross-implementation reproducible.

### 3.4 The group signing key (frozen)

The **group signing key** is the v2 replacement for the v1 `z` pseudonym. It is a secp256k1
keypair every member can derive, whose x-only **public key is the per-epoch wire address** (the
value clients query with `authors`) and whose **secret key signs the outer gift wrap** and seeds
the NIP-44 conversation key for the envelope (§4.1).

```
seed         = HKDF(...info)                       // the §3.1 pseudonym output, 32 bytes
group_sk     = scalar_normalize(seed, info)        // §3.3 reject-and-retry → valid secp256k1 sk
group_pk     = secp256k1_xonly_pubkey(group_sk)    // 32-byte x-only; the wire address
conv_key     = NIP-44 v2 ConversationKey::derive(group_sk, group_pk)  // self-ECDH on the derived key
```

- `scalar_normalize` is exactly §3.3 (reject-and-retry with an appended counter byte) so the
  result is always a valid scalar and every member computes the identical keypair.
- `group_pk` indexes the conversation/channel/epoch on relays. Only a holder of the underlying
  group key can compute `group_sk`, so **only members can emit events that match the address** —
  an outsider cannot spam a member's `authors` filter (the v1 `#z` DoS is closed).
- `conv_key` is the NIP-44 conversation key derived by self-ECDH of the group keypair with
  itself (`derive(group_sk, group_pk)`). Every member arrives at the same `conv_key`; it
  encrypts both the gift-wrap content and the seal content (§4.1). No separate raw-key envelope
  is needed — the one derived keypair is both signer and encryptor.

The four `*-pseudonym` derivations (`channel`, `rekey`, `base-rekey`, `dissolved`) and the
control-plane reuse (§6.5) all feed §3.4 to produce their respective group keypairs.

### 3.5 Community-id commitment (frozen)

The `CommunityId` is a SHA-256 commitment binding the community to its owner's identity key:

```
COMMUNITY_ID_LABEL = "concord/v1/community-id"
community_id = SHA-256( utf8(COMMUNITY_ID_LABEL) || owner_xonly[32] || owner_salt[32] )
```

- `owner_xonly` — the owner's 32-byte x-only identity pubkey.
- `owner_salt` — fresh random 32 bytes minted with the community (§2), so the same owner can run
  many communities and the id is never a bare hash of a public key.
- The label is concatenated **raw** (`utf8`, no separator byte) ahead of the two 32-byte fields;
  the total preimage is `len(label) + 64` bytes.
- Reject an all-zero output at mint (re-roll `owner_salt`) so `community_id` can never equal the
  server-root scope sentinel (§2, §5.1).

This is a plain SHA-256 commitment, **not** an HKDF derivation — it does not use the §3 HKDF
construction. Verification (§6.4) recomputes `community_id` from a presented `(owner_xonly,
owner_salt)` and checks equality; a second-preimage to claim a *different* owner for an existing
id is infeasible.

---

## 4. The message envelope (append plane: kinds 9, 7, 5, 3302, 3306, 3309–3311)

Every append-plane event is a standard NIP-59 three-layer construction, where the **outer wrap
is signed by the derived group key** (§3.4) instead of a random one-time key.

```
rumor       = unsigned Nostr event (kind = the append kind: 9/7/5/3302/3306/3309/3310/3311)
seal        = kind-13 event, content = NIP-44 v2 encrypt(conv_key, rumor.as_json()),
              SIGNED BY THE AUTHOR'S REAL IDENTITY KEY  (authorship)
gift wrap   = kind-1059 event, content = NIP-44 v2 encrypt(conv_key, seal.as_json()),
              SIGNED BY group_sk,  tags: ["p", group_pk], ["v", "2"]
```

`conv_key`, `group_sk`, `group_pk` are the group signing key triple of §3.4 for this channel
(or server root) and epoch. The wrap's `pubkey` **is** `group_pk` — the relay-filterable
address. The `["p", group_pk]` tag is NIP-59-conformant (it equals the signer here, since the
"recipient" is the whole group) and lets generic relays honor recipient-scoped deletion (§4.5).

### 4.1 Symmetric primitive

The envelope uses **standard NIP-44 v2** under the group conversation key:

- `conv_key = ConversationKey::derive(group_sk, group_pk)` — self-ECDH on the §3.4 group keypair.
- `seal(plaintext) = NIP-44 v2 encrypt(conv_key, plaintext)`; `open(content) = NIP-44 v2
  decrypt(conv_key, content)`. A wrong group key (hence wrong `conv_key`) or a tampered payload
  fails the MAC.

Because `conv_key` is derived from the same shared group keypair every member holds, the seal
and the wrap can use one key — there is no separate raw-key NIP-44 layer as in v1.

### 4.2 Rumor

The rumor is a normal **unsigned** Nostr event (NIP-59 rumor: it has an `id` but no `sig`). Its
authorship is proven by the seal that wraps it (§4.4), signed by the author's real identity key.
It carries:

- `kind` = the append kind (9/7/5/3302/3306/3309/3310/3311).
- `pubkey` = the author's real identity pubkey (the rumor `pubkey` must equal the seal signer;
  §4.3).
- `created_at` = the message send time in **seconds** (`ms / 1000`).
- tags:
  - `["channel", <channel_id hex>]` — **required**, must appear exactly once.
  - `["epoch", <epoch decimal>]` — **required**, must appear exactly once.
  - `["ms", <0–999>]` — the sub-second offset; the open side reconstructs full ms as
    `created_at * 1000 + ms`. Reject an `ms` value > 999 (treated as absent).
  - `["e", <target_id>, "", "reply"]` — for a reply (9), the reacted-to (7), the edited
    (3302), the deleted (5) target. NIP-25/Vector reply convention.
  - `["emoji", <shortcode>, <url>]` — NIP-30 custom emoji, one per shortcode used.
  - `["imeta", ...]` — NIP-92 attachments (§4.6), one per file.
  - `["vac", <entity hex>, <version>, <edition-hash hex>]` — authority citation (§6.3) on a
    non-owner moderation action (a kind-5 hide or 3309 kick).

The rumor content is the message text (9), the reaction emoji (7), the new text (3302),
empty (5/3309), `"join"`/`"leave"`/attributed JSON (3306, §9.1), `"typing"` (3311), or a
WebXDC JSON op (3310, §9.2).

### 4.3 The binding triad

The three layers must bind to one coordinate:

1. The **wrap signer** (`group_pk`) must equal the group address derived for the channel id and
   the exact epoch whose key produced `conv_key` (**strict equality**) — this is implicit in
   §3.4 (a holder of a different key produces a different `group_pk`, which simply won't match
   the `authors` filter, and whose `conv_key` won't open the content).
2. The **seal signer** (real identity) must equal the **rumor `pubkey`** — authorship binding.
3. The rumor's `channel`/`epoch` tags must equal the channel id and the exact epoch whose key
   decrypted the payload (**strict equality**, not a membership test).

A receiver that finds any mismatch drops the event. This defeats insider replay/splice across
channel or epoch — a member holding the channel key cannot lift another member's sealed content
into a different context (the seal signer + the bound `channel`/`epoch` pin it).

A **duplicate** `channel` or `epoch` tag on the rumor is rejected (it is constructable by any
channel-key holder, so first-match would be nondeterministic). A duplicate `e` (reply) tag on a
*message* (kind 9) is tolerated (cosmetic); ambiguous targets on reaction/edit/delete are
rejected by the shared parser.

### 4.4 Layers in detail

- **Rumor** — unsigned; the real action. Has an `id` (the deterministic event hash) used for
  dedup and `e`-tag references.
- **Seal** (`kind 13`) — `content` = NIP-44 ciphertext of the rumor JSON under `conv_key`,
  `tags: []`, **signed by the author's real identity key**. This is the authorship proof and is
  identical in shape to a NIP-59 seal.
- **Gift wrap** (`kind 1059`) — `content` = NIP-44 ciphertext of the seal JSON under `conv_key`,
  **signed by `group_sk`**, `pubkey = group_pk`. tags:
  - `["p", <group_pk hex>]` — NIP-59 recipient tag (here the group address itself).
  - `["v", "2"]` — the Concord protocol version. **Checked before any decryption**; an unknown
    version is rejected gracefully.

The opener verifies `v == "2"`, confirms the wrap `pubkey` is a `group_pk` it derived (i.e. it
matched an `authors` it subscribed to), decrypts the wrap under `conv_key` to get the seal,
verifies the seal's Schnorr signature, decrypts the seal to get the rumor, verifies the rumor
`id`, then enforces the binding triad (§4.3).

### 4.5 Deletion

There is **no retained-key relay deletion** as in v1 — the outer signer is the shared group
key, so a relay-level kind-5 by `group_sk` could be forged by any member. Instead, **deletion is
an ordinary append-plane action: a kind-5 rumor wrapped in a fresh gift wrap** (signed by the
*current* epoch's `group_sk`), referencing the target rumor id via
`["e", <target_rumor_id>, "", "reply"]`.

- **Self-delete:** honored when the kind-5 rumor's author (the seal signer) equals the target
  rumor's author.
- **Moderation-hide / reaction-revoke:** honored under the §9.3 authority rules.

Because relays index by the recipient `p`-tag (`group_pk`), a relay MAY additionally honor a
NIP-09 kind-5 / NIP-62 vanish from the recipient per NIP-59's deletion rule — but Concord does
not rely on this for correctness; the cooperative kind-5 tombstone (honored by peers) is the
mechanism. A dissolved community accepts only self-deletes (§9.6).

Far-future rumor timestamps are clamped to ~now on open (an author-controlled `created_at`
inside the ciphertext is not relay-clamped, so a hostile member could otherwise pin a message
to the top forever).

### 4.6 Attachments (NIP-92 `imeta`)

Unlike NIP-17 DMs (one media item per event), a Community message carries a caption in
`content` plus **one `imeta` tag per attachment**, so one event mixes text and N files. Each
file is encrypted with a **fresh random AES-GCM key + nonce** (the NIP-17 attachment
technique), uploaded to Blossom, and referenced by URL. The `imeta` entries are
space-delimited `key value` strings:

```
["imeta",
  "url <blossom url>",
  "m <mime>",
  "encryption-algorithm aes-gcm",
  "decryption-key <hex>",
  "decryption-nonce <hex>",
  "size <bytes>",          (optional)
  "ox <sha256-of-plaintext hex>",  (optional)
  "name <original filename>",      (optional; may contain spaces)
  "thumb <thumbhash>",     (optional, images)
  "dim <w>x<h>",           (optional, images)
  "webxdc <id>"            (optional, Mini Apps realtime)
]
```

Required for a valid attachment: `url`, `decryption-key`, `decryption-nonce`. A value is
everything after the first space (so filenames with spaces survive).

A **webxdc Mini App** is just such an attachment: a `.xdc` (ZIP) file with `m
application/x-webxdc` (the official DeltaChat MIME) and a `webxdc <id>` property carrying a
randomly generated coordination identifier, exactly the app-attachment form of
[NIP-DC](https://github.com/nostr-protocol/nips/pull/2230) (which itself rides a NIP-92
`imeta` / NIP-94 kind-1063 attachment). Concord encrypts the `.xdc` like any other attachment.
The `webxdc` id is the coordination handle that the realtime peer signal (kind 3310, §9.2)
references as its `topic` — the same value NIP-DC carries in its realtime/state `i` tag.

---

## 5. Rekey (kind 3303) — relocation / removal

A rekey rotates a key for a **new epoch** and delivers the fresh key only to the members who
**stay**, one **per-recipient blob** each. Used for hard removal (ban), re-founding, going
members-only, or a scheduled rotation. A removed member can read the rekey *header* but recovers
no new key.

### 5.1 Rekey scope

```
RekeyScope = Channel(channel_id)  | ServerRoot
id32(scope) = channel_id          | 0x00…00 (all-zero sentinel)
```

### 5.2 Per-recipient blob

The atom delivered to one staying member:

```
pairwise_secret = NIP-44 v2 ConversationKey::derive(my_sk, their_pk)   (symmetric ECDH)
locator         = recipient_pseudonym(pairwise_secret, scope, new_epoch)  (hex)
bound_plaintext = scope.id32()[32] || new_epoch_be[8] || new_key[32]      (72 bytes, fixed-width)
wrapped         = NIP-44 v2 seal(pairwise_secret, bound_plaintext)        (base64)
blob            = { "locator": <hex>, "wrapped": <base64> }
```

A recipient recomputes the identical `pairwise_secret` from `(their_sk, sender_pk)`, finds their
blob by `locator` (no trial decryption), decrypts, and **verifies the bound `scope`+`epoch`
match** what they opened under (strict-equality binding defeats cross-coordinate splice). A
removed member cannot even *find* a slot for a pair they are not in.

### 5.3 The 3303 event

Rumor (rotator-authored, unsigned, kind 3303; sealed by the rotator's real identity in §5.3's
wrap):

- `content` = JSON array of blobs.
- tags:
  - `["scope", <scope.id32() hex>]` — the all-zero hex means `ServerRoot`.
  - `["newepoch", <decimal>]`
  - `["prevepoch", <decimal>]`
  - `["prevcommit", <hex>]` — a commitment to the prior epoch's key (fork detection, §5.4).
- **Invariant:** `new_epoch > prev_epoch` (enforced at mint; reject otherwise).

The rumor is sealed (kind 13, signed by the rotator's real identity) and gift-wrapped (kind
1059) exactly as §4, but the **wrap's group signing key** is the rekey address:

- **Channel rekey:** the group signing key derives from the **server-root key** via the
  `rekey_pseudonym` label (`rekey_group_key(server_root, channel_id, new_epoch)`); the wrap is
  signed by it and `conv_key` encrypts the seal/wrap. The new channel key lives only in the
  per-recipient blobs (NIP-44-encrypted under each pairwise ECDH secret), never under the
  server-root-derived envelope.
- **Server-root (base) rekey:** the group signing key derives from the **prior** server-root
  key via the `base_rekey_pseudonym` label
  (`base_rekey_group_key(prior_root, community_id, new_epoch)`). The new root lives only in the
  blobs.
- tags: `["p", <group_pk hex>]`, `["v", "2"]`.

Clients locate a rekey by `authors = [group_pk]` (the rekey address); members who lack the
relevant root cannot compute `group_pk` and so never see it surface.

Cap: at most **120 blobs** per 3303 rumor (fits under the common 64 KiB relay
`max_event_size`). A rotation with more recipients must split across events; receivers reject a
larger array after decrypting (so a hostile array is also size-bounded).

### 5.4 Epoch-key commitment

```
prev_key_commitment = SHA-256( "concord/v1/epoch-key-commitment" || prev_epoch_be[8] || prev_key[32] )
```

Two managers who both rotate epoch N→N+1 produce a *detectable* fork (resolved by
authority-first → time → id), and a recipient holding the prior key can confirm the rotator did
too.

### 5.5 Multi-epoch read

After catching up across one or more rekeys, a member **retains every epoch key** for a channel.
Reads query `authors = [group_pk per held epoch]` (an OR-set) and select the decryption key by
the wrap's signer (`group_pk`). Per-epoch keys are non-ratcheted, so any retained epoch decrypts
directly (random-access). Server-root-scoped epoch keys are stored under the all-zero scope id
(`SERVER_ROOT_SCOPE_HEX`).

---

## 6. Control plane (kind 3308) — keyless authority + metadata

Write authority does **not** come from the outer wrap signer (which is the shared, member-
derivable group key). Read access = key possession; **write authority = a member's npub rank in
the owner-rooted roster**, proven by the **seal** signature. The control plane is a set of
per-entity append **editions**, each real-npub-signed (the seal) inside the encryption and
version-chained.

### 6.1 Sub-kinds (`vsk` tag)

A control edition's **rumor** (kind 3308) carries `["vsk", <n>]`:

| vsk | Entity | entity_id (coordinate) | Content |
|---|---|---|---|
| 0 | GroupRoot (community metadata) | `community_id` | `CommunityMetadata` JSON (§6.6) |
| 1 | RoleMetadata | `role_id` | `Role` JSON (§6.2) |
| 2 | ChannelMetadata | `channel_id` | `ChannelMetadata` JSON (`{"name": ...}`) |
| 3 | Grant (per member) | `grant_locator(community_id, member_xonly)` | `MemberGrant` JSON (§6.2) |
| 4 | Banlist | `banlist_locator(community_id)` | JSON array of banned pubkeys (hex) |
| 5 | RoleOrder | *(reserved, unbuilt)* | — |
| 6 | *(public-invite bundle — token-signed kind 33301, not a 3308 edition; §7.2)* | — | — |
| 7 | *retired (was owner attestation; ownership is now the self-certifying `community_id`, §6.4)* | — | **never reuse** |
| 8 | InviteLinks (per creator) | `invite_links_locator(community_id, creator_xonly)` | JSON array of active link locators (hex) |
| 9 | *(public-invite revocation tombstone — token-signed kind 33301, §7.2)* | — | — |
| 10 | GroupDissolved tombstone | `dissolved_locator(community_id)` | `{}` (chain-free, §9.3) |

Sub-kinds 0–10 are all spoken for; **never reuse** a number. (`vsk` 6/9 are carried on the
addressable public-invite kind 33301, not on a 3308 control edition.)

### 6.2 Roles and grants

```jsonc
// Role (vsk=1). role_id is a random 32-byte hex id (stable across renames; the entity coordinate).
{
  "role_id": "<64 hex>",
  "name": "Admin",
  "position": 1,            // lower = higher authority; owner is the implicit position 0
  "permissions": <u64>,     // bitfield, see below
  "scope": {"kind": "server"} | {"kind": "channel", "channel_id": "<hex>"},
  "color": <u32>            // cosmetic, 0 = theme default
}

// MemberGrant (vsk=3). An empty role_ids is a revoke.
{ "member": "<member pubkey hex>", "role_ids": ["<role_id>", ...] }
```

Permission bits (frozen positions — append a reserved bit, never renumber):

| Bit | Permission |
|---|---|
| `1 << 0` | `MANAGE_ROLES` |
| `1 << 1` | `MANAGE_CHANNELS` |
| `1 << 2` | `MANAGE_METADATA` |
| `1 << 3` | `KICK` |
| `1 << 4` | `BAN` |
| `1 << 5` | `MANAGE_MESSAGES` |
| `1 << 6` | `CREATE_INVITE` |
| `1 << 7` | *retired (was MANAGE_INVITES) — never reuse* |
| `1 << 8` | `VIEW_AUDIT_LOG` |
| `1 << 9` | `MENTION_EVERYONE` |
| `1 << 10`+ | reserved (MANAGE_EMOJI, PIN_MESSAGES, MANAGE_EVENTS) |

The MVP auto-creates one server-scope **Admin** role at `position 1` holding every management
bit (`ADMIN_ALL`). A role holding any bit in the `MANAGEMENT_MASK` (every management bit except
the purely-social `MENTION_EVERYONE`) marks its holder an "admin" (the crown).

**Authority rules** (every honest client recomputes these identically):

- A member's **effective permissions** = the union of their granted roles' bits.
- A member's **highest position** = the minimum `position` among their roles (the owner is the
  implicit position 0, supreme and unremovable).
- To act on a target requiring permission `P`: the actor must hold `P` **and strictly outrank**
  the target (the actor's highest position is a *lower* number). Equal cannot act on equal (an
  admin cannot ban/manage a peer admin). The **owner is supreme** (always authorized) and is
  **never a valid target**.

### 6.3 Edition structure and authority citation

An edition's **rumor** is kind 3308; its authorship is proven by the **seal** (kind 13) signed
by the actor's real identity key (so the rumor `pubkey` = the seal signer = the acting member):

- tags:
  - `["vsk", <n>]` — the sub-kind.
  - `["eid", <entity_id hex>]` — the entity coordinate.
  - `["ev", <version decimal>]` — the per-entity monotonic version (starts at 1).
  - `["ep", <prev_edition_hash hex>]` — the previous edition's hash; **absent** on the genesis
    (v1) edition.
  - `["v", "2"]` — protocol version.
  - `["vac", <authorizing-entity hex>, <version>, <edition-hash hex>]` — the **authority
    citation**: the grant edition the actor claims authority under. **Absent when the owner
    acts** (supreme, cites nothing); required for a non-owner authority action. A verifier
    confirms it has synced that exact grant to ≥ the cited version before honoring the action,
    then resolves the actor's *current* rank against its refuse-downgrade-protected roster.
- `content` = the entity payload JSON.

All of `vsk`/`eid`/`ev`/`ep`/`vac` must appear **at most once**; a duplicate is rejected (it
would make the edition's canonical bytes ambiguous and diverge the chain).

### 6.4 Owner proof (self-certifying community id)

Ownership is proven **cryptographically by the `community_id` itself** (§3.5), not by trusting a
transported claim. Two facts establish the owner:

1. **The id commits to the owner's key.** Given `(owner_xonly, owner_salt)`, a verifier recomputes
   `community_id = SHA-256(COMMUNITY_ID_LABEL || owner_xonly || owner_salt)` and accepts
   `owner_xonly` as the **claimed** owner **iff** it reproduces the `community_id` in hand. An
   attacker cannot point an existing community at a different owner (that is a second-preimage on
   SHA-256), and cannot frame an innocent npub (recomputing for someone else's key yields a
   different, unrelated id).
2. **The owner holds the secret key.** The genesis GroupRoot edition (vsk=0, version 1) MUST be
   **sealed-signed by `owner_xonly`** (the seal in §6.5 is signed by the real identity key). This
   proves possession of the owner secret key — not merely knowledge of the public key — and binds
   the proof to a real, version-1 control edition rather than a free-floating event.

So the proven owner = the `owner_xonly` that (a) reproduces `community_id` via §3.5 **and** (b)
signed the genesis vsk=0 edition. No standalone attestation event (and **no kind 30078**) is
needed: the `owner_salt` travels in metadata/invites (§6.6, §7) so any party can run check (1),
and the owner-signed genesis edition (which every member syncs) provides check (2).

`OwnerProof` (the transported material; embedded, never its own event):

```jsonc
{ "owner": "<owner_xonly hex>", "salt": "<owner_salt hex>" }
```

A consumer keeps an `OwnerProof` **only if** it reproduces the `community_id` it is paired with
(§7 invite acceptance refuses a mismatching proof). The bootstrapping-joiner path (§6.7) then
additionally requires the genesis vsk=0 edition to be owner-signed before trusting authority.

### 6.5 Sealing and addressing a control edition

A control edition is sealed and gift-wrapped exactly as §4, keyed off the **server-root group
signing key**:

```
group_sk/pk/conv_key = control_group_key(server_root, community_id, epoch)   // §3.4 + §6.5 note
seal      = kind-13, content = NIP-44 v2 encrypt(conv_key, rumor.as_json()),
            signed by the actor's REAL IDENTITY key   (authorship)
gift wrap = kind-1059, content = NIP-44 v2 encrypt(conv_key, seal.as_json()),
            signed by group_sk,  tags: ["p", group_pk], ["v", "2"]
```

`control_group_key = group_key(channel-pseudonym, IKM = server_root, id32 = community_id, epoch)`
(the `channel-pseudonym` derivation with `IKM = server_root`, `id32 = community_id`, fed through
§3.4). Only members (who hold the server root) can compute `group_pk`; outsiders cannot find or
spam the control address.

The opener checks `v == "2"`, confirms the wrap signer is the `control` `group_pk` it derived,
decrypts under `conv_key`, parses the seal, verifies the **seal** signature (the actor's
identity), decrypts the rumor, computes `self_hash`, then folds (§6.7). A wrong server-root key
yields a different `group_pk`/`conv_key` — which is also how **cross-community** replay is
rejected. Cross-epoch replay within the *same* community is intentionally NOT blocked at the
envelope (the control plane must be re-wrappable under a new epoch for re-anchoring); the version
chain's refuse-downgrade is the defense.

### 6.6 GroupRoot / Channel metadata content

```jsonc
// CommunityMetadata (vsk=0)
{
  "name": "...",
  "relays": ["wss://...", ...],            // ≤ 5 distinct (MAX_COMMUNITY_RELAYS)
  "description": "..." | absent,
  "icon":   {CommunityImage} | absent,     // encrypted blob ref, §6.6.1
  "banner": {CommunityImage} | absent,
  "owner": "<owner_xonly hex>",            // the committed owner key (§6.4)
  "owner_salt": "<owner_salt hex>"         // so any reader can recompute & verify community_id
}

// ChannelMetadata (vsk=2)
{ "name": "..." }
```

The genesis (version 1) GroupRoot edition MUST be sealed-signed by `owner` (§6.4 check 2); the
`owner`/`owner_salt` fields let any reader recompute `community_id` (§6.4 check 1). A verifier
rejects metadata whose `(owner, owner_salt)` does not reproduce the `community_id`.

#### 6.6.1 CommunityImage (encrypted logo/banner)

A community logo or banner is encrypted with a fresh random AES-GCM key+nonce, uploaded to
Blossom (the same technique as message attachments), and referenced from inside the
server-root-sealed metadata, so possession of the server root (every member) gates the image.

```jsonc
{ "url": "<blossom url>", "key": "<aes-gcm key hex>", "nonce": "<hex>", "hash": "<sha256 plaintext hex>", "ext": "png" }
```

### 6.7 Version chain (per entity)

Each entity is a chain of editions. The **edition hash** is a domain-separated,
length-prefixed SHA-256:

```
EDITION_LABEL = "concord/v1/edition"
signing_bytes = u64_be(len(EDITION_LABEL)) || EDITION_LABEL
             || entity_id[32]
             || u64_be(version)
             || has_prev(1 byte: 1 or 0) || prev_hash[32 or 32 zero bytes]
             || u64_be(len(content)) || content
edition_hash  = SHA-256(signing_bytes)
```

The next edition's `ep` (prev_hash) must equal the head's `edition_hash`. The citation (`vac`) is
**not** part of `signing_bytes` (it is per-action metadata, covered only by the seal signature).

**Fold rules** — given the set of (seal-signature-verified) editions for one entity and a held
floor `(version, hash)`:

- **Refuse-downgrade:** ignore any edition below the floor version.
- **Equal-version fork:** the winner is the **lower rumor edition id** (a commitment hash over
  author+content+tags+time — NOT the author-settable `created_at`, so it can't be cheaply gamed).
  Deterministic for every client.
- **Anchor + walk:** the chain must be rooted (a genuine v1 genesis with no prev, or the held
  floor's exact hash, or `floor+1` linking to the floor hash). Walk upward only across a
  contiguous link (`version == prev+1` AND `prev_hash == predecessor.self_hash`).
- **Gap:** if the head is not chain-anchored (withheld prereqs, a forged middle link, a forked
  floor edition), set `gap = true`. A **tracking** client (holds a floor) MUST then fail closed
  (suspend the entity, refetch from the relay union). A **bootstrapping** joiner (`floor == 0`,
  whose genesis was re-anchored away) may accept the highest signed head **only after** verifying
  the author's current authority against the roster rooted at the proven owner (§6.4: the owner
  is the `owner_xonly` that reproduces `community_id` and signed the genesis vsk=0 edition).

The fold is a pure function of the *set* (order-independent), so two clients that have seen the
same editions compute the identical head. Aggregating across relays heals single-relay gaps
(the union is contiguous even when no single relay holds the whole chain).

### 6.8 Two-layer authorization

1. **Bind + fold** (`fold_roster`) produces the validly-signed, anchored, current roster — the
   seal signature proves *who* authored each edition, and the `entity_id` must *bind* to its
   content (a role at `entity_id == role_id`, a grant at `grant_locator(community_id, member)`).
2. **Delegation check** (`authorize_delegation`) then filters by the delegation chain — *whether*
   each signer was allowed (rank + a chain to the owner). A self-signed or forged-delegation entry
   never becomes trusted authority.

The **banlist** (vsk=4) is the "anti-memberlist": its folded head is honored only if its signer
held `BAN`. The inbound path drops **every** event kind from a banned author (message, reaction,
edit, presence, …) so a banned member vanishes entirely.

A control fold processes at most **50,000** editions (bounds the verify work a hostile relay can
force).

---

## 7. Invites

Accepting an invite hands the recipient the actual **keys** (the server root, the granted
channels' keys, the relay set, the owner proof), so the key *is* the membership. A received
invite is **parked** (nothing connects/joins) until the user accepts.

### 7.1 Targeted invite (NIP-17 private message)

The bundle is the join material:

```jsonc
// CommunityInvite
{
  "community_id": "<hex>",
  "name": "...",
  "server_root_key": "<hex>",
  "server_root_epoch": <u64>,        // omitted when 0
  "relays": ["wss://...", ...],      // capped/deduped to ≤ 5 on read
  "channels": [
    { "id": "<hex>", "key": "<hex>", "epoch": <u64 (omit if 0)>, "name": "..." }, ...
  ],
  "owner": "<owner_xonly hex>",      // self-certifying owner proof (§6.4)
  "owner_salt": "<owner_salt hex>",  //   — together these must reproduce community_id
  "icon": {CommunityImage} | absent  // so a parked invite can show the logo
}
```

Delivery uses **standard [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)**:
build a NIP-17 private-message **rumor (kind 14)** whose `content` is the bundle JSON (a
`["concord-invite", ""]` tag marks it as a Concord invite rather than a chat DM), seal it
(kind 13, signed by the sender's identity), and gift-wrap it (kind 1059) to the invitee per
NIP-17 — using NIP-17's own pairwise gift-wrap signing key (the only place Concord uses the
NIP-59 PR's pairwise-derived wrap key, since here the recipient is a single npub, not a group).
The sender's identity is irrelevant to trust — the self-certifying `community_id` anchors
ownership (§6.4).

On receipt, `parse_invite_dm` returns the bundle only if the rumor is kind 14, carries the
`concord-invite` marker, and the JSON parses. `accept_invite` reconstructs a member-view
Community: it keeps `(owner, owner_salt)` **only if** they reproduce `community_id` via §3.5
(an impostor cannot smuggle a bogus owner claim or hand a fake key for a real community — a
mismatching bundle is refused), and the bootstrapping path (§6.7) then requires the genesis
vsk=0 edition to be owner-signed. Caps: ≤ **256** channels (reject), relays truncated to ≤ 5
(not rejected).

### 7.2 Public invite (link)

A shareable URL `https://vectorapp.io/invite#<fragment>` whose `#fragment` carries a random
**32-byte fetch-token**, never the keys. The token derives three sub-keys (§3.1):

- `public_invite_key(token)` — the NIP-44 decrypt key for the bundle.
- `public_invite_locator(token)` — the addressable `d`-tag locator.
- `public_invite_signer(token)` — a stable signing keypair.

**Bundle event** (posted on the community's relays):

```jsonc
// kind 33301 (COMMUNITY_PUBLIC_INVITE, addressable), signed by Keys(public_invite_signer(token))
content = NIP-44 seal(public_invite_key(token), PublicInviteBundle JSON)
tags = [
  ["d", "<public_invite_locator(token) hex>"],
  ["vsk", "6"],
  ["v", "2"]
]
```

```jsonc
// PublicInviteBundle (plaintext inside the seal)
{
  "preview": { "name": "...", "description": "..."|absent, "icon": {CommunityImage}|absent },
  "join": { CommunityInvite },          // the same join material as §7.1
  "expires_at": <unix secs> | absent,
  "creator_npub": "<bech32>" | absent,  // attribution
  "label": "..." | absent               // metric bucket
}
```

A fetcher queries by the locator `d`-tag, then verifies: `v == "2"` → `event.pubkey ==
signer_pubkey(token)` (rejects an impostor squatting the locator) → Schnorr signature → `vsk ==
"6"` → decrypt under `public_invite_key(token)`. Expiry is reported, not enforced at parse
(a preview can still render an expired link); joins gate on `is_expired(now)`.

The public-invite bundle is **not** gift-wrapped: it must be directly fetchable by a non-member
following a link (the token-derived signer + locator is the addressing), so it is a
Concord-specific **addressable kind 33301** (NOT NIP-78 / kind 30078). This is the one read path
open to outsiders, gated by the secret token in the URL fragment.

**Rotate** = re-post the bundle under the same coordinate. **Revoke** = publish a token-signed
**tombstone** (an empty-content replaceable kind-33301 event, same `(kind, pubkey, d)`,
`vsk == "9"`); a fetcher reading it returns an explicit "revoked" verdict. Relays honor
replaceable-event replacement more reliably than NIP-09 `a`-tag deletion, so the tombstone
guarantees the browser preview dies.

**Public vs. Private** mode is derived from the **InviteLinks** control entity (vsk=8): the
aggregate (union across creators who hold `CREATE_INVITE`) of active link locators. Non-empty =
Public; empty = Private. Switching from Public to Private is, under the hood, a relocation
(server-root rekey) so the memorized token can't keep being used.

**URL fragment encoding** (v2, the common form): base64url-no-pad of
`[version=2][flags][relays?][token:32]`. `flags` bit `0b1` means "the stock trusted relay set"
(zero relay bytes). Otherwise a 1-byte count then, per relay, a dictionary id (1–254), a
`wss://`-implied literal (id 0, length-prefixed host), or a verbatim literal (id 255). A legacy
v1 fragment is base64url-of-JSON `{"v":1,"relays":[...],"t":"<token hex>"}` (first decoded byte
`{` discriminates v1 from v2). The token never reaches a web server (it rides the `#fragment`)
nor the relays (they hold only the locked bundle).

---

## 8. Cross-device sync (kind 33302)

Joins leave no reconstructible network trace (a DM bundle reaching device B doesn't mean device A
accepted; a URL join is invisible), so memberships sync explicitly through self-encrypted,
replaceable per-user lists on the Concord-specific **addressable kind 33302**
(`COMMUNITY_USER_LIST`); Concord uses **no** NIP-78 (kind 30078) event. The two lists are
distinguished by their `d`-tag.

### 8.1 Community List

- **kind 33302**, addressed to yourself, `["d", "vector/communities"]`.
- content = **NIP-44 self-encrypted** JSON of `CommunityList`:

```jsonc
{
  "entries": [
    {
      "community_id": "<hex>",
      "seed": { CommunityInvite },       // stable join bundle (earliest root) — backfill anchor
      "current": { CommunityInvite }|absent,  // freshest snapshot (latest root + keys + name)
      "added_at": <ms>
    }, ...
  ],
  "tombstones": [ { "community_id": "<hex>", "removed_at": <ms> }, ... ]
}
```

ADD on join, REMOVE (tombstone) on self-removal. Merge resolves per-community by latest action
(`added_at` vs `removed_at`); the **seed** keeps the lowest epoch (widest backfill), the
**current** keeps the highest epoch (instant-latest rehydration), with a lexicographic canonical
tiebreak on an epoch tie. Icons are stripped from list blobs (re-folded from metadata). A local
`community_list_published_at` guard ignores any relay copy older than the last local mutation.

### 8.2 Invite List

The same kind-33302 self-sync pattern (a distinct `d`-tag, e.g. `["d", "vector/invite-links"]`)
syncs a creator's active public-invite tokens across their own devices (so rotate/revoke is
consistent everywhere).

---

## 9. Append-plane sub-types in detail

### 9.1 Presence (kind 3306)

Rumor content is `"join"`, `"leave"`, or an attributed-join JSON `{"by":"<npub>","l":"<label>"}`.
The rumor author (the seal signer) is the announcing member, so no one can forge another's
presence. A best-practice, **not enforced** — a silent join omits it. A `leave` whose author is
the local npub is a self-removal teardown (propagates to all your devices); a stale leave
predating the current join renders as history only. In an attributed join, `by` must parse as a
real pubkey (else dropped) and `l` is bounded free text (≤ 48 chars).

### 9.2 WebXDC peer signal (kind 3310)

The Community-transport twin of the NIP-17 peer-advertisement DM, for Mini Apps realtime
(Iroh gossip). Rumor JSON content:

```jsonc
{ "op": "ad",   "topic": "<hex>", "addr": "<iroh node addr>" }   // advertise
{ "op": "left", "topic": "<hex>" }                                // stopped playing
```

Persisted on receipt in a **local store** keyed by topic (IndexedDB, not a Nostr event) so a
member who reopens mid-session rediscovers active players. Own-device echoes are dropped.
Author-controlled timestamps are clamped.

### 9.3 Cooperative delete / moderation-hide (kind 5)

A kind-5 ([NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md)) rumor; content
empty; the `["e", <target_id>, "", "reply"]` tag names the target rumor (a message or a reaction
id). Delivered as a fresh gift wrap signed by the current epoch's group key (§4.5). Honored as:

- **Self-delete:** the target's own author removes it (the kind-5 rumor's author equals the
  target rumor's author).
- **Reaction-revoke:** for a reaction target, the deleter must be the reactor.
- **Moderation-hide:** the deleter must (a) carry an authority citation (`vac`) for a grant the
  receiver has synced to ≥ the cited version (or be the owner, who cites nothing) **and** (b) hold
  `MANAGE_MESSAGES` and strictly outrank the target's author. The owner is never a valid target.

This is *cooperative* soft removal (a hostile client can keep displaying the blob); hard removal
is a rekey (§5). A dissolved community accepts only self-deletes.

### 9.4 Cooperative kick (kind 3309)

Rumor content = the target member's pubkey **hex**; carries the kicker's `vac` citation. Honored
only when the kicker cites a synced grant **and** holds `KICK` **and** strictly outranks the
target in the floor-protected roster. The **target** self-removes on receipt (drops the keys,
wipes local chat data — like a leave); peers drop the target from their observed member list. A
kick older than this account's join is ignored (re-accepting an invite overrides a stale replay).
A target that ignores a kick (malicious) is escalated to a BAN (the cryptographic rekey).

### 9.5 Typing (kind 3311)

Rumor content `"typing"`; sealed under the channel epoch's group key like presence. Ephemeral —
**never persisted or folded, never recorded in the dedup ledger**. Receivers show the typer for
a short window (~30 s) then expire it.

### 9.6 Group dissolution (vsk=10 tombstone)

A permanent, irreversible owner action. The owner authors a vsk=10 edition (kind 3308 rumor,
sealed under the owner's identity) at `dissolved_locator(community_id)` with `version = 1`, **no
prev_hash**, content `{}` — it is **chain-free** (exempt from the version discipline; presence of
≥1 valid owner-sealed edition *is* the state). It is sealed and gift-wrapped two ways: under the
current `control` group key (fast path) **and** under the rotation-stable
`dissolved` group key (`dissolved_group_key(community_id)`, derived via the
`dissolved-pseudonym` label, so a post-rotation joiner who only holds a later root can still
discover it). A client treats the community as dissolved **only if** the proven owner is among
the tombstone seal signers. Once sealed: the control fold stops advancing and the inbound path
drops every subsequent event of any kind.

---

## 10. Publishing and querying — procedures

### 10.1 Relays

A Community carries a relay set capped at **5 distinct** relays (`MAX_COMMUNITY_RELAYS`),
deduped then truncated on every construction/read boundary. All of a Community's events publish
to and fetch from this union. Never trust a single relay — take the union and the version chain
heals single-relay gaps.

- **Single-attempt publish** (`publish`): OK if ≥1 relay ACKs. Used for latency-sensitive chat
  messages.
- **Durable publish** (`publish_durable`): retry each relay independently up to **30** times,
  re-sending only relays that have not yet ACKed. Used for security-critical events — rekeys,
  bans, control editions, deletes, invite-registry updates, and presence-joins that must land
  reliably.

### 10.2 Sending a channel message

1. Build the **rumor** (unsigned; kind = the append kind; `channel`/`epoch`/`ms` tags; reply/
   emoji/imeta as needed; `pubkey` = your real identity).
2. Derive the channel **group signing key** for `(channel_key, channel_id, epoch)` (§3.4).
3. **Seal** the rumor: NIP-44-encrypt the rumor JSON under `conv_key`, place in a kind-13 event,
   and sign with your **real identity** (local keys or the active `NostrSigner` / NIP-46 bunker).
4. **Gift-wrap** the seal: NIP-44-encrypt the seal JSON under `conv_key`, place in a kind-1059
   event with `["p", group_pk]`, `["v", "2"]`, and **sign with `group_sk`**.
5. Publish the wrap to the community relays (durable for control/moderation events, single for
   chat).

### 10.3 Fetching channel history

Query the community relays with:

```
kinds   = [1059]                         // every Concord wrapper is a gift wrap
authors = [ group_pk(key_e, channel_id, e) for each retained (e, key_e) ]   // OR-set across epochs
until   = <oldest-known created_at secs>   // page older history; omit for the latest page
since   = <newest-held wire time secs>     // latest-page only, to skip re-pulling held events
limit   = <page size>                       // newest-first
```

Because the address is the wrap's **author**, a non-member cannot produce a matching event:
this is the DoS fix over v1's `#z` (where anyone could write the filterable tag). Process each
returned wrap: select the channel/epoch by the wrap's `pubkey` (which `group_pk` it is),
NIP-44-decrypt the wrap under that epoch's `conv_key` to get the seal, verify the seal signature,
decrypt the seal to get the rumor, verify the rumor `id`, enforce the binding triad (§4.3), and
silently drop any that fail (wrong key, splice, forged seal, bad version). Then:

- **Dedup on the rumor id**, never the wrapper id — one rumor can ride multiple wrappers
  (re-broadcast, multi-relay copies, replays).
- **Order** deterministically by the rumor's authenticated `ms` timestamp, ties broken by rumor
  id.
- Process **messages (kind 9) before reactions/edits (kind 7 / 3302)** in a batch so a control
  event finds its target already ingested.

### 10.4 Fetching the control plane / roster

Query the relays for `kinds = [1059]`, `authors = [control_group_pk(server_root, community_id,
epoch)]`. For each wrap, decrypt under the control `conv_key`, parse the seal, verify the
**seal** signature (the actor's identity), decrypt the rumor, compute `self_hash`, then
`fold_roster` (group per `eid`, version-fold each chain from its persisted floor, bind
`eid`↔content, two-layer authorize). Apply GroupRoot/ChannelMetadata only if the signer held
`MANAGE_METADATA`/`MANAGE_CHANNELS`; the banlist only if its signer held `BAN`; honor a
dissolution only if the proven owner signed it.

Also probe the rotation-stable dissolution address (`dissolved_group_pk(community_id)`) so a
dead community is discovered regardless of epoch.

### 10.5 Realtime subscription

Subscribe to the community relays with one filter:

```
kinds   = [1059]
authors = [ every channel group_pk (all held epochs) ]
          ∪ [ every control group_pk ]   (and rekey/base-rekey/dissolution addresses)
limit   = 0   // live tail only
```

Route an arriving wrap by which `group_pk` signed it: a control address (or a rekey/base-rekey
address) triggers a control/rekey refresh; otherwise it opens against the channel mapped to that
`group_pk` and is processed, persisted, and dispatched. Decrypt to the rumor to learn the inner
kind (3308 control, 3303 rekey, else append). Typing (kind 3311) is realtime-only and never
persisted.

---

## 11. What is and isn't hidden

Relays and non-members see only NIP-44 ciphertext (kind-1059 gift wraps) authored by **rotating
per-epoch group keys**. They cannot read message content, author identities, community/channel
names, the member list, roles, or bans. The group address (the wrap's `pubkey`) rotates per
epoch, resisting (not guaranteeing against a global observer) correlation of a room's traffic.
Because the address is the wrap's author and only key-holders can compute the signing key, a
non-member **cannot inject events into a member's `authors` filter** — eliminating the v1 `#z`
DoS where outsiders could spam a channel's filterable tag and force members to download and
trial-decrypt junk. **Not** hidden: that *some* encrypted traffic exists, its rough
volume/timing, and your IP to the relays you use (absent Tor/VPN).

> **Security tradeoff (inherited from the NIP-59 change).** A shared, member-derivable wrap
> signing key means **any member can issue a relay-level NIP-09 deletion** for the group address,
> and the group's traffic over an epoch is linkable by a watcher (the author pubkey is stable
> until the next rekey). This mirrors the explicit tradeoff debated upstream
> ([nostr-protocol/nips#2396](https://github.com/nostr-protocol/nips/pull/2396)): per-conversation
> linkability and shared-key deletion power in exchange for spam/DoS prevention and `authors`-based
> filtering. Concord accepts it because (a) the epoch rotation bounds linkability to one epoch,
> and (b) cooperative deletion (§4.5, §9.3) is already the app-level model.

**Ownership is self-certifying, not asserted.** The `community_id` is a SHA-256 commitment to the
owner's identity key plus a random salt (§3.5), so the proven owner is *recomputed* from
`(owner, owner_salt)` rather than trusted from a transported claim, and the genesis vsk=0 edition
must be sealed-signed by that key to prove possession (§6.4). An attacker cannot reassign an
existing community to a different owner (second-preimage resistance) nor frame an innocent npub
(a forged community for someone else's key is simply a different, unrelated id). Concord uses
**no NIP-78 (kind 30078) events**: the public-invite bundle/tombstone live on the addressable
kind 33301 and the per-user sync lists on kind 33302, both Concord-specific. One privacy note:
because `community_id = H(owner_xonly || salt)` and `owner`/`owner_salt` travel in metadata and
invites, **a party who holds an invite learns the owner's npub** — this is intentional (it is the
proof) but means the owner is not pseudonymous to members; the id alone (without the salt) reveals
nothing.

---

## Appendix A — frozen golden vectors (regression pins)

These exact outputs anchor the wire format (independent RFC-5869 HKDF / SHA-256
implementations). A drift means the format changed.

The `*_pseudonym` values below are the **HKDF seeds** (§3.1) under the `concord/v1` label prefix.
In v2 each seed is fed through the scalar-normalization of §3.4 (reject-and-retry to a valid
secp256k1 secret key) to produce the **group signing key**; the keypair's x-only public key is
the on-wire `authors` address. Implementations MUST additionally pin, for each derivation, the
resulting `group_sk` (after normalization) and the x-only `group_pk`; those pins are generated
from the seeds below and committed alongside the golden HKDF vectors in the source.

```
# HKDF seeds (concord/v1 label prefix; seed the group signing key per §3.4)
channel_pseudonym(key=0x00..1f, id=0xff,0xfe,.., epoch 0)
  = 23b4e1059184c52788da6876823ada480ce4442e56adbb0a347b3444bc24c500
channel_pseudonym(.., epoch 1)
  = d5e38a2134141fe45423b8f35c635e45c1d0b31fc60398ed398db0f1c766c9e3
channel_pseudonym(.., epoch 0x0102030405060708)   // proves u64 big-endian
  = 794674e1e215064cb21e4ab9587e8428d1ba7552ea96bd508e570af229372be8

grant_locator(community=0x11*32, member=0x22*32)
  = 9ffe7fc6960270ea06a3dc0d0b01fb646edeb35c28003c19f281f62b7aa0fffd
invite_links_locator(community=0x11*32, creator=0x22*32)
  = beb6cccf3efd06af4c858970e0f5e3185f1d2e1af807a3ea3248c1b8f2db6f4b

rekey_pseudonym(server_root=0x07*32, channel=0xff,0xfe,.., epoch 1)
  = bcef42f7a54681bd85136aa6efbd681b571bdb2e80c88e6d0da47cf6cb875ba5
base_rekey_pseudonym(prior_root=0x07*32, community=0x09*32, epoch 1)
  = bc3053d885290b94aaef04ade6e2423a115e10f45139863a459653abb3fd4a65
recipient_pseudonym(secret=0x07*32, Channel(0xff,0xfe,..), epoch 3)
  = ace6b8b85a1057cdb0a5f0c9d45727df389ac36cffe71a43d3f43d535001ff63
recipient_pseudonym(secret=0x07*32, ServerRoot, epoch 3)
  = 47de47fc4222d6cf72e291b993f89f46997a659fe2eb09561ad91bba998e2017

public_invite_key(token=0x05*32)
  = aec07ed9655ef10fbae5287a36fd452ed310c6b75f8ed1f7b528b9aaeb75617d
public_invite_locator(token=0x05*32)
  = a1ba7ccab72e7f529391b761991db98a5042822da1bd7039d7e33321a1d679c7
public_invite_signer(token=0x05*32)
  = a223f898821a0a979ef1b01e4b082de88e3bed0800871acbe8066fa906af29c5

edition_hash(entity=0x11*32, version=1, prev=None, content="hello")
  = 27ee643a84e2dc23d0bfcb471106e71dd0b7328646090afb41c54c4ad09a53f1

# Self-certifying community id (§3.5): SHA-256(label || owner_xonly[32] || owner_salt[32])
community_id(owner=0x22*32, salt=0x33*32)
  = a294f4c7bbb864e7e19f5530b864b9b5c2847100505858b3f22e058b12470dea

# v2 group-key normalization (§3.4) — pins generated from the seeds above:
#   group_sk = scalar_normalize(seed, info);  group_pk = secp256k1_xonly_pubkey(group_sk)
# A normalization counter is appended to info only on the ~2⁻¹²⁸ reject branch.
# (group_sk / group_pk vectors committed with the source test suite.)
```

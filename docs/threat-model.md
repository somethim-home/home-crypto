# Threat model — Home Files end-to-end encryption

Status: draft, unreviewed. Companion to `docs/format.md`. Source plans: infra `022-home-files-age-e2ee.md`,
`012-home-server-hardware-goal.md` ("Confirmed storage decision — private E2EE plus shared locations").

## Scope

Family file storage on the home server. Each person has a private space; shared spaces (for example
"Family") have several members. Clients (desktop, Android, web, iOS later) encrypt before upload and decrypt
after download. The server (`home-files`) stores and serves ciphertext only and enforces accounts, membership
and quotas.

Out of scope: the server-readable media library (Jellyfin and similar), which is explicitly not end-to-end
encrypted; transport security (TLS/WireGuard) beyond noting it is required; availability guarantees; the
security of the devices themselves.

## Assets

| Asset | Where it lives |
| --- | --- |
| File contents | Client devices (plaintext); server and backups (ciphertext) |
| File and folder names, paths, sizes, modification times, content hashes | Inside the encrypted manifest; plaintext only on clients |
| User identity (grant identity, keyring identity, Ed25519 signing key) | Plaintext only in client memory / client key store; on the server only as two age files sealed by passphrase and by recovery identity |
| Pinned verifying keys (trust on first use) | The person's keyring (age file to the secret keyring recipient) |
| Recovery identity | Printed once on paper (or stored by the person); never on the server |
| Passphrase | The person's memory / password manager; never sent to the server |
| Space identities (one per space per epoch) | The member's keyring (age file to the keyring recipient) and grants (age file to the member's grant recipient) |
| Share-link identities | The URL fragment held by the link recipient |

## Actors

| Actor | Capabilities assumed |
| --- | --- |
| Family member | Holds their own identity and the identities of every space they belong to. Trusted with the content of those spaces. An admin is also trusted with membership: what an admin signs, the other members accept. |
| Server operator / root | Full control of the server: reads and modifies all stored files, databases and logs, sees all traffic metadata, can replace server code and the web client bundle, can withhold, reorder, replay or delete data. |
| Stolen server disk or backup | Read-only copy of everything stored at one point in time. No running code. |
| Removed member | Was a member; keeps every identity and every plaintext they had before removal; may still have network access to the server via another space or may collude with the operator. |
| Network attacker | On the tailnet now, on the internet once the server is exposed (plan 007 static-IP step). Can observe and tamper with traffic outside TLS/WireGuard and attack the server's public surface. |
| Device thief | Has one unlocked or locked client device. |

## What is protected

1. **Confidentiality of contents and names against the server.** Operator, root, a stolen disk, backups and
   network attackers see only age ciphertext. Decryption requires a space identity, which the server never
   receives in plaintext.
2. **Account and decryption are separate.** The home-auth password/passkey and an operator-side account reset
   do not unlock files. Unlocking needs the passphrase or the recovery identity.
3. **Integrity of each age file.** Every age file is authenticated (header MAC, STREAM chunk tags). Bit flips
   and truncation are detected.
4. **No forgery by the server.** age has no sender authentication: anyone who knows a recipient can encrypt
   to it. The design therefore keeps every recipient the server does not need *secret from the server*
   (keyring recipient, recovery recipient, space recipients). Without them the server cannot create keyrings,
   manifests, rosters or objects that clients accept. The only public recipient is each person's grant
   recipient; grants sent to it are **signed with Ed25519** by the granting member, and recipients verify the
   signature against the signer's pinned verifying key and refuse unsigned or wrongly signed grants. The
   server therefore cannot forge an invitation from a person whose key the recipient has pinned (format
   §3.2). The exception is first contact; see "What is not protected".
5. **Members authenticate each other's membership changes.** Rosters and rotation records are signed by the
   admin who makes the change. A member accepts a roster change only if it is signed by an admin of the
   roster they already trust, and a rotation (with its grant and new roster) only if one admin of the
   previous epoch signed all three. A non-admin member, a removed member, the server, or any combination of
   them cannot add members, change roles or keys, or steer the space to a new identity — as long as none of
   them holds an admin's signing key. Every member's verifying key is pinned when first seen in an accepted
   roster; a roster or published key that later shows a different key is refused as a key change.
6. **Grants cannot be redirected.** A grant names its addressee (`granted-to`) inside the signed bytes, so a
   member cannot re-encrypt a grant they received to a third person as if the admin had sent it.
7. **Object substitution inside a space.** Each object's plaintext begins with its own object id, so the
   server cannot answer a request for object A with object B of the same space, including for range reads.
   The manifest also records each file's SHA-256, checked after a full download.
8. **Removal of a member going forward.** After removal the space is rotated to a new identity that the
   removed member never receives. New files, new manifest entries and re-encrypted old files are unreadable
   to them. Because the rotation is signed by an admin of the previous epoch, a removed (non-admin) member
   colluding with the server can no longer forge a rotation that remaining members accept.

## What is not protected (visible or possible to the server)

Visible metadata, stated plainly:

- Account ids, which spaces exist, and **who is a member of which space** (needed for authorisation).
- Each person's grant recipient and verifying key (public keys).
- **Object ids**, the number of objects per space, **ciphertext sizes** (plaintext size ≈ ciphertext size minus
  a small constant; age adds about 16 bytes per 64 KiB chunk plus a header).
- **Upload, download and deletion times**, which device/account did them, from which IP.
- **Access patterns**: which objects are read together, range-read offsets, frequency.
- Size and timing of manifest updates (roughly how much the tree changes and when).
- Number of epochs (how often members were removed).
- That a share link was created, for which space, and when it is used (not its key).

Other limits:

- **Availability and freshness.** The server can delete, withhold or roll back objects and manifest segments.
  Clients detect some rollback (they remember the highest frontier they have seen per space) but cannot force
  the server to serve data.
- **Rollback of the keyring.** The server can serve an older keyring version; clients reject versions lower
  than the highest they have seen on that device, but a fresh device cannot tell.
- **First contact (trust on first use).** When a person receives an invitation from someone whose verifying
  key they have never pinned, the client can only check the signature against the key the server publishes
  for that user. A malicious server can publish its own key and sign a grant for a space identity of its own
  choosing; accepting it and then uploading private files into that space would expose them. Mitigation:
  first-use invitations are marked as such, never accepted silently, and show the inviter's person
  fingerprint (which covers the verifying key and the grant recipient) for comparison in person; once pinned,
  a substituted key is refused. The same applies to an admin adding a member whose key the admin has not
  pinned yet.
- **A malicious or compromised admin can sign bad changes.** Signatures prove who made a change, not that it
  is a good one. An admin (or anyone holding an admin's unlocked device) can add members, change roles, remove
  other members (including other admins) by rotating, or rotate to a key they share with outsiders, and the
  other members' clients accept it. Mitigation: clients show who signed each membership change and the new
  safety numbers. Equally, a member who was an admin of epoch `n` and is being removed can race the genuine
  rotation with one of their own (removing the other admins); whichever the server stores first wins. Members
  who see both can tell they conflict; the format does not resolve it.
- **Replay and rollback of signed records.** Signatures do not carry a version or time. The server can serve
  an older signed roster of the same epoch (for example one without a newly added member) to a device that
  has not seen the newer one, or withhold a rotation. Devices keep the roster they trust and never go back to
  an older epoch, but cannot force the server to show them the newest one.
- **Lost signing key, compromised device.** Whoever unlocks a person's identity holds their signing key and can
  sign as them in every space where they are admin, until that person is removed by a rotation. A person who
  recreates their identity gets a new key, which everyone who pinned the old one sees as a key change to
  confirm in person.
- **Within a space, file contents and the manifest are not authenticated per member.** Signatures cover
  grants, rosters and rotations only. Any member can still write any manifest entry or object and can claim
  any device or author. Members are trusted with each other's files.
- **No retroactive secrecy against a removed member.** Anything they downloaded, and any old identity they
  copied, stays with them. If they (or the operator, colluding) kept old ciphertext, they can decrypt it with
  the old identity. Re-encryption after removal only protects copies the server holds afterwards.
- **No forward secrecy for stored data.** Whoever obtains a space identity can decrypt every stored object of
  that epoch.
- **No post-quantum protection.** X25519 recipients only; ciphertext recorded today could be decrypted by a
  future quantum computer (the Rust `age` crate 0.12.1 has no hybrid ML-KEM identity; see open questions).
- **Passphrase guessing offline.** Anyone holding `identity.passphrase.age` (operator, stolen disk) can run
  an offline scrypt guessing attack. The scrypt cost slows this; a weak passphrase is still a weak point.
- **Compromised client device.** Malware on an unlocked device sees plaintext and keys. Out of scope.

## Web-client trust caveat

A browser runs whatever JavaScript/WebAssembly the server delivers at load time. A malicious operator, or
anyone who controls the server or the delivery path, can ship a bundle that exfiltrates the passphrase,
identities or plaintext, including the share-link fragment. End-to-end encryption in the web client is
therefore only as strong as trust in the server operator at the moment of each page load. Mitigations
(pinned, signed bundle; native apps as the primary clients) reduce but do not remove this. The web client must
say so plainly and must never be described as "operator-blind".

Share links opened in a browser carry the same caveat: the fragment is not sent to the server by the
browser, but code served by the server can read it.

## Lost keys

- Passphrase lost, recovery identity kept: unlock with the recovery identity on a new device, set a new
  passphrase.
- Recovery identity lost, passphrase kept: unlock with the passphrase, generate and print a new recovery
  identity (the identity file sealed to the old recovery identity is replaced).
- **Both lost and no device still unlocked: the person's private files are gone.** Server backups contain
  only ciphertext and cannot help. This is by design. Shared spaces stay readable by the other members, who
  can grant them again to a new identity of the same person.
- A space whose every member has lost their keys is permanently unreadable.

## Actor-by-actor summary

| Actor | Contents/names | Metadata | Can forge | Can deny service |
| --- | --- | --- | --- | --- |
| Member | Own spaces only | Own spaces | Objects and manifest entries inside own spaces; membership changes only as an admin | Delete inside own spaces (server-side permissions permitting) |
| Operator / root | No (native clients); yes via a malicious web bundle | All listed above | First-contact invitations only (no pinned key); nothing else without an admin's signing key | Yes |
| Stolen disk / backup | No (offline passphrase guessing only) | All stored metadata | No | n/a |
| Removed member | Old epoch data they had or can still fetch | Old epoch | With the operator: old-epoch objects and manifest entries; rotations only if they were an admin of the old epoch | Via the operator only |
| Network attacker | No (with TLS/WireGuard) | Traffic sizes/timing | No | Yes (availability) |

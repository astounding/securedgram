# SecureDGram - Security Evaluation

## Summary

SecureDGram provides authenticated, encrypted UDP messaging using ChaCha20-Poly1305 AEAD with a pre-shared symmetric key. For its intended purpose — casual encrypted messaging between a small number of trusted hosts — the system provides solid cryptographic protections. The primary limitations relate to the key management model (single shared secret) and properties inherent to UDP-based transport.

---

## Strengths

### 1. Strong Cryptographic Primitives

- **ChaCha20-Poly1305-IETF** is a modern, well-vetted AEAD cipher standardised in RFC 8439. It provides both confidentiality (ChaCha20 stream cipher) and integrity/authentication (Poly1305 MAC) in a single operation.
- The implementation uses **libsodium** via `rbnacl`, which is a high-quality, audited cryptographic library. This avoids the risk of hand-rolled crypto and benefits from constant-time comparisons and other side-channel protections that libsodium provides.
- **12-byte random nonces** are generated per message using `SecureRandom.random_bytes`, which draws from the OS CSPRNG. With 96-bit nonces and a collision threshold around 2^48 messages per key, nonce reuse risk is negligible for the expected message volume.

### 2. Replay Protection

- Every message embeds a nanosecond-precision timestamp inside the encrypted envelope. The receiver rejects any message whose timestamp falls outside a configurable window (default ±10 seconds).
- Since the timestamp is inside the AEAD ciphertext, an attacker cannot forge or modify it without the key. Replaying a captured datagram after the window expires will be rejected.

### 3. Privilege Separation

- The daemon performs a classic Unix double-fork daemonisation and drops privileges from root to an unprivileged user after binding the socket. This limits the damage from any post-initialisation vulnerability.

### 4. Database Isolation

- SQLite3 WAL mode allows external processes to read/write concurrently without blocking the daemon. The `busy_timeout` and auto-commit strategy minimises lock contention.
- Sensitive data (the shared secret) is never stored in the database — only in the `.env` file and in process memory.

### 5. Clean Crash Recovery

- On startup, the daemon resets any outbound messages stuck in the transient `sending` state and re-queues ACKs for inbound messages that were received but never acknowledged. This provides at-least-once delivery semantics without manual intervention.

### 6. Silent-by-Default Posture (WireGuard-Style)

- The daemon never responds to unauthenticated traffic. An invalid datagram (wrong key, corrupted, malformed) is silently discarded — no error response, no ICMP, no indication that anything is listening. This is a significant security property shared with WireGuard: from the perspective of an unauthorised scanner, the port appears closed or filtered.
- This stands in contrast to protocols like QUIC, which must respond to connection attempts even from unauthorised clients (via Initial packets and Retry tokens), revealing the presence of a listener. SecureDGram's silence-unless-authenticated approach makes port scanning and service fingerprinting ineffective.
- Only a peer that proves possession of the shared key (by submitting a valid AEAD-authenticated datagram with a valid timestamp) will ever elicit a response (the ACK).

### 7. ACK as Proof of Receipt

- When both sides run the same SecureDGram code, a received ACK is cryptographic proof that the remote peer successfully decrypted the original message. The ACK itself is AEAD-encrypted and contains the `message_id`, so it cannot be forged without the key. The chain of trust is: the sender encrypted a message containing a unique `message_id` → the receiver decrypted it, extracted the `message_id`, constructed an ACK containing that `message_id`, and encrypted the ACK → the sender decrypted the ACK and verified the `message_id` matches. This provides non-repudiation of receipt within the trust domain of the shared key.

---

## Known Limitations and Risks

### 1. Single Pre-Shared Key (Critical Limitation)

**Current state:** All endpoints share one 256-bit symmetric key. Compromise of any single host exposes the secret for all communication.

**Implications:**
- An attacker who obtains the key from any participating host can decrypt all traffic (past and future) between all hosts.
- There is no forward secrecy — captured ciphertext can be decrypted later if the key is ever compromised.
- There is no sender authentication beyond "possesses the key". Any keyholder can forge messages appearing to come from any source IP (or inject into the outbound queue of any host with DB access).
- Revoking a compromised host means rotating the key on all remaining hosts simultaneously.

**Future mitigation (as planned):** Per-endpoint secrets with an IP-to-key mapping would contain a compromise to a single communication pair. A further improvement would be an ephemeral key exchange (e.g., X25519 Diffie-Hellman) to achieve forward secrecy, though this is complex over stateless UDP.

### 2. No Forward Secrecy

The system uses a static symmetric key. If the key is compromised at any point, an adversary who has captured historical ciphertext can decrypt it retroactively. Protocols like Signal, TLS 1.3, and WireGuard achieve forward secrecy via ephemeral key exchanges, but this requires a handshake or state that is more complex to implement over raw UDP.

### 3. UDP Transport Properties

- **No delivery guarantee:** UDP datagrams can be lost, reordered, or duplicated by the network. The ACK/retry mechanism provides some reliability, but it is not a full reliable transport. Messages that exhaust retries are marked `send_failed` and lost.
- **No congestion control:** The daemon sends all pending messages in a batch with no pacing. Under high load, this could flood the network or get rate-limited by firewalls.
- **Source IP spoofing:** UDP source addresses can be spoofed on networks that don't implement BCP 38 egress filtering. An attacker on the same network could send a forged-source datagram. However, without the shared key, the message will fail AEAD decryption immediately, so this is a denial-of-service vector only (wasting CPU on failed decrypts), not a data integrity risk.
- **Maximum datagram size:** UDP payloads exceeding ~1400 bytes risk fragmentation and loss. There is no chunking or reassembly mechanism. Large JSON payloads may silently fail on some paths.

### 4. Replay Window Coarseness

The ±10-second default window is generous. Within that window, a captured datagram could theoretically be replayed. However:
- The UNIQUE constraint on `message_id` prevents duplicate storage — a replayed message would hit the constraint and be silently dropped (but still ACK'd, which is correct behaviour for retransmits).
- An attacker replaying a message within the window would need to capture it in transit (passive eavesdropping of the encrypted datagram) and then replay it before the window expires. The message_id deduplication prevents any actual damage.

**Effective risk:** Low. The combination of timestamp window + message_id deduplication provides adequate replay protection for the threat model.

### 5. No Peer Identity Verification

The protocol authenticates messages ("this was encrypted by someone who knows the key") but does not authenticate peers ("this was sent by host X specifically"). Source IP addresses are logged but can be spoofed at the network level.

With per-endpoint secrets (planned), this improves — a message decryptable with host A's key is proven to be from host A (or someone who compromised host A's key).

### 6. Database as Attack Surface

Any process with filesystem access to the SQLite3 database can:
- Insert arbitrary outbound messages (the daemon will encrypt and send them)
- Read all received plaintext messages
- Modify message states

The database file should be restricted to the daemon user's permissions (`chmod 600`). The `.env` file containing the shared secret must also be strictly access-controlled.

### 7. Timestamp Relies on System Clock

The replay protection depends on synchronised clocks between sender and receiver. If an endpoint's clock drifts beyond the configured window, legitimate messages will be rejected. NTP or similar time synchronisation is essential.

### 8. No Rate Limiting on Inbound Processing

The daemon processes all decryptable datagrams without rate limiting. An attacker who possesses the key (or if the network allows high-volume spoofed UDP) could flood the daemon with valid or invalid packets. Invalid packets (bad AEAD) are rejected quickly by libsodium, but valid-looking traffic could fill the database or exhaust resources.

---

## Threat Model Assessment

### What SecureDGram protects against:
- **Passive eavesdropping:** All payloads are encrypted with a strong AEAD cipher.
- **Message tampering:** Poly1305 MAC detects any modification to the ciphertext.
- **Replay attacks:** Timestamp window + message_id deduplication.
- **Unauthorised message injection (without key):** AEAD decryption fails immediately.

### What SecureDGram does NOT protect against:
- **Key compromise:** Total loss of confidentiality and authenticity.
- **Traffic analysis:** An observer can see which IPs communicate, when, and the size of datagrams (but not content).
- **Denial of service:** UDP is inherently susceptible. Rate limiting at the firewall level is recommended.
- **Compromised endpoint:** If an endpoint's OS is compromised, the attacker has the key, the database, and all plaintext.
- **Long-term confidentiality:** No forward secrecy — historical captures become readable upon key compromise.

---

## Recommendations

### Short Term
1. **File permissions:** Ensure the `.env` file is `chmod 600` and owned by the daemon user. The database file should similarly be restricted.
2. **Key rotation procedure:** Document and practice periodic key rotation across all endpoints. Shorter key lifetimes reduce the window of exposure from a potential compromise.
3. **Network-level protections:** Use firewall rules to restrict which source IPs can reach the daemon's UDP port. This reduces the DoS surface.
4. **Clock synchronisation:** Ensure all participating hosts run NTP and the timestamp window is appropriate for the expected clock drift.

### Medium Term (Per-Endpoint Secrets)
5. **IP-to-secret mapping:** Implement a configuration map of `{remote_ip => secret}` so each communication pair uses a unique key. Compromise of one pair does not affect others.
6. **Key derivation:** Consider deriving per-pair keys from a master secret using HKDF (available in libsodium as `crypto_kdf`), which simplifies management — only the master secret needs secure distribution, and per-pair keys are deterministically derived from `(master, local_ip, remote_ip)`.

### Medium Term (Reliability and Large Messages)
7. **Guaranteed delivery:** The current ACK/retry mechanism provides best-effort reliability, but messages that exhaust retries are permanently lost. A more robust approach would include exponential backoff, configurable retry policies, and application-level delivery notifications. Since a valid ACK is proof of receipt (see Strengths §7), the delivery guarantee is strong once an ACK arrives — the gap is in retry persistence.
8. **Message fragmentation and reassembly:** Messages exceeding the UDP path MTU (~1400 bytes after encryption overhead) risk silent loss due to IP fragmentation. A fragmentation layer would: (a) split large payloads into numbered fragments, each individually encrypted and sent as a separate datagram; (b) track per-fragment ACKs; (c) reassemble on the receiving side once all fragments arrive. This keeps the system within the low-volume, low-complexity design philosophy while supporting occasional larger payloads. Each fragment would carry a `(message_id, fragment_index, total_fragments)` tuple inside the encrypted envelope.

### Long Term
9. **Forward secrecy:** Investigate an initial key exchange (e.g., X25519) to establish ephemeral session keys. This is the most significant upgrade for long-term confidentiality but requires a handshake protocol and session state management.
10. **Message sequencing:** Add monotonic sequence numbers inside the encrypted envelope for strict ordering and detection of dropped messages, complementing the timestamp-based replay protection.

---

## Design Philosophy: Why Not QUIC?

SecureDGram intentionally operates at a lower level than QUIC. While QUIC provides reliable, multiplexed, encrypted streams over UDP, it has a fundamental property that conflicts with SecureDGram's threat model: **QUIC must respond to connection attempts from unauthorised clients.** The QUIC handshake (Initial packets, Retry tokens, Version Negotiation) requires the server to participate in a multi-round exchange before authentication is established. This means:

- A port scanner can confirm a QUIC server is listening.
- The Initial packet exchange reveals protocol metadata before any authentication occurs.
- Retry tokens and version negotiation are sent in cleartext.

SecureDGram's approach — silence except where cryptographic keys match — is analogous to WireGuard's "Cryptokey Routing" model. The daemon is a black hole to anyone without the key. For low-volume messaging between trusted hosts, this stealth property is more valuable than QUIC's rich transport features.

If high-volume, reliable, ordered delivery becomes necessary, a QUIC-inspired approach could be layered on top of SecureDGram's existing AEAD envelope, preserving the silent-by-default posture while gaining congestion control and stream multiplexing. But for the current use case — occasional messages between a few hosts — the simplicity of single-datagram-per-message with ACK confirmation is the right trade-off.

---

## Conclusion

SecureDGram's cryptographic core is sound. ChaCha20-Poly1305-IETF with random nonces and libsodium is a well-chosen, modern construction. The timestamp-based replay protection and message_id deduplication work together to prevent message replay and duplication. The main risk is the key management model: a single pre-shared key provides no forward secrecy and creates a single point of failure. For casual encrypted messaging between a small number of trusted hosts where the key is securely distributed and periodically rotated, this is an acceptable trade-off. The planned evolution toward per-endpoint secrets will meaningfully improve the security posture.


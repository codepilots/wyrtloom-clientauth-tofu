# Changelog

## Unreleased

- Security (bootstrap single-use is now cross-process atomic): `consume_bootstrap_key`
  no longer does a get-then-put on a `consumed` flag made atomic only by the in-process
  `enroll_lock`. After confirming the key was issued (constant-time hash compare), it
  claims single-use with an atomic `put_if_absent` consume marker in a new
  `consumed_bootstrap_keys` collection (the sqlite store implements this as a single
  `INSERT … ON CONFLICT DO NOTHING` under WAL). Two processes sharing one store can no
  longer double-redeem a key; correctness no longer depends on the process lock (which
  remains only as belt-and-suspenders for the in-process TOFU-pin check). The `consumed`
  field was removed from `StoredBootstrapKey`. Adds `bootstrap_key_single_use_across_processes`
  (two independent `TofuClientAuth` instances, separate connections to one shared on-disk
  WAL store, racing the same key → exactly one succeeds).
  Note: this crate is pre-release, so there is no on-disk data in the prior
  `consumed`-flag format; the new marker collection is the sole source of truth from the
  start and no data migration is required.

- Security (P-256 signature malleability): `verify_signature` now rejects
  non-canonical (high-s) ECDSA signatures via `normalize_s()`, so a captured
  signature cannot be malleated into a second valid one (`(r, s)` / `(r, n-s)`).
  P-256 clients (incl. WebCrypto, whose signer does not auto-normalize) must send
  low-s/normalized signatures. Adds a regression test that a constructed high-s
  twin of a valid signature is rejected.
- Replay cache (DoS): replaced the O(n) `Vec` scan (`retain` + `iter().any`) with
  an O(1)-membership `HashSet<(client_id, nonce)>` plus a `VecDeque` eviction
  queue, and added a fail-closed cap on live entries. Eviction does a full sweep
  of no-longer-replayable entries (the queue is not timestamp-ordered because the
  presented timestamp is client-controlled within ±skew), exactly matching the
  prior `retain` semantics and keeping the live set bounded. All existing
  replay/freshness/boundary tests continue to pass.

- Replay protection: align the nonce-cache retention window with the timestamp
  freshness window so no recorded `(client_id, nonce)` is evictable while a replay
  of it would still pass the ±skew admission check. Retention is now trailing-edge
  only (`now - ts <= skew`), which also keeps a future-dated entry across a
  backward clock step. Timestamp arithmetic is saturating, so an out-of-range
  attacker-supplied timestamp is rejected without panicking or wrapping into the
  window. Adds regression tests for the trailing-edge, backward-clock, and
  extreme-timestamp cases.

## 0.1.0

Initial release.

- `TofuClientAuth`: a trust-on-first-use [`ClientAuthScheme`] over an injected
  `Arc<dyn PersistenceProvider>` (storage-agnostic).
- Asymmetric (ed25519) client keys. The store holds only the public key and its
  SHA-256 fingerprint — never a recoverable secret.
- Single-use CSPRNG bootstrap keys (≥128-bit), stored only as a SHA-256 hash and
  constant-time compared on enrollment.
- TOFU pinning: re-enrolling a `client_id` with a different public key is
  rejected (`PinMismatch`); re-presenting the same key is idempotent.
- `verify` checks the ed25519 signature over the presented canonical request,
  enforces a bounded ±skew timestamp window, and rejects replayed
  `(client_id, nonce)` pairs within that window with an evicting, bounded cache.
- `canonicalize`: length-prefixed, domain-separated (`wyrtloom-client-auth-v1`)
  canonical request bytes shared by clients and the server.
- Enrollment serializes its read-modify-write (TOFU check-then-put and the
  bootstrap-key get-then-consume) under an internal lock, so a single-use
  bootstrap key cannot be consumed twice by concurrent enrollments within a
  process. (A disk-backed store shared across processes would additionally
  require a store-level transaction — a limitation of the persistence contract.)

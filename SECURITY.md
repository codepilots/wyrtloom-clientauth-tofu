# Security model — `wyrtloom-clientauth-tofu`

This crate is a trust-on-first-use (TOFU) `ClientAuthScheme` that authenticates the
*client application* (web SPA, mobile app, CLI) — distinct from the human user —
using asymmetric keys over an injected `Arc<dyn PersistenceProvider>` (`src/lib.rs`
lines 1–17, 247–262). Citations below point at `src/lib.rs` unless stated otherwise.

## Threat model & scope

**What it protects.** It proves that each request originates from a previously
enrolled client application that holds a specific private key, and that the request
is fresh (not replayed). Authentication is by signature over canonical request bytes
(`verify_at`, lines 516–571).

**What it stores.** Only public material: the client's public key (hex), its
algorithm tag, its SHA-256 fingerprint, a validated name, and the enrollment time
(`StoredClient`, lines 78–94). There is **no recoverable secret** in the store — a
dedicated test (`stored_client_has_no_secret_material`, lines 1104–1150) asserts the
serialized record contains exactly those six public fields and scans the document for
the private scalar's hex (lines 1144–1149) and for any `secret`/`private`/`seed`/
`signing_key` field name (lines 1133–1142).

**In scope:** client-app identity (TOFU pin), per-request signature verification,
bootstrap-key issuance/consumption, timestamp freshness, and replay/nonce defense.

**Out of scope / explicitly trusted:**
- **Human-user authentication** — a different layer.
- **First-contact authenticity** — TOFU trusts whatever key is pinned on first
  enrollment (see Gotchas).
- **Transport confidentiality/integrity** — there is no TLS here; canonicalization
  binds the request but does not hide it.
- **Cross-process replay-cache coordination** — the per-request replay/nonce cache
  is process-local (see Gotchas, Operational requirements). Bootstrap-key
  single-use, by contrast, is now **cross-process atomic** via the persistence
  layer's compare-and-set (see Bootstrap keys), so it is *not* in this exclusion.

## Security mechanisms

### Asymmetric TOFU pinning
On first contact, the client presents a bootstrap key plus its public key; the server
validates the key, atomically consumes it, and **pins** the public key (`enroll`). The pin is keyed by `client_id`, which is derived as
`client_id == fingerprint == SHA-256(public_key)` (lines 435–438). Because the id is
the hash of the key, forging a colliding id for a *different* key requires breaking
SHA-256 second-preimage resistance. Re-enrolling the same id with the same key is
idempotent and consumes **no** bootstrap key (lines 460–469); re-enrolling with a
different key under the same id is rejected as `PinMismatch` (lines 457–459; test
`reenroll_different_key_pin_mismatch`, lines 1054–1102).

Per-request verification (`verify_at`, lines 516–571): look up the pinned client
(lines 521–527), verify the signature over the presented canonical bytes using the
**stored** algorithm (lines 529–536), enforce the freshness window (lines 538–542),
then the replay check (lines 543–566).

### Algorithms (auto-detected by key length)
`detect_key_alg` (lines 100–122) distinguishes algorithms by encoding length, which
is unambiguous, so no on-the-wire algorithm field is needed:
- **ed25519** — 32-byte raw key; validated via `VerifyingKey::from_bytes` (lines
  107–111). Signatures are 64-byte raw (lines 141–143).
- **ECDSA P-256** — 65-byte SEC1 *uncompressed* (`0x04 ‖ X ‖ Y`); validated via
  `from_sec1_bytes` (lines 113–116). Signatures are raw `r‖s` (P1363).

P-256 **enforces canonical low-s** to remove ECDSA malleability: `(r, s)` and
`(r, n−s)` both verify, so a high-s signature is a second valid encoding of the same
message. `verify_signature` rejects any signature for which `normalize_s()` returns
`Some` (i.e. the input was non-canonical high-s) — lines 151–157. Tests
`p256_high_s_signature_rejected` (lines 744–801) and
`p256_webcrypto_client_enrolls_and_verifies` (lines 699–742) cover this.

### Bootstrap keys
`issue_bootstrap_key` draws **256 bits** from the OS CSPRNG (`OsRng.fill_bytes` into a
32-byte buffer), hex-encodes the plaintext, stores only its **SHA-256 hash** (an
issuance record in `bootstrap_keys`), and returns the plaintext **once** for
out-of-band distribution.

`consume_bootstrap_key` enforces single-use in two steps:

1. **Issued-check (constant-time).** It looks up the key's hash id in
   `bootstrap_keys` and **constant-time compares** (`ct_eq`) the stored hash against
   the recomputed hash, rejecting a never-issued or mismatched key as `BadApiKey`.
2. **Atomic consume marker (compare-and-set).** It then calls
   `PersistenceProvider::put_if_absent` to insert a consume marker keyed by that hash
   into the `consumed_bootstrap_keys` collection. `Ok(true)` (inserted) means this is
   the first — and only — redemption, so it proceeds; `Ok(false)` (already present)
   means the key was already consumed → `BadApiKey`.

`put_if_absent` is **atomic across processes** sharing the store: the sqlite store
implements it as a single `INSERT … ON CONFLICT(id) DO NOTHING` under WAL, so exactly
one caller — whatever process or thread — observes `Ok(true)`. Single-use therefore
**no longer depends on the in-process `enroll_lock`**; the lock remains only as
belt-and-suspenders for the in-process TOFU-pin check (see Key decisions). Tests:
`bootstrap_key_is_single_use`, `unknown_or_garbage_bootstrap_key_rejected`,
`bootstrap_key_single_use_under_concurrency` (8 threads, exactly one success), and
`bootstrap_key_single_use_across_processes` (two independent `TofuClientAuth`
instances over separate connections to one shared on-disk WAL store — no shared
`enroll_lock` — both racing the same key; exactly one succeeds, the other gets
`BadApiKey`).

### Replay / freshness
- **Bounded ±skew window.** `is_fresh` (lines 374–383) admits a request iff its
  timestamp lies in the closed interval `[now−skew, now+skew]`, rejecting both stale
  and far-future timestamps; out-of-window → `Replay` (lines 538–542). Default skew is
  `DEFAULT_SKEW_SECS = 300` (line 66); `with_skew` rejects non-positive skew (lines
  272–280).
- **O(1) replay cache.** `ReplayCache` (lines 173–245) uses a `HashSet` of
  `(client_id, nonce)` for O(1) membership plus a `VecDeque` eviction queue. On each
  `verify`, every entry that is no longer `is_replayable` at `now` is evicted by a
  full position-independent sweep (lines 224–232) — a front-only pop would be unsound
  because client-controlled timestamps make the queue non-monotonic (lines 173–188).
- **Fail-closed cap.** `MAX_NONCE_ENTRIES = 1_000_000` (lines 68–73). When the live
  set hits the cap, `check_and_record` returns `Err(())` and `verify` rejects with a
  storage error rather than admitting an unbounded request (lines 238–240, 563–564).
  Test `nonce_cache_caps_and_fails_closed` (lines 998–1034).
- **Retention matches admission.** `is_replayable` (lines 400–402) is trailing-edge
  only (`now − ts <= skew`), derived from the *same* `now`/`skew` as admission, so a
  nonce is retained exactly as long as a replay of it could still be admitted — no
  early eviction (trailing-edge replay slot) and no indefinite retention. Tests
  `nonce_not_evictable_while_replay_still_fresh` (lines 880–922) and
  `future_dated_nonce_survives_backward_clock_step` (lines 924–966).
- **Saturating arithmetic.** Both predicates use `saturating_sub`/`saturating_abs`
  (lines 382, 401), so attacker timestamps at `i64::MIN`/`i64::MAX` are rejected
  without panicking (`i64::MIN.abs()` would) or wrapping into the window. Test
  `out_of_range_timestamp_is_rejected_not_panicking` (lines 968–996).

### Canonicalization
`canonicalize` (lines 404–419) delegates to
`wyrtloom_core::client_auth::canonical_request`, which length-prefixes every field
under a domain-separation tag (`DOMAIN_TAG`, lines 56–58; README documents 8-byte
big-endian length prefixes and the `wyrtloom-client-auth-v1` tag, README lines 70–75).
Clients, the verifier, and the API server all derive byte-identical signed bytes from
one shared encoder, so field-boundary confusion is impossible (e.g. `("ab","c")`
cannot collide with `("a","bc")` — test `canonicalize_is_unambiguous`, lines
1187–1199). Bumping the domain tag hard-invalidates older clients' signatures
(lines 56–58).

## Key decisions & rationale

- **`client_id == fingerprint == SHA-256(pubkey)`** (lines 435–438). A
  self-certifying id means the store needs no separate id↔key mapping and a forged id
  requires a SHA-256 second preimage.
- **Store only public material** (lines 78–94, 478–496). The store can never leak a
  client secret because it never holds one; enforced by test (lines 1104–1150).
- **Algorithm by length, not a wire field** (lines 100–122). The two encodings (32 vs
  65 bytes) are unambiguous, removing a field an attacker could otherwise try to
  confuse, and `key_alg` is recorded at enroll for verification dispatch.
- **Enforce low-s for P-256** (lines 151–157). Closes ECDSA signature malleability so
  a captured signature cannot be re-encoded into a second valid form.
- **Hash + single-use + constant-time bootstrap keys.** A stolen store reveals no
  usable bootstrap key; timing does not leak the comparison; a key works at most once.
- **Store-level CAS for bootstrap single-use.** The persistence contract now offers
  `put_if_absent` (an atomic insert-if-absent), so single-use is settled by an atomic
  consume-marker insert rather than a read-modify-write. This holds **across
  processes** sharing the store, removing the prior dependence on the process-local
  `enroll_lock` for single-use correctness.
- **Process `Mutex` as TOFU-pin belt-and-suspenders only.** `enroll_lock` still
  serializes the in-process TOFU pin `get`→`put` so two threads here don't both treat
  the same `client_id` as first contact. It is **not** what makes a bootstrap key
  single-use anymore — that is the store CAS above. Dropping the lock would weaken only
  the in-process TOFU-pin race for a brand-new `client_id`, not single-use.
- **Retention predicate distinct from admission** (lines 400–402 vs 374–383). Using
  the symmetric window for eviction would wrongly drop a future-dated entry on a
  backward clock step and reopen a replay slot; trailing-edge retention prevents that.

## Gotchas / watch-outs

- **P-256 clients MUST low-s-normalize before sending.** The verifier rejects high-s
  signatures (lines 151–157). WebCrypto `crypto.subtle.sign('ECDSA', …)` emits high-s
  ~50% of the time and does **not** normalize, so a non-normalizing client sees
  intermittent ~50% `BadSignature` rejections. Normalize: if `s > n/2`, replace `s`
  with `n − s` and leave `r` unchanged. Reference implementation: `normalizeLowS` in
  `wyrtloom-dashboard-web/src/crypto/clientKey.ts` (README lines 61–68). ed25519 has
  no such requirement — it is deterministic (README line 58).
- **Replay cache is process-local.** The per-request replay/nonce cache
  (`seen_nonces`) is **process-local**. Horizontal scaling over a shared store would
  let two instances each admit the same `(client_id, nonce)` once (cross-instance
  replay) within the ±skew window, because that cache is in-memory per process. Fixing
  this would require moving nonce state into the shared store with a compare-and-set
  (the same `put_if_absent` primitive now used for bootstrap single-use). **Bootstrap
  single-use is no longer subject to this caveat:** it is enforced by the store's
  atomic `put_if_absent` consume marker, so two instances racing the same bootstrap
  key still yield exactly one successful enrollment (test
  `bootstrap_key_single_use_across_processes`).
- **TOFU first-contact trust.** A MITM on the very first enrollment can pin its own
  key and thereafter authenticate as that client. TOFU trusts whatever key arrives
  first. Mitigations live outside this crate: secure out-of-band bootstrap-key
  distribution, and (ideally) TLS for any non-loopback enrollment path.
- **Idempotent re-enroll consumes no bootstrap key.** Re-presenting the same key for
  an already-pinned `client_id` succeeds without a fresh bootstrap key (lines
  460–469). This is intentional (the returned credential carries no secret), but
  means possession of the public key alone re-confirms an existing pin.
- **Clock dependence.** Freshness is wall-clock based (`now_unix`, lines 368–371).
  A badly wrong server clock shifts the entire admission window; clients must also be
  within `±skew` of the server.

## Operational requirements

- **Distribute bootstrap keys out of band and once.** The plaintext is returned only
  by `issue_bootstrap_key` and never stored recoverably (lines 304–326). Treat it as a
  one-time secret; it is single-use and expires on first successful enrollment.
- **Replay cache requires a single instance (bootstrap single-use does not).**
  Bootstrap-key single-use is cross-process atomic (store CAS), so multiple instances
  may safely share one store for enrollment. The per-request replay/nonce cache,
  however, is still process-local: run a single instance, or move replay-nonce state
  into the shared store with `put_if_absent`, before relying on cross-instance replay
  protection (see Gotchas).
- **Use TLS for non-loopback enrollment and requests.** This crate authenticates and
  binds requests but provides no transport security; first-contact MITM and request
  confidentiality are the deployment's responsibility.
- **Keep client and server clocks within `±skew`.** Default `±300s` (line 66); tune
  via `with_skew` (lines 272–280). Too-wide a skew enlarges the replay window and
  cache (size is O(2·skew·rate), lines 68–73); too-narrow rejects legitimate drift.
- **Size the replay cache for your rate.** Steady-state live entries are
  O(2·skew·rate); the hard cap is 1,000,000 (line 73) and the scheme fails closed at
  the cap. Ensure expected `skew × request-rate` stays well under the cap.
- **Provide a durable `PersistenceProvider` with an atomic `put_if_absent`.** Pinned
  clients and bootstrap-key consumption state are only as durable as the injected
  store; losing it loses the TOFU pins and the consumed-key markers (collections
  `clients`, `bootstrap_keys`, and `consumed_bootstrap_keys`). Cross-process
  single-use additionally **requires** the store's `put_if_absent` to be genuinely
  atomic across connections/processes (the sqlite store's `INSERT … ON CONFLICT DO
  NOTHING` under WAL is; the contract's default get-then-put fallback is **not** and
  must not be used as a shared backing store for single-use).

//! Trust-on-first-use (TOFU) [`ClientAuthScheme`] with asymmetric (ed25519) keys.
//!
//! Part of the Wyrtloom dashboard ecosystem. This crate authenticates the *client
//! application* (web SPA, mobile app, CLI) — distinct from the human user — over
//! an injected [`PersistenceProvider`], so the backing store is swappable.
//!
//! # Model
//!
//! 1. An operator mints a single-use **bootstrap key** with [`TofuClientAuth::issue_bootstrap_key`]
//!    and distributes the plaintext out of band. Only its SHA-256 hash is stored.
//! 2. A client makes first contact via [`enroll`](TofuClientAuth::enroll), presenting the
//!    bootstrap key and its **ed25519 public key**. The server validates the key
//!    (hash + constant-time compare against the issued record), **atomically consumes
//!    it** via the store's compare-and-set (single-use even across processes sharing
//!    the store), and **pins** the public key (TOFU). Only the public key +
//!    fingerprint are stored.
//! 3. Each subsequent request is verified by [`verify`](TofuClientAuth::verify): an
//!    ed25519 signature over the canonical request bytes, a bounded ±skew timestamp
//!    window, and a per-request nonce checked against a bounded, evicting replay cache.
//!
//! # Security
//!
//! - **Asymmetric only.** The store never holds a recoverable secret — only the
//!   client's public key and its SHA-256 fingerprint.
//! - **Bootstrap keys** are CSPRNG, ≥128-bit, single-use, stored hashed, and
//!   constant-time compared. Single-use is enforced by an atomic consume marker
//!   (`put_if_absent`), so it holds across processes sharing the store — not merely
//!   within one process. A bad or already-consumed key yields [`ClientAuthError::BadApiKey`].
//! - **Canonicalization** ([`canonicalize`]) length-prefixes every field under a
//!   domain-separation tag so field-boundary confusion is impossible and clients and
//!   the server build identical signed bytes.
//! - **Replay protection** enforces a bounded ±skew admission window
//!   (`[now-skew, now+skew]`) and evicts a nonce on each `verify` the instant a
//!   replay of it could no longer be admitted. Admission and nonce-retention are
//!   derived from the *same* `now` and `skew`, so an admitted nonce is retained for
//!   exactly as long as a replay of it would still pass admission — never evicted
//!   early (no trailing-edge replay slot) and never retained past usefulness. With
//!   `now` monotonic in practice, live entries' timestamps span at most `2·skew`,
//!   bounding the cache at O(2·skew·rate). Attacker-controlled timestamps use
//!   saturating arithmetic, so out-of-range values are rejected without panicking
//!   or wrapping into the window.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use wyrtloom_core::client_auth::{
    ClientAuthError, ClientAuthScheme, ClientCredential, ClientIdentity, EnrollmentRequest,
    PresentedClientAuth,
};
use wyrtloom_core::persistence::{CollectionSpec, PersistenceProvider, Record, StoreError};
use wyrtloom_core::types::Timestamp;

/// Domain-separation tag mixed into every canonical request. Bumping this version
/// hard-invalidates signatures built by older clients.
pub const DOMAIN_TAG: &[u8] = wyrtloom_core::client_auth::CLIENT_AUTH_DOMAIN.as_bytes();

/// Collection holding pinned client identities.
const CLIENTS: &str = "clients";
/// Collection holding hashed, single-use bootstrap keys.
const BOOTSTRAP_KEYS: &str = "bootstrap_keys";
/// Collection of consume markers, one per redeemed bootstrap key. The marker's id
/// is the key's SHA-256 hash; its presence means the key was already consumed.
/// First-consumption is decided by an atomic `put_if_absent` here (a store-level
/// compare-and-set), so single-use holds across processes sharing the store — not
/// merely within one process via a lock.
const CONSUMED_BOOTSTRAP_KEYS: &str = "consumed_bootstrap_keys";

/// Default permitted clock skew (seconds) for the timestamp / replay window.
pub const DEFAULT_SKEW_SECS: i64 = 300;

/// Hard cap on live nonce-cache entries. Under `now` monotonic in practice, live
/// timestamps span at most `2·skew`, so the steady-state size is O(2·skew·rate);
/// this cap is a fail-closed backstop against an unbounded burst (e.g. a forged
/// clock feeding many distinct in-window nonces). When the cap is hit, `verify`
/// rejects (fail closed) rather than admitting an unbounded request.
const MAX_NONCE_ENTRIES: usize = 1_000_000;

/// Maximum accepted `client_name` length (chars).
const MAX_CLIENT_NAME_LEN: usize = 256;

/// Stored shape of a pinned client. Note: **no private/secret material** —
/// only the public key, its fingerprint, the validated name, and the time.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredClient {
    client_id: String,
    /// Public key, hex-encoded. ed25519 raw (32 bytes) or SEC1 uncompressed
    /// P-256 (65 bytes), per `key_alg`.
    public_key: String,
    /// Signature algorithm: `"ed25519"` or `"p256"`. Defaulted for records
    /// written before P-256 support (all such records are ed25519).
    #[serde(default = "default_key_alg")]
    key_alg: String,
    /// SHA-256 hex of the raw public-key bytes (the TOFU pin / fingerprint).
    fingerprint: String,
    client_name: String,
    enrolled_at: Timestamp,
}

fn default_key_alg() -> String {
    "ed25519".to_string()
}

/// Detect and validate the public-key algorithm from its encoding: a 32-byte
/// ed25519 key, or a 65-byte SEC1 *uncompressed* P-256 key (`0x04` prefix). The
/// two encodings are unambiguous by length, so no separate algorithm field is
/// needed on the wire — the scheme decides how to interpret the contract's
/// opaque `public_key` bytes.
fn detect_key_alg(public_key: &[u8]) -> Result<&'static str, ClientAuthError> {
    match public_key.len() {
        32 => {
            let b: [u8; 32] = public_key.try_into().unwrap();
            VerifyingKey::from_bytes(&b)
                .map_err(|_| ClientAuthError::Invalid("invalid ed25519 public_key".into()))?;
            Ok("ed25519")
        }
        65 if public_key[0] == 0x04 => {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| ClientAuthError::Invalid("invalid P-256 public_key".into()))?;
            Ok("p256")
        }
        _ => Err(ClientAuthError::Invalid(
            "public_key must be a 32-byte ed25519 key or a 65-byte SEC1 P-256 key".into(),
        )),
    }
}

/// Verify a signature over `msg` for the stored hex public key, dispatching on
/// the recorded algorithm. WebCrypto emits raw r‖s (P1363) ECDSA signatures and
/// SEC1 public keys, matching the `p256` crate's `from_slice`/`from_sec1_bytes`.
fn verify_signature(
    key_alg: &str,
    public_key_hex: &str,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), ClientAuthError> {
    let corrupt = || ClientAuthError::Storage("stored public key is corrupt".into());
    match key_alg {
        "ed25519" => {
            let vk_bytes = hex_decode(public_key_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(corrupt)?;
            let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| corrupt())?;
            let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| ClientAuthError::BadSignature)?;
            vk.verify(msg, &Signature::from_bytes(&sig_bytes))
                .map_err(|_| ClientAuthError::BadSignature)
        }
        "p256" => {
            use p256::ecdsa::signature::Verifier as _;
            let pk_bytes = hex_decode(public_key_hex).map_err(|_| corrupt())?;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(|_| corrupt())?;
            let signature =
                p256::ecdsa::Signature::from_slice(sig).map_err(|_| ClientAuthError::BadSignature)?;
            // Enforce low-s (canonical) signatures to remove ECDSA malleability:
            // a high-s signature can be flipped to a second, distinct, still-valid
            // encoding of the same message. `normalize_s()` returns `Some(_)` only
            // when the input was non-canonical (high-s), so reject those outright.
            if signature.normalize_s().is_some() {
                return Err(ClientAuthError::BadSignature);
            }
            vk.verify(msg, &signature).map_err(|_| ClientAuthError::BadSignature)
        }
        _ => Err(ClientAuthError::Storage("unknown key algorithm".into())),
    }
}

/// Stored shape of an *issued* bootstrap key: only its hash and issue time. The
/// "consumed" state is no longer a mutable flag on this record — it is tracked
/// out-of-band by the presence of a marker in [`CONSUMED_BOOTSTRAP_KEYS`], decided
/// atomically by the store's compare-and-set. Keeping issuance and consumption in
/// separate records is what lets a single `put_if_absent` settle single-use without
/// any read-modify-write here.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredBootstrapKey {
    /// SHA-256 hex of the plaintext bootstrap key.
    key_hash: String,
    issued_at: Timestamp,
}

/// Stored shape of a consume marker: its id (in [`CONSUMED_BOOTSTRAP_KEYS`]) is the
/// key's SHA-256 hash, so its mere presence means the key was redeemed. The body is
/// purely informational (when it was consumed); single-use correctness depends only
/// on the atomic insert of this row, never on reading it back.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsumedBootstrapKey {
    consumed_at: Timestamp,
}

/// Bounded, evicting replay cache with O(1) membership.
///
/// Membership is a [`HashSet`] of `(client_id, nonce)` keys so the replay check is
/// O(1) instead of an O(n) linear scan under the mutex. Eviction is tracked by a
/// [`VecDeque`] of `(timestamp, key)` recording each admitted entry.
///
/// On each call, eviction matches the prior code's `retain` semantics exactly: it
/// drops **every** entry that is no longer [`is_replayable`] at `now`, regardless of
/// its position in the queue. A front-only pop would be unsound for the memory
/// bound here because the queue is *not* timestamp-ordered — `presented.timestamp`
/// is client-controlled across the whole `[now-skew, now+skew]` admission band, so a
/// future-dated entry can sit ahead of already-expired ones and would block a
/// front-only sweep, letting non-replayable stragglers accumulate toward the cap. A
/// full retain keeps the live set bounded at O(2·skew·rate) under adversarial
/// timestamps and never evicts a still-replayable entry (no trailing-edge replay
/// slot), preserving the documented retention contract.
struct ReplayCache {
    /// O(1) membership over `(client_id, nonce)`.
    seen: HashSet<(String, String)>,
    /// Eviction queue mirroring `seen`'s membership, in admission order.
    order: VecDeque<(i64, (String, String))>,
    /// Fail-closed cap on live entries.
    max_entries: usize,
}

impl ReplayCache {
    fn new(max_entries: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    /// Evict every entry whose timestamp is no longer replayable at `now`, then test
    /// the presented `(client_id, nonce)` for replay and, if fresh, record it.
    ///
    /// Returns `Ok(true)` if the nonce was newly recorded, `Ok(false)` if it is a
    /// replay, and `Err(())` if recording would exceed `max_entries`
    /// (fail closed). Eviction uses the same `now`/`skew` as admission via
    /// [`is_replayable`], so an admitted nonce is retained for exactly as long as a
    /// replay of it would still pass admission — no trailing-edge slot.
    fn check_and_record(
        &mut self,
        client_id: &str,
        nonce: &str,
        timestamp: i64,
        now: i64,
        skew: i64,
    ) -> Result<bool, ()> {
        // Drop every no-longer-replayable entry (full sweep, position-independent),
        // mirroring the prior `Vec::retain`. The membership set stays in sync.
        let seen = &mut self.seen;
        self.order.retain(|(ts, key)| {
            let keep = is_replayable(now, *ts, skew);
            if !keep {
                seen.remove(key);
            }
            keep
        });

        let key = (client_id.to_string(), nonce.to_string());
        if self.seen.contains(&key) {
            return Ok(false);
        }
        if self.seen.len() >= self.max_entries {
            return Err(());
        }
        self.seen.insert(key.clone());
        self.order.push_back((timestamp, key));
        Ok(true)
    }
}

/// Trust-on-first-use client-authentication scheme over an injected store.
pub struct TofuClientAuth {
    store: Arc<dyn PersistenceProvider>,
    /// Belt-and-suspenders serialization of the in-process TOFU pin check
    /// (`get` → `put` on [`CLIENTS`]) so two threads in THIS process don't
    /// interleave a first-contact insert. It is **not** what makes a bootstrap key
    /// single-use: that guarantee now rests entirely on the store's atomic
    /// `put_if_absent` consume marker (see [`consume_bootstrap_key`]), which holds
    /// across processes sharing the store. Single-use correctness does not depend on
    /// this lock; dropping it would only weaken the cross-process-shared TOFU-pin
    /// race for a never-before-seen client_id, not single-use.
    ///
    /// [`consume_bootstrap_key`]: TofuClientAuth::consume_bootstrap_key
    enroll_lock: Mutex<()>,
    /// Bounded, O(1)-membership cache of recently seen `(client_id, nonce)`. On each
    /// `verify` an entry is evicted exactly when a replay of it could no longer be
    /// admitted (see `is_replayable` and `ReplayCache`), so no in-window nonce is
    /// ever evicted while it remains replayable.
    seen_nonces: Mutex<ReplayCache>,
    skew_secs: i64,
}

impl TofuClientAuth {
    /// Create the scheme over `store`, ensuring the `clients` and `bootstrap_keys`
    /// collections (with their indexes) exist. Uses [`DEFAULT_SKEW_SECS`].
    pub fn new(store: Arc<dyn PersistenceProvider>) -> Result<Self, ClientAuthError> {
        Self::with_skew(store, DEFAULT_SKEW_SECS)
    }

    /// As [`new`](Self::new) but with an explicit skew/replay window in seconds.
    pub fn with_skew(
        store: Arc<dyn PersistenceProvider>,
        skew_secs: i64,
    ) -> Result<Self, ClientAuthError> {
        if skew_secs <= 0 {
            return Err(ClientAuthError::Invalid(
                "skew_secs must be positive".into(),
            ));
        }
        store
            .ensure_collection(&CollectionSpec {
                name: CLIENTS.into(),
                indexed_fields: vec!["fingerprint".into()],
            })
            .map_err(store_err)?;
        store
            .ensure_collection(&CollectionSpec {
                name: BOOTSTRAP_KEYS.into(),
                indexed_fields: vec!["key_hash".into()],
            })
            .map_err(store_err)?;
        // Consume markers are looked up only by their id (the key hash) via the
        // atomic `put_if_absent`, so the record body needs no secondary index.
        store
            .ensure_collection(&CollectionSpec {
                name: CONSUMED_BOOTSTRAP_KEYS.into(),
                indexed_fields: vec![],
            })
            .map_err(store_err)?;
        Ok(Self {
            store,
            enroll_lock: Mutex::new(()),
            seen_nonces: Mutex::new(ReplayCache::new(MAX_NONCE_ENTRIES)),
            skew_secs,
        })
    }

    /// Mint a single-use bootstrap key. A CSPRNG ≥128-bit token is generated; only
    /// its SHA-256 hash is persisted (an issuance record in [`BOOTSTRAP_KEYS`] — the
    /// "consumed" state lives separately, see [`consume_bootstrap_key`]). The
    /// plaintext is returned **once** for the operator to distribute out of band — it
    /// is not recoverable.
    ///
    /// [`consume_bootstrap_key`]: TofuClientAuth::consume_bootstrap_key
    pub fn issue_bootstrap_key(&self) -> Result<String, ClientAuthError> {
        // 256 bits of CSPRNG entropy, well above the 128-bit floor.
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let plaintext = hex_encode(&raw);
        let key_hash = sha256_hex(plaintext.as_bytes());

        let record = StoredBootstrapKey {
            key_hash: key_hash.clone(),
            issued_at: Timestamp::now(),
        };
        self.store
            .put(
                BOOTSTRAP_KEYS,
                Record {
                    id: key_hash,
                    doc: to_value(&record)?,
                },
            )
            .map_err(store_err)?;
        Ok(plaintext)
    }

    /// Validate a presented bootstrap key and atomically consume it. A bad,
    /// never-issued, or already-consumed key → `BadApiKey`.
    ///
    /// Single-use is settled by a store-level **compare-and-set**, not by any
    /// read-modify-write here: after confirming the key was genuinely issued (its
    /// hash exists in [`BOOTSTRAP_KEYS`], constant-time compared), we attempt to
    /// insert a consume marker keyed by that hash via [`PersistenceProvider::put_if_absent`].
    /// That insert is atomic across processes sharing the store (the sqlite store
    /// uses a single `INSERT … ON CONFLICT DO NOTHING` under WAL), so exactly one
    /// caller — process or thread — observes `Ok(true)` and consumes the key; every
    /// other concurrent or later attempt observes `Ok(false)` and is rejected. The
    /// in-process `enroll_lock` is NOT relied upon for this guarantee.
    fn consume_bootstrap_key(&self, presented: &str) -> Result<(), ClientAuthError> {
        let hash = sha256_hex(presented.as_bytes());
        // 1. Confirm the key was actually issued. Look up by the hash id directly
        //    (it *is* the record id).
        let record = match self.store.get(BOOTSTRAP_KEYS, &hash) {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => return Err(ClientAuthError::BadApiKey),
            Err(e) => return Err(store_err(e)),
        };
        let stored: StoredBootstrapKey = from_value(record.doc)?;

        // Constant-time compare the stored hash against the recomputed hash. (The
        // id lookup already matched, but compare explicitly so the verification
        // path is uniform and resistant to any future change in lookup strategy.)
        let matches: bool = stored.key_hash.as_bytes().ct_eq(hash.as_bytes()).into();
        if !matches {
            return Err(ClientAuthError::BadApiKey);
        }

        // 2. Atomically claim single-use. The FIRST insert of this marker wins
        //    (Ok(true)); any subsequent attempt — even from another process —
        //    sees the marker already present (Ok(false)) and is rejected. This is
        //    the sole arbiter of single-use; it does not depend on `enroll_lock`.
        let marker = ConsumedBootstrapKey {
            consumed_at: Timestamp::now(),
        };
        let inserted = self
            .store
            .put_if_absent(
                CONSUMED_BOOTSTRAP_KEYS,
                Record {
                    id: hash,
                    doc: to_value(&marker)?,
                },
            )
            .map_err(store_err)?;
        if !inserted {
            return Err(ClientAuthError::BadApiKey);
        }
        Ok(())
    }

    /// Current Unix-seconds time.
    fn now_unix() -> i64 {
        Timestamp::now().0.timestamp()
    }
}

/// Whether a request stamped `ts` is *fresh* for **admission** relative to `now`
/// under `skew`: the accepted window is the closed interval `[now-skew, now+skew]`,
/// rejecting both stale and far-future timestamps.
///
/// `ts` is attacker-controlled, so the subtraction is saturating: an out-of-range
/// timestamp (e.g. `i64::MIN`) saturates to a value far outside `±skew` and is
/// rejected, never panicking (`i64::MIN.abs()` would) or wrapping into the window.
fn is_fresh(now: i64, ts: i64, skew: i64) -> bool {
    now.saturating_sub(ts).saturating_abs() <= skew
}

/// Whether a nonce recorded with timestamp `ts` could **still be replayed** at
/// `now` — i.e. a replay carrying that original `ts` would still pass [`is_fresh`]
/// admission. This is the nonce-cache *retention* predicate.
///
/// A replay only ever falls off the **trailing** (past) edge of the admission
/// window as `now` advances: it stops being admissible exactly when `now - ts >
/// skew`. The leading (future) edge only gates *first* admission; once an entry is
/// recorded, `now` only moves toward the trailing edge, so retention must test the
/// trailing edge alone. Using the symmetric [`is_fresh`] here would wrongly evict a
/// future-dated-but-still-replayable entry if `now` ever stepped backward (clock
/// correction), reopening a replay slot. Retaining iff `now - ts <= skew`
/// guarantees no entry is evicted while a replay of it would still be admitted, and
/// (under `now` monotonic in practice) bounds the cache at O(2·skew·rate): the
/// widest a retained entry's `ts` can trail `now` is `skew`, and the furthest ahead
/// it can have been admitted is `skew`, so live timestamps span `2·skew`.
fn is_replayable(now: i64, ts: i64, skew: i64) -> bool {
    now.saturating_sub(ts) <= skew
}

/// Build the canonical, signed request bytes. Delegates to the core contract
/// function [`wyrtloom_core::client_auth::canonical_request`] so that clients, the
/// `ClientAuthScheme` verifier, and the API server all derive byte-identical input
/// from one shared, audited length-prefix encoder (no per-crate reinvention).
pub fn canonicalize(
    method: &str,
    path: &str,
    body_sha256: &[u8],
    client_id: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8> {
    wyrtloom_core::client_auth::canonical_request(
        method, path, body_sha256, client_id, timestamp, nonce,
    )
}

impl ClientAuthScheme for TofuClientAuth {
    fn enroll(&self, req: EnrollmentRequest) -> Result<ClientCredential, ClientAuthError> {
        // 1. Validate the client name (validated, not trusted).
        let name = req.client_name.trim();
        if name.is_empty() || name.chars().count() > MAX_CLIENT_NAME_LEN {
            return Err(ClientAuthError::Invalid(
                "client_name must be 1..=256 non-blank chars".into(),
            ));
        }

        // 2. Detect + validate the public key (ed25519 or P-256) before we burn the
        //    single-use bootstrap key, so a malformed key doesn't waste the token.
        let key_alg = detect_key_alg(&req.public_key)?;

        // 3. Derive the deterministic fingerprint and client_id from the public key.
        let fingerprint = sha256_hex(&req.public_key);
        let client_id = fingerprint.clone();
        let public_key_hex = hex_encode(&req.public_key);

        // Serialize the in-process TOFU pin check (`get` → `put` on CLIENTS) so two
        // threads here don't both treat the same client_id as first contact. This is
        // belt-and-suspenders only: single-use of the bootstrap key is enforced by
        // the store's atomic `put_if_absent` consume marker in
        // `consume_bootstrap_key`, which holds even across separate processes sharing
        // the store and does NOT rely on this lock. (For a store shared across
        // processes, the TOFU-pin first-contact race is settled by the consume marker
        // being burned exactly once, so at most one process completes a first-contact
        // enrollment for a given bootstrap key.)
        let _enroll_guard = self
            .enroll_lock
            .lock()
            .map_err(|_| ClientAuthError::Storage("enroll lock poisoned".into()))?;

        // 4. TOFU pin check. Look up an existing client by id.
        match self.store.get(CLIENTS, &client_id) {
            Ok(existing) => {
                let stored: StoredClient = from_value(existing.doc)?;
                if stored.public_key != public_key_hex {
                    return Err(ClientAuthError::PinMismatch);
                }
                // Same key → idempotent re-enroll. Do NOT consume a bootstrap key:
                // the pinned key is public material the caller already holds, and
                // the returned credential carries no secret, so re-confirming an
                // existing pin without a fresh bootstrap key exposes nothing an
                // attacker could not derive from the public key itself.
                return Ok(ClientCredential {
                    client_id: stored.client_id,
                    fingerprint: stored.fingerprint,
                    enrolled_at: stored.enrolled_at,
                });
            }
            Err(StoreError::NotFound(_)) => { /* first contact — proceed */ }
            Err(e) => return Err(store_err(e)),
        }

        // 5. Validate + consume the single-use bootstrap key (only for new clients).
        self.consume_bootstrap_key(&req.api_key)?;

        // 6. Persist ONLY public material.
        let enrolled_at = Timestamp::now();
        let stored = StoredClient {
            client_id: client_id.clone(),
            public_key: public_key_hex,
            key_alg: key_alg.to_string(),
            fingerprint: fingerprint.clone(),
            client_name: name.to_string(),
            enrolled_at: enrolled_at.clone(),
        };
        self.store
            .put(
                CLIENTS,
                Record {
                    id: client_id.clone(),
                    doc: to_value(&stored)?,
                },
            )
            .map_err(store_err)?;

        Ok(ClientCredential {
            client_id,
            fingerprint,
            enrolled_at,
        })
    }

    fn verify(&self, presented: &PresentedClientAuth) -> Result<ClientIdentity, ClientAuthError> {
        self.verify_at(presented, Self::now_unix())
    }
}

impl TofuClientAuth {
    /// [`verify`](ClientAuthScheme::verify) with an explicitly supplied notion of
    /// "now" (Unix seconds). The public trait method calls this with the system
    /// clock; tests inject `now` to exercise the freshness/eviction boundary
    /// without sleeping. The freshness check and the cache-eviction predicate are
    /// both [`is_fresh`] against the *same* `now`, so they can never disagree.
    fn verify_at(
        &self,
        presented: &PresentedClientAuth,
        now: i64,
    ) -> Result<ClientIdentity, ClientAuthError> {
        // 1. Look up the pinned client.
        let record = match self.store.get(CLIENTS, &presented.client_id) {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => return Err(ClientAuthError::UnknownClient),
            Err(e) => return Err(store_err(e)),
        };
        let stored: StoredClient = from_value(record.doc)?;

        // 2. Verify the signature (ed25519 or P-256) over the presented canonical
        //    request, using the stored key's recorded algorithm.
        verify_signature(
            &stored.key_alg,
            &stored.public_key,
            &presented.canonical_request,
            &presented.signature,
        )?;

        // 3. Enforce the bounded ±skew timestamp window. A request is admitted
        //    iff its timestamp is fresh relative to `now`.
        if !is_fresh(now, presented.timestamp, self.skew_secs) {
            return Err(ClientAuthError::Replay);
        }

        // 4. Replay check + nonce recording, with eviction. An entry is retained
        //    exactly while a replay carrying its timestamp would still pass the
        //    step-3 admission window (`is_replayable`, derived from the same `now`
        //    and `skew`). This closes the trailing-edge replay slot: a recorded
        //    nonce is never evicted while a replay of it would still be admitted,
        //    and no longer-replayable entry lingers — keeping the cache bounded.
        let mut cache = self
            .seen_nonces
            .lock()
            .map_err(|_| ClientAuthError::Storage("nonce cache poisoned".into()))?;
        match cache.check_and_record(
            &presented.client_id,
            &presented.nonce,
            presented.timestamp,
            now,
            self.skew_secs,
        ) {
            Ok(true) => { /* fresh nonce, recorded */ }
            Ok(false) => return Err(ClientAuthError::Replay),
            // Cap exceeded: fail closed rather than admit an unbounded request.
            Err(()) => return Err(ClientAuthError::Storage("nonce cache full".into())),
        }
        drop(cache);

        Ok(ClientIdentity {
            client_id: stored.client_id,
        })
    }
}

// ---- small helpers ---------------------------------------------------------

fn store_err(e: StoreError) -> ClientAuthError {
    ClientAuthError::Storage(e.to_string())
}

fn to_value<T: Serialize>(v: &T) -> Result<serde_json::Value, ClientAuthError> {
    serde_json::to_value(v).map_err(|e| ClientAuthError::Storage(e.to_string()))
}

fn from_value<T: for<'de> Deserialize<'de>>(
    v: serde_json::Value,
) -> Result<T, ClientAuthError> {
    serde_json::from_value(v).map_err(|e| ClientAuthError::Storage(e.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or(())?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use wyrtloom_store_sqlite::SqliteStore;

    fn scheme() -> TofuClientAuth {
        let store: Arc<dyn PersistenceProvider> =
            Arc::new(SqliteStore::in_memory().expect("in-memory store"));
        TofuClientAuth::new(store).expect("scheme")
    }

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn enroll_with(scheme: &TofuClientAuth, api_key: &str, sk: &SigningKey) -> ClientCredential {
        scheme
            .enroll(EnrollmentRequest {
                api_key: api_key.to_string(),
                client_name: "dashboard-spa".into(),
                public_key: sk.verifying_key().to_bytes().to_vec(),
            })
            .expect("enroll")
    }

    fn presented(
        sk: &SigningKey,
        client_id: &str,
        timestamp: i64,
        nonce: &str,
    ) -> PresentedClientAuth {
        let canonical = canonicalize(
            "POST",
            "/v1/tasks",
            &sha256_bytes(b"{}"),
            client_id,
            timestamp,
            nonce,
        );
        let sig = sk.sign(&canonical);
        PresentedClientAuth {
            client_id: client_id.to_string(),
            canonical_request: canonical,
            signature: sig.to_bytes().to_vec(),
            timestamp,
            nonce: nonce.to_string(),
        }
    }

    fn sha256_bytes(b: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().to_vec()
    }

    #[test]
    fn bootstrap_key_is_single_use() {
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();

        // First enroll with the key succeeds.
        let cred = enroll_with(&s, &key, &sk);
        assert_eq!(cred.client_id.len(), 64); // sha-256 hex

        // Reusing the same key for a *different* client → BadApiKey (consumed).
        let sk2 = keypair();
        let err = s
            .enroll(EnrollmentRequest {
                api_key: key.clone(),
                client_name: "another".into(),
                public_key: sk2.verifying_key().to_bytes().to_vec(),
            })
            .unwrap_err();
        assert!(matches!(err, ClientAuthError::BadApiKey), "got {err:?}");
    }

    #[test]
    fn p256_webcrypto_client_enrolls_and_verifies() {
        use p256::ecdsa::{signature::Signer, Signature as P256Sig, SigningKey as P256Key};
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();

        // A browser generates a non-extractable P-256 key and enrolls its SEC1
        // uncompressed public key (0x04 || X || Y, 65 bytes) — exactly what
        // SubtleCrypto exportKey('raw') produces.
        let sk = P256Key::random(&mut OsRng);
        let pubkey = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(pubkey.len(), 65);
        let cred = s
            .enroll(EnrollmentRequest {
                api_key: key,
                client_name: "web-spa".into(),
                public_key: pubkey,
            })
            .expect("p256 enroll");

        // Sign the canonical request (raw r‖s, as WebCrypto sign('ECDSA') emits).
        // The verifier requires canonical low-s form to remove malleability, so a
        // compliant client normalizes s before sending (the RustCrypto `p256` signer
        // does not auto-normalize; `normalize_s()` yields the canonical twin when the
        // freshly-signed value happened to be high-s).
        let canonical =
            canonicalize("POST", "/api/login", &sha256_bytes(b"{}"), &cred.client_id, 1_000, "n1");
        let raw: P256Sig = sk.sign(&canonical);
        let sig = raw.normalize_s().unwrap_or(raw);
        let presented = PresentedClientAuth {
            client_id: cred.client_id.clone(),
            canonical_request: canonical,
            signature: sig.to_bytes().to_vec(),
            timestamp: 1_000,
            nonce: "n1".into(),
        };
        assert!(s.verify_at(&presented, 1_000).is_ok(), "valid P-256 signature must verify");

        // Tampered signature is rejected (fresh nonce to bypass the replay cache).
        let mut bad = presented.clone();
        bad.signature[10] ^= 0x01;
        bad.nonce = "n2".into();
        assert!(matches!(s.verify_at(&bad, 1_000), Err(ClientAuthError::BadSignature)));
    }

    #[test]
    fn p256_high_s_signature_rejected() {
        // ECDSA signatures are malleable: (r, s) and (r, n - s) both verify. We
        // enforce low-s (canonical) form, so a high-s variant of a valid signature
        // must be rejected even though it is cryptographically valid for the message.
        use p256::ecdsa::{signature::Signer, Signature as P256Sig, SigningKey as P256Key};
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();

        let sk = P256Key::random(&mut OsRng);
        let pubkey = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let cred = s
            .enroll(EnrollmentRequest {
                api_key: key,
                client_name: "web-spa".into(),
                public_key: pubkey,
            })
            .expect("p256 enroll");

        let canonical =
            canonicalize("POST", "/api/login", &sha256_bytes(b"{}"), &cred.client_id, 1_000, "hs1");
        // The RustCrypto signer does not auto-normalize, so explicitly canonicalize
        // to low-s to obtain the form a compliant client would send.
        let raw: P256Sig = sk.sign(&canonical);
        let sig = raw.normalize_s().unwrap_or(raw);
        assert!(sig.normalize_s().is_none(), "base sig must be canonical low-s");

        // The canonical low-s signature verifies.
        let low = PresentedClientAuth {
            client_id: cred.client_id.clone(),
            canonical_request: canonical.clone(),
            signature: sig.to_bytes().to_vec(),
            timestamp: 1_000,
            nonce: "hs1".into(),
        };
        assert!(s.verify_at(&low, 1_000).is_ok(), "low-s signature must verify");

        // Construct the high-s malleated twin: s' = n - s. Negating the (low-s)
        // scalar yields its non-canonical high-s equivalent, an equally valid
        // ECDSA signature for the same message.
        let (r, s_scalar) = (sig.r(), sig.s());
        let high_s = -*s_scalar; // n - s, the non-canonical twin
        let high_sig = P256Sig::from_scalars(r, high_s).expect("high-s sig");
        // Sanity: the constructed sig is genuinely high-s (normalize would change it).
        assert!(high_sig.normalize_s().is_some(), "constructed sig must be high-s");

        let high = PresentedClientAuth {
            client_id: cred.client_id.clone(),
            canonical_request: canonical,
            signature: high_sig.to_bytes().to_vec(),
            timestamp: 1_000,
            nonce: "hs2".into(),
        };
        assert!(
            matches!(s.verify_at(&high, 1_000), Err(ClientAuthError::BadSignature)),
            "high-s (malleated) signature must be rejected"
        );
    }

    #[test]
    fn unknown_or_garbage_bootstrap_key_rejected() {
        let s = scheme();
        let sk = keypair();
        let err = s
            .enroll(EnrollmentRequest {
                api_key: "not-a-real-key".into(),
                client_name: "c".into(),
                public_key: sk.verifying_key().to_bytes().to_vec(),
            })
            .unwrap_err();
        assert!(matches!(err, ClientAuthError::BadApiKey), "got {err:?}");
    }

    #[test]
    fn verify_succeeds_then_tamper_fails() {
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        let now = TofuClientAuth::now_unix();
        let p = presented(&sk, &cred.client_id, now, "nonce-a");
        let id = s.verify(&p).expect("verify ok");
        assert_eq!(id.client_id, cred.client_id);

        // Tamper the signature → BadSignature.
        let mut bad = presented(&sk, &cred.client_id, now, "nonce-b");
        bad.signature[0] ^= 0xff;
        assert!(matches!(s.verify(&bad), Err(ClientAuthError::BadSignature)));

        // Tamper the canonical bytes (signature no longer matches) → BadSignature.
        let mut bad2 = presented(&sk, &cred.client_id, now, "nonce-c");
        let last = bad2.canonical_request.len() - 1;
        bad2.canonical_request[last] ^= 0xff;
        assert!(matches!(s.verify(&bad2), Err(ClientAuthError::BadSignature)));
    }

    #[test]
    fn unknown_client_rejected() {
        let s = scheme();
        let sk = keypair();
        let p = presented(&sk, "00ff", TofuClientAuth::now_unix(), "n");
        assert!(matches!(s.verify(&p), Err(ClientAuthError::UnknownClient)));
    }

    #[test]
    fn replayed_nonce_rejected() {
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        let now = TofuClientAuth::now_unix();
        let p = presented(&sk, &cred.client_id, now, "dup-nonce");
        assert!(s.verify(&p).is_ok());
        // Same (client_id, nonce) again → Replay.
        assert!(matches!(s.verify(&p), Err(ClientAuthError::Replay)));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        let stale = TofuClientAuth::now_unix() - DEFAULT_SKEW_SECS - 60;
        let p = presented(&sk, &cred.client_id, stale, "old-nonce");
        assert!(matches!(s.verify(&p), Err(ClientAuthError::Replay)));

        // Future beyond skew is equally rejected.
        let future = TofuClientAuth::now_unix() + DEFAULT_SKEW_SECS + 60;
        let pf = presented(&sk, &cred.client_id, future, "future-nonce");
        assert!(matches!(s.verify(&pf), Err(ClientAuthError::Replay)));
    }

    #[test]
    fn nonce_not_evictable_while_replay_still_fresh() {
        // Regression for the freshness/eviction boundary mismatch: a nonce admitted
        // at timestamp T must keep being rejected as Replay for the ENTIRE window
        // during which a replay of it would still pass the ±skew freshness check —
        // i.e. it must never be evicted one tick early, opening a trailing-edge slot.
        let skew = 300;
        let store: Arc<dyn PersistenceProvider> = Arc::new(SqliteStore::in_memory().unwrap());
        let s = TofuClientAuth::with_skew(store, skew).unwrap();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        // Admit a request at timestamp T, with "now" == T.
        let t = 1_000_000_000;
        let p = presented(&sk, &cred.client_id, t, "edge-nonce");
        assert!(s.verify_at(&p, t).is_ok(), "initial request must be accepted");

        // For every "now" across the whole window in which a replay of timestamp T
        // is STILL freshness-valid (|now - T| <= skew, i.e. now <= T + skew), the
        // exact same (client_id, nonce) replay must be rejected as Replay — proving
        // the entry was not evicted while still replayable.
        for now in t..=t + skew {
            assert!(
                is_fresh(now, t, skew),
                "test precondition: timestamp T must be fresh at now={now}"
            );
            assert!(
                matches!(s.verify_at(&p, now), Err(ClientAuthError::Replay)),
                "replay of T must stay rejected as Replay at now={now} (window still fresh)"
            );
        }

        // One tick past the window the replay is no longer admissible, so it is
        // rejected on freshness grounds (still Replay) and the entry may be evicted —
        // either way no fresh replay is ever admitted.
        let past = t + skew + 1;
        assert!(!is_fresh(past, t, skew));
        assert!(matches!(
            s.verify_at(&p, past),
            Err(ClientAuthError::Replay)
        ));
    }

    #[test]
    fn future_dated_nonce_survives_backward_clock_step() {
        // The retention predicate must be trailing-edge only (`now - ts <= skew`),
        // NOT the symmetric admission window. Otherwise a future-dated entry admitted
        // at the leading edge would be wrongly evicted if `now` ever stepped backward
        // (clock correction), reopening a replay slot while the replay is still
        // admissible.
        let skew = 300;
        let store: Arc<dyn PersistenceProvider> = Arc::new(SqliteStore::in_memory().unwrap());
        let s = TofuClientAuth::with_skew(store, skew).unwrap();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        // Admit a FUTURE-dated request: ts = now0 + skew (leading edge of admission).
        let now0 = 1_000_000_000;
        let ts = now0 + skew;
        let p = presented(&sk, &cred.client_id, ts, "future-edge");
        assert!(s.verify_at(&p, now0).is_ok(), "future-dated request must be admitted");

        // Clock steps BACKWARD to a point where the future-dated ts is OUTSIDE the
        // symmetric admission window (now < ts - skew), so the symmetric `is_fresh`
        // eviction predicate WOULD drop the entry here — but a trailing-edge-only
        // retention keeps it. At this `now` the replay is itself rejected on
        // freshness grounds; the danger is eviction now followed by recovery.
        let back = ts - skew - 100; // now < ts - skew  ⇒ is_fresh(back, ts) == false
        assert!(!is_fresh(back, ts, skew), "precondition: symmetric window would evict");
        assert!(is_replayable(back, ts, skew), "precondition: still trailing-edge retainable");
        // Replay at the backward `now` is rejected (Replay): freshness fails AND, with
        // correct trailing-edge retention, the entry is still present.
        assert!(matches!(s.verify_at(&p, back), Err(ClientAuthError::Replay)));

        // Clock recovers to an in-window `now`: the replay is now admissible by
        // freshness, so the ONLY thing rejecting it is the still-present nonce entry.
        // If the backward step had evicted it (symmetric predicate), this replay would
        // be wrongly admitted.
        let recovered = now0;
        assert!(is_fresh(recovered, ts, skew), "precondition: replay admissible again");
        assert!(
            matches!(s.verify_at(&p, recovered), Err(ClientAuthError::Replay)),
            "future-dated nonce must survive a backward clock step (trailing-edge retention)"
        );
    }

    #[test]
    fn out_of_range_timestamp_is_rejected_not_panicking() {
        // Attacker-controlled timestamps at the extremes of i64 must be rejected via
        // saturating arithmetic, never panic (`i64::MIN.abs()`) or wrap into the
        // freshness window.
        let skew = 300;
        let store: Arc<dyn PersistenceProvider> = Arc::new(SqliteStore::in_memory().unwrap());
        let s = TofuClientAuth::with_skew(store, skew).unwrap();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        for ts in [i64::MIN, i64::MIN + 1, i64::MAX, i64::MAX - 1] {
            let p = presented(&sk, &cred.client_id, ts, "extreme");
            assert!(
                matches!(s.verify_at(&p, TofuClientAuth::now_unix()), Err(ClientAuthError::Replay)),
                "extreme timestamp {ts} must be rejected as Replay"
            );
        }
        // The pure predicates must not panic at the extremes either.
        assert!(!is_fresh(0, i64::MIN, skew));
        assert!(!is_fresh(0, i64::MAX, skew));
        // Far-past ts: now - ts saturates to i64::MAX (> skew) → not replayable, evicted.
        assert!(!is_replayable(0, i64::MIN, skew));
        // Far-future ts: now - ts saturates to i64::MIN (<= skew) → still "replayable",
        // but such an entry can never have been admitted (is_fresh rejects it), so it
        // never enters the cache; harmless.
        assert!(is_replayable(0, i64::MAX, skew));
    }

    #[test]
    fn nonce_cache_caps_and_fails_closed() {
        // The replay cache must reject (fail closed) once the entry cap is exceeded,
        // rather than growing unbounded. Drive the ReplayCache directly with a small
        // injected cap so the test stays fast (the production cap is MAX_NONCE_ENTRIES).
        let skew = 300;
        let cap = 4;
        let mut cache = ReplayCache::new(cap);
        let now = 1_000_000_000;
        for i in 0..cap {
            let nonce = format!("n{i}");
            assert_eq!(
                cache.check_and_record("client", &nonce, now, now, skew),
                Ok(true),
                "fresh nonce {i} must be recorded"
            );
        }
        // Cap reached: a further distinct, in-window nonce fails closed.
        assert_eq!(
            cache.check_and_record("client", "overflow", now, now, skew),
            Err(()),
            "exceeding the cap must fail closed"
        );
        // A replay of an already-seen nonce is still detected (membership intact).
        assert_eq!(
            cache.check_and_record("client", "n0", now, now, skew),
            Ok(false),
            "replay must still be detected at the cap"
        );
        // Advancing `now` past the window evicts the lot, freeing capacity again.
        let later = now + skew + 1;
        assert_eq!(
            cache.check_and_record("client", "after-evict", later, later, skew),
            Ok(true),
            "eviction must free capacity once entries fall out of the window"
        );
    }

    #[test]
    fn reenroll_same_key_is_idempotent() {
        let s = scheme();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let c1 = enroll_with(&s, &key, &sk);
        // Re-enroll same client_id + same public key: idempotent, no bootstrap key needed.
        let c2 = s
            .enroll(EnrollmentRequest {
                api_key: "ignored-because-idempotent".into(),
                client_name: "dashboard-spa".into(),
                public_key: sk.verifying_key().to_bytes().to_vec(),
            })
            .expect("idempotent re-enroll");
        assert_eq!(c1.client_id, c2.client_id);
        assert_eq!(c1.fingerprint, c2.fingerprint);
    }

    #[test]
    fn reenroll_different_key_pin_mismatch() {
        // To force a client_id collision with a different key, we cannot rely on the
        // fingerprint==client_id derivation (different keys → different ids). So we
        // test the pin path directly by enrolling, then putting a record whose
        // public_key differs under the same id is not possible via the public API.
        // Instead, the realistic PinMismatch is exercised by storing a client and
        // re-enrolling with a key that hashes to the same id — infeasible. We
        // therefore validate the pin logic against a forged stored record.
        let store: Arc<dyn PersistenceProvider> =
            Arc::new(SqliteStore::in_memory().unwrap());
        let s = TofuClientAuth::new(store.clone()).unwrap();

        let sk_real = keypair();
        let fingerprint = sha256_hex(&sk_real.verifying_key().to_bytes());
        let client_id = fingerprint.clone();

        // Pin a DIFFERENT public key under this client_id directly in the store.
        let sk_other = keypair();
        let forged = StoredClient {
            client_id: client_id.clone(),
            public_key: hex_encode(&sk_other.verifying_key().to_bytes()),
            key_alg: "ed25519".into(),
            fingerprint: fingerprint.clone(),
            client_name: "pinned".into(),
            enrolled_at: Timestamp::now(),
        };
        store
            .put(
                CLIENTS,
                Record {
                    id: client_id.clone(),
                    doc: to_value(&forged).unwrap(),
                },
            )
            .unwrap();

        // Now enroll presenting sk_real, which derives the SAME client_id but a
        // different pinned key → PinMismatch.
        let key = s.issue_bootstrap_key().unwrap();
        let err = s
            .enroll(EnrollmentRequest {
                api_key: key,
                client_name: "dashboard-spa".into(),
                public_key: sk_real.verifying_key().to_bytes().to_vec(),
            })
            .unwrap_err();
        assert!(matches!(err, ClientAuthError::PinMismatch), "got {err:?}");
    }

    #[test]
    fn stored_client_has_no_secret_material() {
        let store: Arc<dyn PersistenceProvider> =
            Arc::new(SqliteStore::in_memory().unwrap());
        let s = TofuClientAuth::new(store.clone()).unwrap();
        let key = s.issue_bootstrap_key().unwrap();
        let sk = keypair();
        let cred = enroll_with(&s, &key, &sk);

        let rec = store.get(CLIENTS, &cred.client_id).unwrap();
        let obj = rec.doc.as_object().unwrap();
        let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();

        // Exactly the public fields, nothing else.
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![
                "client_id",
                "client_name",
                "enrolled_at",
                "fingerprint",
                "key_alg",
                "public_key"
            ]
        );

        // Defensively scan for any secret-ish field name or for the private key bytes.
        for k in &keys {
            let lk = k.to_lowercase();
            assert!(
                !lk.contains("secret")
                    && !lk.contains("private")
                    && !lk.contains("seed")
                    && lk != "signing_key",
                "stored client must not contain secret-ish field: {k}"
            );
        }
        // The private scalar must not appear anywhere in the serialized document.
        let serialized = serde_json::to_string(&rec.doc).unwrap();
        let secret_hex = hex_encode(sk.to_bytes().as_slice());
        assert!(
            !serialized.contains(&secret_hex),
            "serialized client leaked the private key"
        );
    }

    #[test]
    fn bootstrap_key_single_use_under_concurrency() {
        use std::thread;

        // One bootstrap key, many threads each presenting a DISTINCT public key.
        // Exactly one enrollment must succeed; the rest must see BadApiKey.
        let store: Arc<dyn PersistenceProvider> = Arc::new(SqliteStore::in_memory().unwrap());
        let scheme = Arc::new(TofuClientAuth::new(store).unwrap());
        let key = scheme.issue_bootstrap_key().unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let scheme = scheme.clone();
            let key = key.clone();
            handles.push(thread::spawn(move || {
                let sk = SigningKey::generate(&mut OsRng);
                scheme.enroll(EnrollmentRequest {
                    api_key: key,
                    client_name: "racer".into(),
                    public_key: sk.verifying_key().to_bytes().to_vec(),
                })
            }));
        }

        let mut successes = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(_) => successes += 1,
                Err(ClientAuthError::BadApiKey) => {}
                Err(other) => panic!("unexpected enroll error: {other:?}"),
            }
        }
        assert_eq!(successes, 1, "single-use bootstrap key authorized {successes} enrollments");
    }

    #[test]
    fn bootstrap_key_single_use_across_processes() {
        use std::sync::Barrier;
        use std::thread;

        // Simulate two separate PROCESSES sharing one on-disk WAL store: each opens
        // its OWN SqliteStore connection to the SAME file and wraps it in its OWN
        // TofuClientAuth (so there is NO shared `enroll_lock` — the only thing that
        // could serialize them is the store's atomic `put_if_absent`). Both try to
        // enroll DIFFERENT clients with the SAME bootstrap key concurrently; exactly
        // one must succeed and the other must get BadApiKey. This proves single-use
        // no longer depends on the in-process lock.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wyrtloom_tofu_xproc_{}_{:?}.db",
            std::process::id(),
            thread::current().id()
        ));
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);

        // Issue the key via a first connection, then drop it so the two racing
        // instances are wholly independent.
        let key = {
            let store: Arc<dyn PersistenceProvider> =
                Arc::new(SqliteStore::open(&path_str).unwrap());
            let issuer = TofuClientAuth::new(store).unwrap();
            issuer.issue_bootstrap_key().unwrap()
        };

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let key = key.clone();
                let path_str = path_str.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    // A wholly separate store connection + scheme instance ⇒ a
                    // separate `enroll_lock`. The shared on-disk file is the only
                    // common state.
                    let store: Arc<dyn PersistenceProvider> =
                        Arc::new(SqliteStore::open(&path_str).unwrap());
                    let scheme = TofuClientAuth::new(store).unwrap();
                    let sk = SigningKey::generate(&mut OsRng);
                    barrier.wait(); // maximise contention
                    scheme.enroll(EnrollmentRequest {
                        api_key: key,
                        client_name: "xproc".into(),
                        public_key: sk.verifying_key().to_bytes().to_vec(),
                    })
                })
            })
            .collect();

        let mut successes = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(_) => successes += 1,
                Err(ClientAuthError::BadApiKey) => {}
                Err(other) => panic!("unexpected enroll error: {other:?}"),
            }
        }
        assert_eq!(
            successes, 1,
            "cross-process single-use: {successes} enrollments authorized by one key"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path_str}-wal"));
        let _ = std::fs::remove_file(format!("{path_str}-shm"));
    }

    #[test]
    fn canonicalize_is_unambiguous() {
        // Moving a byte across a field boundary must change the output (length
        // prefixes prevent ("ab","c") colliding with ("a","bc")).
        let a = canonicalize("ab", "c", b"", "id", 1, "n");
        let b = canonicalize("a", "bc", b"", "id", 1, "n");
        assert_ne!(a, b);
        // Identical inputs → identical bytes (deterministic).
        assert_eq!(
            canonicalize("GET", "/x", b"\x01", "id", 7, "nn"),
            canonicalize("GET", "/x", b"\x01", "id", 7, "nn")
        );
    }
}

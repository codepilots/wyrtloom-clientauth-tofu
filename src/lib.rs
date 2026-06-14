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
//!    (hash + constant-time compare against an unconsumed record), marks it consumed,
//!    and **pins** the public key (TOFU). Only the public key + fingerprint are stored.
//! 3. Each subsequent request is verified by [`verify`](TofuClientAuth::verify): an
//!    ed25519 signature over the canonical request bytes, a bounded ±skew timestamp
//!    window, and a per-request nonce checked against a bounded, evicting replay cache.
//!
//! # Security
//!
//! - **Asymmetric only.** The store never holds a recoverable secret — only the
//!   client's public key and its SHA-256 fingerprint.
//! - **Bootstrap keys** are CSPRNG, ≥128-bit, single-use, stored hashed, and
//!   constant-time compared. A bad or already-consumed key yields [`ClientAuthError::BadApiKey`].
//! - **Canonicalization** ([`canonicalize`]) length-prefixes every field under a
//!   domain-separation tag so field-boundary confusion is impossible and clients and
//!   the server build identical signed bytes.
//! - **Replay protection** enforces a bounded ±skew window and evicts stale nonce
//!   entries on each `verify`, keeping the cache O(window·rate).

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
pub const DOMAIN_TAG: &[u8] = b"wyrtloom-client-auth-v1";

/// Collection holding pinned client identities.
const CLIENTS: &str = "clients";
/// Collection holding hashed, single-use bootstrap keys.
const BOOTSTRAP_KEYS: &str = "bootstrap_keys";

/// Default permitted clock skew (seconds) for the timestamp / replay window.
pub const DEFAULT_SKEW_SECS: i64 = 300;

/// Maximum accepted `client_name` length (chars).
const MAX_CLIENT_NAME_LEN: usize = 256;

/// Stored shape of a pinned client. Note: **no private/secret material** —
/// only the public key, its fingerprint, the validated name, and the time.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredClient {
    client_id: String,
    /// ed25519 public key, hex-encoded.
    public_key: String,
    /// SHA-256 hex of the raw public-key bytes (the TOFU pin / fingerprint).
    fingerprint: String,
    client_name: String,
    enrolled_at: Timestamp,
}

/// Stored shape of a bootstrap key: only the hash, plus single-use state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredBootstrapKey {
    /// SHA-256 hex of the plaintext bootstrap key.
    key_hash: String,
    consumed: bool,
    issued_at: Timestamp,
}

/// A recorded nonce sighting within the replay window.
#[derive(Debug, Clone)]
struct NonceEntry {
    client_id: String,
    nonce: String,
    timestamp: i64,
}

/// Trust-on-first-use client-authentication scheme over an injected store.
pub struct TofuClientAuth {
    store: Arc<dyn PersistenceProvider>,
    /// Serializes the read-modify-write of `enroll` (TOFU check-then-put and the
    /// single-use bootstrap-key get-then-consume). The `PersistenceProvider`
    /// contract offers no compare-and-set/transaction, so this lock — not the
    /// store — is what makes those sequences atomic and keeps a bootstrap key
    /// truly single-use under concurrent enrollment.
    enroll_lock: Mutex<()>,
    /// Bounded cache of recently seen `(client_id, nonce, timestamp)`; entries
    /// older than `now - skew_secs` are evicted on each `verify`.
    seen_nonces: Mutex<Vec<NonceEntry>>,
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
        Ok(Self {
            store,
            enroll_lock: Mutex::new(()),
            seen_nonces: Mutex::new(Vec::new()),
            skew_secs,
        })
    }

    /// Mint a single-use bootstrap key. A CSPRNG ≥128-bit token is generated; only
    /// its SHA-256 hash is persisted (`consumed: false`). The plaintext is returned
    /// **once** for the operator to distribute out of band — it is not recoverable.
    pub fn issue_bootstrap_key(&self) -> Result<String, ClientAuthError> {
        // 256 bits of CSPRNG entropy, well above the 128-bit floor.
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let plaintext = hex_encode(&raw);
        let key_hash = sha256_hex(plaintext.as_bytes());

        let record = StoredBootstrapKey {
            key_hash: key_hash.clone(),
            consumed: false,
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

    /// Validate a presented bootstrap key and atomically consume it. Returns the
    /// store id of the consumed record. A bad or already-consumed key → `BadApiKey`.
    fn consume_bootstrap_key(&self, presented: &str) -> Result<(), ClientAuthError> {
        let hash = sha256_hex(presented.as_bytes());
        // Look up by the hash id directly (it *is* the record id).
        let record = match self.store.get(BOOTSTRAP_KEYS, &hash) {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => return Err(ClientAuthError::BadApiKey),
            Err(e) => return Err(store_err(e)),
        };
        let stored: StoredBootstrapKey = from_value(record.doc)?;

        // Constant-time compare the stored hash against the recomputed hash. (The
        // id lookup already matched, but compare explicitly so the verification
        // path is uniform and resistant to any future change in lookup strategy.)
        let matches: bool = stored
            .key_hash
            .as_bytes()
            .ct_eq(hash.as_bytes())
            .into();
        if !matches || stored.consumed {
            return Err(ClientAuthError::BadApiKey);
        }

        let consumed = StoredBootstrapKey {
            consumed: true,
            ..stored
        };
        self.store
            .put(
                BOOTSTRAP_KEYS,
                Record {
                    id: hash,
                    doc: to_value(&consumed)?,
                },
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Current Unix-seconds time.
    fn now_unix() -> i64 {
        Timestamp::now().0.timestamp()
    }
}

/// Build the canonical, signed request bytes. **Every field is length-prefixed**
/// (4-byte big-endian length + bytes) under the [`DOMAIN_TAG`], so field-boundary
/// confusion is impossible and clients and the server derive identical bytes.
///
/// Layout: `DOMAIN_TAG || lp(method) || lp(path) || lp(body_sha256) || lp(client_id)
/// || lp(timestamp_ascii) || lp(nonce)`.
pub fn canonicalize(
    method: &str,
    path: &str,
    body_sha256: &[u8],
    client_id: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, DOMAIN_TAG);
    push_field(&mut out, method.as_bytes());
    push_field(&mut out, path.as_bytes());
    push_field(&mut out, body_sha256);
    push_field(&mut out, client_id.as_bytes());
    push_field(&mut out, timestamp.to_string().as_bytes());
    push_field(&mut out, nonce.as_bytes());
    out
}

/// Append `len(field) as u32 BE || field` to `buf`.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
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

        // 2. Validate the presented public key is a real ed25519 key before we burn
        //    the single-use bootstrap key, so a malformed key doesn't waste the token.
        let vk_bytes: [u8; 32] = req
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| ClientAuthError::Invalid("public_key must be 32 bytes".into()))?;
        VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|_| ClientAuthError::Invalid("public_key is not a valid ed25519 key".into()))?;

        // 3. Derive the deterministic fingerprint and client_id from the public key.
        let fingerprint = sha256_hex(&req.public_key);
        let client_id = fingerprint.clone();
        let public_key_hex = hex_encode(&req.public_key);

        // Serialize the rest of enroll: the TOFU check-then-put and the
        // single-use bootstrap-key get-then-consume are read-modify-write
        // sequences that the store cannot make atomic on its own. Holding this
        // lock for the remainder makes them atomic within the process, so a
        // bootstrap key cannot be consumed twice by concurrent enrollments.
        // (A disk-backed store shared across *processes* would still need a
        // store-level transaction; that is a limitation of the persistence
        // contract, not of this lock.)
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
        // 1. Look up the pinned client.
        let record = match self.store.get(CLIENTS, &presented.client_id) {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => return Err(ClientAuthError::UnknownClient),
            Err(e) => return Err(store_err(e)),
        };
        let stored: StoredClient = from_value(record.doc)?;

        // 2. Verify the ed25519 signature over the presented canonical request.
        let vk_bytes = hex_decode(&stored.public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| ClientAuthError::Storage("stored public key is corrupt".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|_| ClientAuthError::Storage("stored public key is corrupt".into()))?;

        let sig_bytes: [u8; 64] = presented
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ClientAuthError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&presented.canonical_request, &signature)
            .map_err(|_| ClientAuthError::BadSignature)?;

        // 3. Enforce the bounded ±skew timestamp window.
        let now = Self::now_unix();
        if (now - presented.timestamp).abs() > self.skew_secs {
            return Err(ClientAuthError::Replay);
        }

        // 4. Replay check + nonce recording, with eviction of stale entries.
        let cutoff = now - self.skew_secs;
        let mut cache = self
            .seen_nonces
            .lock()
            .map_err(|_| ClientAuthError::Storage("nonce cache poisoned".into()))?;
        // Evict entries older than the window so the cache stays bounded.
        cache.retain(|e| e.timestamp >= cutoff);
        if cache
            .iter()
            .any(|e| e.client_id == presented.client_id && e.nonce == presented.nonce)
        {
            return Err(ClientAuthError::Replay);
        }
        cache.push(NonceEntry {
            client_id: presented.client_id.clone(),
            nonce: presented.nonce.clone(),
            timestamp: presented.timestamp,
        });
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

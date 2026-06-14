# wyrtloom-clientauth-tofu

A trust-on-first-use (TOFU) [`ClientAuthScheme`] for the Wyrtloom dashboard
ecosystem, using **asymmetric (ed25519)** client keys over an injected
`Arc<dyn PersistenceProvider>` — so the backing store is swappable.

It authenticates the *client application* (web SPA, mobile app, CLI), which is
distinct from the human user.

## How it works

1. **Bootstrap.** An operator mints a single-use bootstrap key:

   ```rust
   let plaintext = scheme.issue_bootstrap_key()?; // returned ONCE
   ```

   Only the SHA-256 hash is stored. The operator distributes the plaintext out of
   band.

2. **Enroll (first contact).** The client presents the bootstrap key plus its
   ed25519 **public key**. The server validates the key (hash + constant-time
   compare against the issued record), then **atomically consumes it** via the
   persistence layer's compare-and-set so the key is single-use even across
   processes sharing the store, and **pins** the public key (TOFU). Only the public
   key and its SHA-256 fingerprint are stored — never a recoverable secret.

   ```rust
   let cred = scheme.enroll(EnrollmentRequest {
       api_key: plaintext,
       client_name: "dashboard-spa".into(),
       public_key: verifying_key.to_bytes().to_vec(),
   })?;
   ```

   Re-enrolling the same `client_id` with the same key is idempotent; with a
   different key it is rejected (`PinMismatch`).

3. **Verify (each request).** The client signs the canonical request bytes and
   presents the signature, timestamp, and a per-request nonce:

   ```rust
   let canonical = wyrtloom_clientauth_tofu::canonicalize(
       method, path, &body_sha256, &client_id, timestamp, &nonce,
   );
   let signature = signing_key.sign(&canonical);
   let identity = scheme.verify(&PresentedClientAuth { /* … */ })?;
   ```

   `verify` checks the signature, enforces a bounded ±skew timestamp window, and
   rejects replayed `(client_id, nonce)` pairs within that window.

## Signing requirements (every client must follow)

The public key's encoding selects the algorithm (no separate field):

| Key | Encoding (the bytes you enroll) | Signature |
|-----|---------------------------------|-----------|
| **ed25519** | 32-byte raw public key | 64-byte raw — no extra requirements (ed25519 is deterministic) |
| **ECDSA P-256** | 65-byte SEC1 **uncompressed** (`0x04 ‖ X ‖ Y`) | 64-byte raw `r‖s` (P1363), and **MUST be canonical low-s** |

> **P-256 low-s is mandatory.** ECDSA signatures are malleable — `(r, s)` and
> `(r, n−s)` both verify — so `verify` rejects high-s signatures (`s > n/2`) to
> keep the encoding canonical. Most ECDSA producers (including **WebCrypto
> `crypto.subtle.sign('ECDSA', …)`**) emit high-s ~50% of the time and do **not**
> normalize, so a client MUST normalize before sending: if `s > n/2`, replace `s`
> with `n − s` (leave `r` unchanged). Forgetting this yields intermittent ~50%
> `BadSignature` rejections. The reference browser client does this in
> `wyrtloom-dashboard-web/src/crypto/clientKey.ts` (`normalizeLowS`).

## Canonicalization

[`canonicalize`] (which delegates to `wyrtloom_core::client_auth::canonical_request`)
length-prefixes every field (**8-byte big-endian** length + bytes) under the
domain-separation tag `wyrtloom-client-auth-v1`, so clients and the API server
build byte-identical signed bytes and field-boundary confusion is impossible.

## Security

- Asymmetric only; the store holds only the public key + fingerprint.
- Single-use CSPRNG (≥128-bit) bootstrap keys, stored hashed, constant-time
  compared. Single-use is **cross-process atomic**: redemption is settled by the
  persistence layer's `put_if_absent` compare-and-set (an atomic consume marker),
  so instances sharing one store cannot double-redeem a key. The per-request replay
  cache remains process-local — run a single instance for cross-instance replay
  protection (see `SECURITY.md`).
- Length-prefixed, domain-separated canonicalization.
- Bounded ±skew replay window with nonce eviction (cache is O(window·rate),
  process-local).
- TOFU rejects key changes (`PinMismatch`).
- ed25519 and ECDSA P-256 supported; P-256 signatures must be canonical low-s
  (anti-malleability) — see "Signing requirements" above.

## License

Apache-2.0. See `LICENSE`.

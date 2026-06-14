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
   compare against an unconsumed record), marks it consumed, and **pins** the
   public key (TOFU). Only the public key and its SHA-256 fingerprint are stored —
   never a recoverable secret.

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

   `verify` checks the ed25519 signature, enforces a bounded ±skew timestamp
   window, and rejects replayed `(client_id, nonce)` pairs within that window.

## Canonicalization

[`canonicalize`] length-prefixes every field (4-byte big-endian length + bytes)
under the domain-separation tag `wyrtloom-client-auth-v1`, so clients and the API
server build identical signed bytes and field-boundary confusion is impossible.

## Security

- Asymmetric only; the store holds only the public key + fingerprint.
- Single-use CSPRNG (≥128-bit) bootstrap keys, stored hashed, constant-time
  compared.
- Length-prefixed, domain-separated canonicalization.
- Bounded ±skew replay window with nonce eviction (cache is O(window·rate)).
- TOFU rejects key changes (`PinMismatch`).

## License

Apache-2.0. See `LICENSE`.

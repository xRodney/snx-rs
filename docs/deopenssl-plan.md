# OpenSSL → RustCrypto migration plan (for an NDK-free Android build)

Goal: remove `openssl` from the dependency graph so the Android build needs no NDK-built C, and
so the Android-only Rust can be type-checked on a plain host. A TLS swap alone does **not** achieve
this — OpenSSL is pulled by three independent places:

1. `reqwest` + `tokio-native-tls` (gateway HTTPS + SSL tunnel) — the TLS stack.
2. `crates/snxcore/src/tunnel/ipsec/auth.rs` — `openssl::x509` for the client-cert common name.
3. **`crates/isakmp`** (now vendored) — the entire IKE/ESP crypto suite + cert handling.

OpenSSL only truly drops once **all three** are migrated. Status so far: isakmp is vendored
(`crates/isakmp`, path dep) so its crypto can be rewritten in-tree.

## Per-file OpenSSL inventory and RustCrypto mapping

### `crates/isakmp/src/crypto.rs` (central IKE crypto — ~1170 lines)

| OpenSSL use | Purpose | RustCrypto replacement |
|-------------|---------|------------------------|
| `hash::Hasher`, `sha::sha1` | MD5/SHA1/SHA2 | `md-5`, `sha1`, `sha2` via `digest::DynDigest` |
| `pkey::hmac` + `sign::Signer` | HMAC (PRF/integrity) | `hmac` crate, dispatched by digest |
| `symm::{Cipher,Crypter}` CBC | AES-{128,192,256}-CBC, 3DES-CBC, no pad | `cbc` + `aes` + `des`, `NoPadding` |
| `symm` GCM | AES-{128,192,256}-GCM AEAD | `aes-gcm` (`AesGcm<Aes192,U12>` for 192) |
| `dh::Dh` + `bn::BigNum` | MODP groups 2/14 | `num-bigint` `modpow` (gen private from `rand` bytes) |
| `ec`,`derive::Deriver` | ECDH P-256/384/521 | `p256`,`p384`,`p521` (`ecdh` feature) |
| `rsa::Padding` + `public_decrypt` | IKEv1 raw RSA verify | `rsa` `Pkcs1v15Sign::new_unprefixed()` |
| `sign::Verifier` + X509 pubkey | IKEv2 RSA verify (w/ DigestInfo) | `rsa` `Pkcs1v15Sign::new::<D>()` |
| `x509::X509::public_key` | pubkey from cert DER | `x509-parser` → `PublicKey::RSA` → `rsa::RsaPublicKey::new` |

Verification: `crypto.rs` has known-answer tests (`prf_plus`, cipher round-trips). `cargo test
-p isakmp` must stay green. The `From<DigestType> for MessageDigest` / `From<CipherType> for
Cipher` impls are internal-only (confirmed) and get deleted.

### `crates/isakmp/src/esp.rs` (ESP data path — ~732 lines)

Uses `symm::{Cipher,Crypter,Mode}` directly for AES-CBC / AES-GCM and `openssl::memcmp::eq` for the
HMAC compare. Map to the same `cbc`/`aes`/`aes-gcm` helpers (factor them out of `crypto.rs` into a
small internal `sym` module shared by both) and `subtle::ConstantTimeEq` for the compare. **Coupling
note:** `esp.rs` obtains its cipher via `CipherType::into()`; porting `crypto.rs` and `esp.rs` must
land together or the `From` removal breaks the build.

### `crates/isakmp/src/certs.rs` (client certificate handling — ~645 lines)

The hardest file. Uses OpenSSL for:
- **PKCS#12** load (`.p12` client identity) → pure-Rust `p12-keystore` or `pkcs12` + `pkcs8`/`pkcs1`.
- **PKCS#11** token signing via `cryptoki` (HSM) — *decision:* **drop on Android** behind a cfg/feature;
  keep on desktop. Mobile has no PKCS#11 driver model.
- SHA-1 cert fingerprint (`c.digest`) → `sha1`.
- Windows cert store (`windows-sys`) — already `cfg(windows)`, unaffected by Android.

`ClientCertificate` is a trait with `certs()` + a sign/pad operation; the pure-Rust impl needs an
RSA/EC private key signer (`rsa` `SigningKey`, `p256::ecdsa`).

### `crates/isakmp/src/ikev2/{codec,session,service}.rs`

Only `openssl::memcmp::eq` in non-test code → `subtle`. The remaining matches are in `#[cfg(test)]`
(self-signed cert generation with `openssl::x509::X509Builder`, verifier checks) → either port tests
to `rcgen` + RustCrypto, or gate those tests out on the pure-Rust build.

### `crates/snxcore/src/tunnel/ipsec/auth.rs`

`X509::from_der(...).subject_name()` CN lookup → `x509-parser` `iter_common_name()`.

### `crates/snxcore/src/tunnel/ssl.rs`

`tokio-native-tls` → `tokio-rustls`. Build a `rustls::ClientConfig`: protocol-version cap
(`TlsVersion::Tls12` ⇒ TLS1.2 only), roots via `rustls-native-certs` (reads Android's
`/system/etc/security/cacerts` without JNI) + user `ca_cert`, and a dangerous no-verify verifier for
`ignore_server_cert`. SNI from `server_name` (DnsName or IpAddress).

### `crates/snxcore/src/tunnel/gateway.rs` (reqwest)

Switch `reqwest` features `["native-tls"]` → `["rustls-tls-native-roots"]`. **Wrinkle:**
`Identity::from_pkcs12_der` is native-tls-only; the mutual-TLS CCC auth uses it. Under rustls, parse
the PKCS#12 in-code (same helper as `certs.rs`) and build the identity from PEM
(`Identity::from_pem`). `from_pkcs8_pem` already works on rustls.

### `crates/snxcore/src/platform/linux.rs`

`openssl::provider::Provider` (PKCS#11 legacy provider) is Linux-only (`cfg(target_os="linux")`) and
can stay OpenSSL — it is never compiled for Android.

## Cross-cutting notes

- **RNG version skew:** isakmp uses `rand 0.10`; the EC crates want `rand_core 0.6`. For MODP,
  generate the private exponent from `rand 0.10` bytes (no `num-bigint`/rand feature). For ECDH, add
  `rand_core = { version = "0.6", features = ["getrandom"] }` and use its `OsRng`.
- **Constant-time:** `num-bigint` `modpow` is not constant-time. Acceptable for a first correct port
  (documented); revisit with `crypto-bigint` `BoxedMontyForm` if side-channel hardening is required.
- **Feature gating:** put PKCS#11 behind a `pkcs11` feature (default on desktop, off for Android) so
  `cryptoki` leaves the Android graph too.

## Staging (each stage keeps the tree building; OpenSSL drops only at the end)

1. ✅ Vendor isakmp as a path dep.
2. `crypto.rs` + `esp.rs` → RustCrypto (land together; verify `cargo test -p isakmp`).
3. `certs.rs` → pure-Rust PKCS#12 + signer; `pkcs11` feature-gated; port/gate the cert tests.
4. snxcore `auth.rs` (x509-parser), `ssl.rs` (tokio-rustls), `gateway.rs` (reqwest rustls + in-code
   PKCS#12). Remove `openssl`/`tokio-native-tls` from snxcore (keep Linux provider cfg).
5. Drop `openssl` from `crates/isakmp/Cargo.toml`. Build the Android target end-to-end with
   `cargo-ndk` (now NDK-free for crypto) and type-check the Android platform module.

## Progress (this branch)

- ✅ isakmp vendored at `crates/isakmp`.
- ✅ `crypto.rs`, `esp.rs`, `ikev2/*`, `certs.rs` ported to RustCrypto. **The isakmp library is
  OpenSSL-free** (`cargo tree -p isakmp -e normal -i openssl` is empty); OpenSSL is a dev-dependency
  only, for test-cert generation. `cargo test -p isakmp` green (174 tests).
- ✅ snxcore `auth.rs` X.509 → x509-parser.
- ⬜ snxcore `ssl.rs` (tokio-rustls), `gateway.rs` (reqwest rustls + PKCS#12→PEM identity).
- ⬜ Scope the `openssl` crate to `cfg(target_os = "linux")` (only `platform/linux.rs` uses it) and
  drop the Windows/macOS/Android vendored-openssl deps once the TLS swap lands.

## Correction: "NDK-free" was wrong

An earlier note claimed the swap would make the Android build need no NDK. That is not achievable:

- rustls needs a crypto provider — `ring` or `aws-lc-rs` — **both of which compile C/asm** and need a
  C cross-compiler for Android. (`ring` is the Android-friendly choice via `cargo-ndk`.)
- `rusqlite` with `bundled` compiles SQLite (C) too.

So the realistic, still-worthwhile goal is **OpenSSL-free**, not C-free: `ring` + SQLite cross-compile
cleanly with `cargo-ndk`, whereas vendored OpenSSL is the finicky one. The IKE/ESP crypto (isakmp) is
genuinely pure-Rust now, which was the hardest part. The Android build will still use `cargo-ndk`.

Provider choice for the snxcore TLS swap: pin **rustls + ring** (not aws-lc-rs) for the smoothest
Android cross-compile.

## Verification reality

Unit tests (isakmp known-answer + round-trip) and host compilation are the only checks available
here. **IKE/ESP interop against a real Check Point gateway is required before trusting this** — the
wire-level crypto (DH group encoding, RSA AUTH payloads, ESP framing) must be confirmed against the
live protocol, which cannot be done in this environment.

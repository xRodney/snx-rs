use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use digest::DynDigest;
use num_bigint::BigUint;
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Sign};
use serde::{Deserialize, Serialize};

use crate::ikev1::model::{IkeEncryptionAlgorithm, TransformId};

/// Expand a GCM operation over the (key size, tag size) matrix. `$run` is a
/// local macro, defined at the call site over the function's key/nonce/data/aad,
/// taking an AES block type and a tag-size type and yielding a `Vec<u8>`.
macro_rules! gcm_match {
    ($cipher:expr, $run:ident) => {{
        use aes_gcm::aead::consts::{U12, U16};
        // The RustCrypto `aes-gcm` crate floors TagSize at 12 octets (short GCM tags are weak), so
        // ENCR_AES_GCM_8 (IcvLength::Eight) is not expressible here and is rejected. It is a rarely
        // negotiated transform; supporting it would need a manual GHASH. See docs/deopenssl-plan.md.
        match $cipher {
            CipherType::Aes128Gcm(IcvLength::Twelve) => $run!(aes::Aes128, U12),
            CipherType::Aes128Gcm(IcvLength::Sixteen) => $run!(aes::Aes128, U16),
            CipherType::Aes192Gcm(IcvLength::Twelve) => $run!(aes::Aes192, U12),
            CipherType::Aes192Gcm(IcvLength::Sixteen) => $run!(aes::Aes192, U16),
            CipherType::Aes256Gcm(IcvLength::Twelve) => $run!(aes::Aes256, U12),
            CipherType::Aes256Gcm(IcvLength::Sixteen) => $run!(aes::Aes256, U16),
            CipherType::Aes128Gcm(IcvLength::Eight)
            | CipherType::Aes192Gcm(IcvLength::Eight)
            | CipherType::Aes256Gcm(IcvLength::Eight) => {
                return Err(anyhow!(
                    "AES-GCM-8 (8-octet ICV) is not supported by the RustCrypto backend"
                ));
            }
            other => return Err(anyhow!("Cipher {:?} is not an AEAD cipher", other)),
        }
    }};
}

// RFC2409: Oakley group 2
const G2_P: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209,
    41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25,
    179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98,
    94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137,
    159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255, 255, 255,
    255, 255,
];

const G14_P: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209,
    41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25,
    179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98,
    94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137,
    159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 228, 91, 61, 194, 0, 124, 184, 161, 99, 191, 5,
    152, 218, 72, 54, 28, 85, 211, 154, 105, 22, 63, 168, 253, 36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28,
    98, 243, 86, 32, 133, 82, 187, 158, 213, 41, 7, 112, 150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116,
    108, 8, 202, 24, 33, 124, 50, 144, 94, 70, 46, 54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39, 131, 162,
    236, 7, 162, 143, 181, 197, 93, 240, 111, 76, 82, 201, 222, 43, 203, 246, 149, 88, 23, 24, 57, 149, 73, 124, 234,
    149, 106, 229, 21, 210, 38, 24, 152, 250, 5, 16, 21, 114, 142, 90, 138, 172, 170, 104, 255, 255, 255, 255, 255,
    255, 255, 255,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DigestType {
    Md5,  // Cryptographically broken
    Sha1, // Deprecated for signatures
    Sha256,
    Sha384,
    Sha512,
}

impl DigestType {
    pub fn is_deprecated(&self) -> bool {
        matches!(self, DigestType::Md5 | DigestType::Sha1)
    }

    /// Full (untruncated) output length in bytes.
    pub fn hash_len(&self) -> usize {
        match self {
            DigestType::Md5 => 16,
            DigestType::Sha1 => 20,
            DigestType::Sha256 => 32,
            DigestType::Sha384 => 48,
            DigestType::Sha512 => 64,
        }
    }

    /// Truncated checksum length used by the IKEv2 integrity transforms:
    /// HMAC-MD5-96 / HMAC-SHA1-96 (RFC 2404) and the RFC 4868 SHA-2 variants,
    /// which truncate to half the digest size.
    pub fn integrity_len(&self) -> usize {
        match self {
            DigestType::Md5 | DigestType::Sha1 => 12,
            DigestType::Sha256 => 16,
            DigestType::Sha384 => 24,
            DigestType::Sha512 => 32,
        }
    }

    fn new_hasher(&self) -> Box<dyn DynDigest> {
        match self {
            DigestType::Md5 => Box::new(md5::Md5::default()),
            DigestType::Sha1 => Box::new(sha1::Sha1::default()),
            DigestType::Sha256 => Box::new(sha2::Sha256::default()),
            DigestType::Sha384 => Box::new(sha2::Sha384::default()),
            DigestType::Sha512 => Box::new(sha2::Sha512::default()),
        }
    }

    fn pkcs1v15(&self) -> Pkcs1v15Sign {
        match self {
            DigestType::Md5 => Pkcs1v15Sign::new::<md5::Md5>(),
            DigestType::Sha1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
            DigestType::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
            DigestType::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
            DigestType::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        }
    }

    /// The DER `DigestInfo` that RSASSA-PKCS1-v1_5 signs (RFC 8017 §9.2): an
    /// ASN.1 prefix naming the hash algorithm, followed by the hash itself.
    ///
    /// IKEv2 AUTH method 1 signs this, where IKEv1 signs the bare hash — the
    /// difference [`Crypto::verify_rsa_signature`] exists for, seen from the
    /// signing side. It is built here rather than by a signer because a
    /// [`crate::certs::ClientCertificate`] may hold its private key in a token
    /// or in the Windows store, and can only PKCS#1-pad and encrypt whatever it
    /// is handed.
    pub fn digest_info(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let prefix: &[u8] = match self {
            DigestType::Md5 => &[
                0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04,
                0x10,
            ],
            DigestType::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
            ],
            DigestType::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
                0x04, 0x20,
            ],
            DigestType::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
                0x04, 0x30,
            ],
            DigestType::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
                0x04, 0x40,
            ],
        };

        let mut hasher = self.new_hasher();
        hasher.update(data);
        let hash = hasher.finalize();

        let mut buf = BytesMut::with_capacity(prefix.len() + hash.len());
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(&hash);

        Ok(buf.freeze())
    }
}

/// One-shot hash of the concatenated chunks.
pub(crate) fn hash_chunks<I, R>(digest: DigestType, data: I) -> Vec<u8>
where
    I: IntoIterator<Item = R>,
    R: AsRef<[u8]>,
{
    let mut hasher = digest.new_hasher();
    for d in data {
        hasher.update(d.as_ref());
    }
    hasher.finalize().to_vec()
}

/// HMAC over the concatenated chunks, dispatched by digest.
pub(crate) fn hmac_chunks<I, R>(digest: DigestType, key: &[u8], data: I) -> Vec<u8>
where
    I: IntoIterator<Item = R>,
    R: AsRef<[u8]>,
{
    use hmac::Mac;

    macro_rules! run {
        ($hash:ty) => {{
            let mut mac = <hmac::Hmac<$hash>>::new_from_slice(key).expect("HMAC accepts keys of any length");
            for d in data {
                Mac::update(&mut mac, d.as_ref());
            }
            mac.finalize().into_bytes().to_vec()
        }};
    }

    match digest {
        DigestType::Md5 => run!(md5::Md5),
        DigestType::Sha1 => run!(sha1::Sha1),
        DigestType::Sha256 => run!(sha2::Sha256),
        DigestType::Sha384 => run!(sha2::Sha384),
        DigestType::Sha512 => run!(sha2::Sha512),
    }
}

/// Constant-time equality, replacing `openssl::memcmp::eq`. Differing lengths are public, so the
/// short-circuit on length is not a leak.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

/// Length of the AES-GCM authentication tag, which IKEv2 negotiates as three
/// distinct ENCR transforms: ENCR_AES_GCM_8/12/16 (RFC 5282).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IcvLength {
    Eight,
    Twelve,
    Sixteen,
}

impl IcvLength {
    pub fn size(&self) -> usize {
        match self {
            IcvLength::Eight => 8,
            IcvLength::Twelve => 12,
            IcvLength::Sixteen => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CipherType {
    Aes128Cbc,
    Aes192Cbc,
    #[default]
    Aes256Cbc,
    DesEde3Cbc,
    Aes128Gcm(IcvLength),
    Aes192Gcm(IcvLength),
    Aes256Gcm(IcvLength),
}

impl CipherType {
    pub fn new_for_ike(enc_alg: IkeEncryptionAlgorithm, key_len: usize) -> anyhow::Result<Self> {
        match enc_alg {
            IkeEncryptionAlgorithm::AesCbc => match key_len {
                16 => Ok(Self::Aes128Cbc),
                24 => Ok(Self::Aes192Cbc),
                32 => Ok(Self::Aes256Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            IkeEncryptionAlgorithm::DesEde3Cbc => match key_len {
                24 => Ok(Self::DesEde3Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            _ => Err(anyhow!("Unsupported encryption algorithm: {:?}", enc_alg)),
        }
    }

    /// IKEv2 transform type 1 (ENCR) transform IDs, RFC 7296 §3.3.2.
    pub fn new_for_ikev2(transform_id: u16, key_len: usize) -> anyhow::Result<Self> {
        fn by_key_len<T>(key_len: usize, k128: T, k192: T, k256: T) -> anyhow::Result<T> {
            match key_len {
                16 => Ok(k128),
                24 => Ok(k192),
                32 => Ok(k256),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            }
        }

        match transform_id {
            // ENCR_3DES
            3 => match key_len {
                24 => Ok(Self::DesEde3Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            // ENCR_AES_CBC
            12 => by_key_len(key_len, Self::Aes128Cbc, Self::Aes192Cbc, Self::Aes256Cbc),
            // ENCR_AES_GCM_8 / _12 / _16
            18..=20 => {
                let icv = match transform_id {
                    18 => IcvLength::Eight,
                    19 => IcvLength::Twelve,
                    _ => IcvLength::Sixteen,
                };
                by_key_len(
                    key_len,
                    Self::Aes128Gcm(icv),
                    Self::Aes192Gcm(icv),
                    Self::Aes256Gcm(icv),
                )
            }
            other => Err(anyhow!("Unsupported IKEv2 encryption transform: {}", other)),
        }
    }

    pub fn new_for_esp(transform_id: TransformId, key_len: usize) -> anyhow::Result<Self> {
        match transform_id {
            TransformId::EspAesCbc => match key_len {
                16 => Ok(Self::Aes128Cbc),
                24 => Ok(Self::Aes192Cbc),
                32 => Ok(Self::Aes256Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            TransformId::Esp3Des => Ok(Self::DesEde3Cbc),
            _ => Err(anyhow!("Unsupported transform id: {:?}", transform_id)),
        }
    }

    /// Whether this cipher authenticates its own output, in which case the
    /// negotiated integrity transform is NONE and `encrypt_aead`/`decrypt_aead`
    /// must be used instead of `encrypt`/`decrypt`.
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::Aes128Gcm(_) | Self::Aes192Gcm(_) | Self::Aes256Gcm(_))
    }

    /// Length of the authentication tag appended to the ciphertext, 0 for
    /// non-AEAD ciphers.
    pub fn icv_len(&self) -> usize {
        match self {
            Self::Aes128Gcm(icv) | Self::Aes192Gcm(icv) | Self::Aes256Gcm(icv) => icv.size(),
            _ => 0,
        }
    }

    /// Length of the implicit salt carried in the keying material but not on
    /// the wire (RFC 5282 §4), 0 for non-AEAD ciphers.
    pub fn salt_len(&self) -> usize {
        if self.is_aead() { 4 } else { 0 }
    }

    /// Cipher block size in bytes.
    fn cbc_block_size(&self) -> usize {
        match self {
            Self::DesEde3Cbc => 8,
            _ => 16,
        }
    }

    /// Length of the explicit IV carried in the message.
    pub fn iv_len(&self) -> usize {
        if self.is_aead() { 8 } else { self.cbc_block_size() }
    }

    /// Full nonce length expected by `encrypt_aead`/`decrypt_aead`: salt || IV.
    pub fn nonce_len(&self) -> usize {
        self.salt_len() + self.iv_len()
    }

    /// Length of the key proper, excluding any salt.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes128Gcm(_) => 16,
            Self::Aes192Cbc | Self::Aes192Gcm(_) | Self::DesEde3Cbc => 24,
            Self::Aes256Cbc | Self::Aes256Gcm(_) => 32,
        }
    }

    /// Number of octets of keying material to draw for this cipher: key || salt.
    pub fn key_material_len(&self) -> usize {
        self.key_len() + self.salt_len()
    }

    /// Plaintext padding boundary. GCM is a stream mode, so RFC 7296 §3.14
    /// only requires 4-octet alignment there.
    pub fn block_size(&self) -> usize {
        if self.is_aead() { 4 } else { self.cbc_block_size() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GroupType {
    Oakley2,
    Oakley14,
    EcP256,
    EcP384,
    EcP521,
}

impl GroupType {
    /// IKE Diffie-Hellman group number (IKEv1 group description / IKEv2
    /// transform type 4 ID).
    pub fn group_id(&self) -> u16 {
        match self {
            GroupType::Oakley2 => 2,
            GroupType::Oakley14 => 14,
            GroupType::EcP256 => 19,
            GroupType::EcP384 => 20,
            GroupType::EcP521 => 21,
        }
    }

    pub fn from_group_id(group_id: u16) -> anyhow::Result<Self> {
        match group_id {
            2 => Ok(GroupType::Oakley2),
            14 => Ok(GroupType::Oakley14),
            19 => Ok(GroupType::EcP256),
            20 => Ok(GroupType::EcP384),
            21 => Ok(GroupType::EcP521),
            other => Err(anyhow!("Unsupported Diffie-Hellman group: {}", other)),
        }
    }

    pub fn is_ecp(&self) -> bool {
        matches!(self, GroupType::EcP256 | GroupType::EcP384 | GroupType::EcP521)
    }

    /// Size of the KE payload data: the modulus length for MODP groups, or the
    /// concatenated x || y coordinates for ECP groups (RFC 5903 §7).
    pub fn public_key_len(&self) -> usize {
        match self {
            GroupType::Oakley2 => 128,
            GroupType::Oakley14 => 256,
            _ => 2 * self.field_len(),
        }
    }

    /// Size of the derived shared secret: the modulus length for MODP groups,
    /// or the single x coordinate for ECP groups.
    pub fn shared_secret_len(&self) -> usize {
        match self {
            GroupType::Oakley2 => 128,
            GroupType::Oakley14 => 256,
            _ => self.field_len(),
        }
    }

    /// Coordinate size in bytes for ECP groups.
    fn field_len(&self) -> usize {
        match self {
            GroupType::EcP256 => 32,
            GroupType::EcP384 => 48,
            GroupType::EcP521 => 66,
            _ => 0,
        }
    }

    fn modp_prime(&self) -> Option<&'static [u8]> {
        match self {
            GroupType::Oakley2 => Some(G2_P),
            GroupType::Oakley14 => Some(G14_P),
            _ => None,
        }
    }
}

/// Finite-field (MODP) key agreement state: a fixed prime/generator and our
/// ephemeral private exponent, with the public value `g^x mod p` precomputed.
struct ModpKex {
    p: BigUint,
    x: BigUint,
    public: BigUint,
}

impl ModpKex {
    fn generate(prime: &[u8]) -> anyhow::Result<Self> {
        let p = BigUint::from_bytes_be(prime);
        let g = BigUint::from(2u32);

        // Private exponent in [2, p-2]. Drawn from fresh OS randomness the same
        // width as the modulus, then reduced into range.
        let mut buf = vec![0u8; prime.len()];
        rand::fill(&mut buf[..]);
        let modulus = &p - BigUint::from(4u32);
        let x = BigUint::from_bytes_be(&buf) % modulus + BigUint::from(2u32);

        let public = g.modpow(&x, &p);
        Ok(Self { p, x, public })
    }
}

/// Elliptic-curve key agreement state. Each curve is a distinct RustCrypto type,
/// so they cannot share a field.
enum EcKex {
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
    P521(p521::ecdh::EphemeralSecret),
}

/// Ephemeral key agreement state, either finite-field (MODP) or elliptic curve.
enum KeyExchange {
    Modp(ModpKex),
    Ecp(EcKex),
}

impl KeyExchange {
    fn generate(group: GroupType) -> anyhow::Result<Self> {
        match group {
            GroupType::EcP256 => Ok(KeyExchange::Ecp(EcKex::P256(p256::ecdh::EphemeralSecret::random(
                &mut rand_core::OsRng,
            )))),
            GroupType::EcP384 => Ok(KeyExchange::Ecp(EcKex::P384(p384::ecdh::EphemeralSecret::random(
                &mut rand_core::OsRng,
            )))),
            GroupType::EcP521 => Ok(KeyExchange::Ecp(EcKex::P521(p521::ecdh::EphemeralSecret::random(
                &mut rand_core::OsRng,
            )))),
            GroupType::Oakley2 | GroupType::Oakley14 => {
                let prime = group.modp_prime().context("No MODP prime for group")?;
                Ok(KeyExchange::Modp(ModpKex::generate(prime)?))
            }
        }
    }
}

/// Left-pad `data` with zeroes to exactly `len` octets. IKE carries both the
/// KE payload and the shared secret as fixed-width big-endian integers, but a
/// big integer renders without leading zeroes.
fn left_pad(data: &[u8], len: usize) -> anyhow::Result<Bytes> {
    if data.len() > len {
        return Err(anyhow!("Value of {} bytes exceeds the expected {}", data.len(), len));
    }
    let mut out = BytesMut::zeroed(len - data.len());
    out.extend_from_slice(data);
    Ok(out.freeze())
}

pub struct Crypto {
    kex: KeyExchange,
    digest_type: DigestType,
    prf_type: DigestType,
    cipher_type: CipherType,
    group_type: GroupType,
}

impl Crypto {
    /// IKEv1 parameters, where a single negotiated hash algorithm serves as
    /// PRF, integrity function and hash.
    pub fn with_parameters(digest: DigestType, cipher: CipherType, group: GroupType) -> anyhow::Result<Self> {
        Ok(Self {
            kex: KeyExchange::generate(group)?,
            digest_type: digest,
            prf_type: digest,
            cipher_type: cipher,
            group_type: group,
        })
    }

    /// Override the PRF, which IKEv2 negotiates as a transform of its own,
    /// independently of the integrity algorithm (RFC 7296 §3.3.2).
    pub fn with_prf(mut self, prf: DigestType) -> Self {
        self.set_prf(prf);
        self
    }

    pub fn set_prf(&mut self, prf: DigestType) {
        self.prf_type = prf;
    }

    /// Override the integrity/hash digest, keeping the key exchange.
    ///
    /// IKEv2 sends KEi before the responder has chosen the transforms, so the
    /// negotiated algorithms are applied to an existing key pair rather than
    /// through [`Crypto::with_parameters`], which would generate a new one and
    /// invalidate the KE payload already on the wire.
    pub fn set_digest(&mut self, digest: DigestType) {
        self.digest_type = digest;
    }

    /// Override the cipher, keeping the key exchange. See [`Crypto::set_digest`].
    pub fn set_cipher(&mut self, cipher: CipherType) {
        self.cipher_type = cipher;
    }

    pub fn public_key(&self) -> anyhow::Result<Bytes> {
        match &self.kex {
            KeyExchange::Modp(modp) => left_pad(&modp.public.to_bytes_be(), self.group_type.public_key_len()),
            KeyExchange::Ecp(ec) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                // Strip the 0x04 uncompressed-point marker: IKE carries x || y.
                let bytes = match ec {
                    EcKex::P256(s) => s.public_key().to_encoded_point(false).as_bytes().to_vec(),
                    EcKex::P384(s) => s.public_key().to_encoded_point(false).as_bytes().to_vec(),
                    EcKex::P521(s) => s.public_key().to_encoded_point(false).as_bytes().to_vec(),
                };
                Ok(Bytes::copy_from_slice(
                    bytes.get(1..).context("Malformed EC public key")?,
                ))
            }
        }
    }

    pub fn shared_secret(&self, public_key: &[u8]) -> anyhow::Result<Bytes> {
        match &self.kex {
            KeyExchange::Modp(modp) => {
                let peer = BigUint::from_bytes_be(public_key);
                let one = BigUint::from(1u32);
                let limit = &modp.p - &one;

                // 1 < peer < p - 1, otherwise the shared secret is degenerate
                if peer <= one || peer >= limit {
                    return Err(anyhow!("Peer public key is out of range"));
                }

                left_pad(
                    &peer.modpow(&modp.x, &modp.p).to_bytes_be(),
                    self.group_type.shared_secret_len(),
                )
            }
            KeyExchange::Ecp(ec) => {
                let expected = self.group_type.public_key_len();
                if public_key.len() != expected {
                    return Err(anyhow!(
                        "Peer public key is {} bytes, expected {}",
                        public_key.len(),
                        expected
                    ));
                }

                // Re-attach the SEC1 uncompressed-point marker the wire format drops.
                let mut sec1 = Vec::with_capacity(1 + public_key.len());
                sec1.push(0x04);
                sec1.extend_from_slice(public_key);

                ecdh_shared(ec, &sec1)
            }
        }
    }

    pub fn prf<I, R>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        Ok(hmac_chunks(self.prf_type, key, data).into())
    }

    /// `prf+` key expansion, RFC 7296 §2.13:
    ///
    /// ```text
    /// prf+(K,S) = T1 | T2 | T3 | ...
    /// T1 = prf(K, S | 0x01)
    /// Tn = prf(K, T(n-1) | S | n)
    /// ```
    pub fn prf_plus(&self, key: &[u8], seed: &[u8], out_len: usize) -> anyhow::Result<Bytes> {
        let mut out = BytesMut::with_capacity(out_len);
        let mut block = Bytes::new();
        let mut counter = 0u8;

        while out.len() < out_len {
            counter = counter
                .checked_add(1)
                .context("prf+ cannot produce more than 255 blocks")?;

            block = self.prf(key, [block.as_ref(), seed, &[counter][..]])?;
            out.extend_from_slice(&block);
        }

        out.truncate(out_len);
        Ok(out.freeze())
    }

    /// Integrity checksum truncated per the negotiated integrity transform.
    pub fn integrity<I, R>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        let mut mac: Bytes = hmac_chunks(self.digest_type, key, data).into();
        mac.truncate(self.digest_type.integrity_len());
        Ok(mac)
    }

    pub fn hash<I, R>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        Ok(hash_chunks(self.digest_type, data).into())
    }

    pub fn encrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        if self.cipher_type.is_aead() {
            return Err(anyhow!("Cipher {:?} is AEAD, use encrypt_aead", self.cipher_type));
        }
        Ok(cbc_encrypt(self.cipher_type, key, data, iv)?.into())
    }

    pub fn decrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        if self.cipher_type.is_aead() {
            return Err(anyhow!("Cipher {:?} is AEAD, use decrypt_aead", self.cipher_type));
        }
        Ok(cbc_decrypt(self.cipher_type, key, data, iv)?.into())
    }

    /// AEAD encryption. `nonce` is the full salt || IV value; `aad` is the
    /// associated data authenticated but not encrypted. Returns
    /// `ciphertext || ICV`.
    pub fn encrypt_aead(&self, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> anyhow::Result<Bytes> {
        self.check_aead(key, nonce)?;
        Ok(gcm_encrypt(self.cipher_type, key, data, nonce, aad)?.into())
    }

    /// AEAD decryption. `data` is `ciphertext || ICV`; fails if the ICV does
    /// not authenticate both the ciphertext and `aad`.
    pub fn decrypt_aead(&self, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> anyhow::Result<Bytes> {
        self.check_aead(key, nonce)?;

        let icv_len = self.cipher_type.icv_len();
        if data.len() < icv_len {
            return Err(anyhow!("AEAD ciphertext is shorter than its ICV"));
        }

        Ok(gcm_decrypt(self.cipher_type, key, data, nonce, aad)?.into())
    }

    fn check_aead(&self, key: &[u8], nonce: &[u8]) -> anyhow::Result<()> {
        if !self.cipher_type.is_aead() {
            return Err(anyhow!("Cipher {:?} is not AEAD", self.cipher_type));
        }
        if key.len() != self.cipher_type.key_len() {
            return Err(anyhow!(
                "AEAD key is {} bytes, expected {}",
                key.len(),
                self.cipher_type.key_len()
            ));
        }
        if nonce.len() != self.cipher_type.nonce_len() {
            return Err(anyhow!(
                "AEAD nonce is {} bytes, expected {}",
                nonce.len(),
                self.cipher_type.nonce_len()
            ));
        }
        Ok(())
    }

    pub fn block_size(&self) -> usize {
        self.cipher_type.block_size()
    }

    pub fn key_len(&self) -> usize {
        self.cipher_type.key_len()
    }

    /// Keying material to draw for the cipher: key || salt.
    pub fn key_material_len(&self) -> usize {
        self.cipher_type.key_material_len()
    }

    pub fn salt_len(&self) -> usize {
        self.cipher_type.salt_len()
    }

    pub fn iv_len(&self) -> usize {
        self.cipher_type.iv_len()
    }

    pub fn icv_len(&self) -> usize {
        self.cipher_type.icv_len()
    }

    pub fn is_aead(&self) -> bool {
        self.cipher_type.is_aead()
    }

    pub fn hash_len(&self) -> usize {
        self.digest_type.hash_len()
    }

    pub fn prf_len(&self) -> usize {
        self.prf_type.hash_len()
    }

    pub fn integrity_len(&self) -> usize {
        self.digest_type.integrity_len()
    }

    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    pub fn prf_type(&self) -> DigestType {
        self.prf_type
    }

    pub fn cipher_type(&self) -> CipherType {
        self.cipher_type
    }

    pub fn group_type(&self) -> GroupType {
        self.group_type
    }

    /// Verifies an IKEv2 AUTH payload of method 1 (RSA Digital Signature):
    /// RSASSA-PKCS1-v1_5 over the signed octets, *with* the DigestInfo prefix
    /// that IKEv1's raw construction in [`Crypto::verify_signature`] omits.
    ///
    /// RFC 7296 §3.8 only says implementations SHOULD support SHA-1 here, so
    /// the caller passes the hash to try; there is nothing on the wire that
    /// names it (that is what RFC 7427 method 14 added).
    pub fn verify_rsa_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        cert: &[u8],
        digest: DigestType,
    ) -> anyhow::Result<()> {
        let public_key = rsa_public_from_cert(cert)?;
        let hash = hash_chunks(digest, [data]);

        public_key
            .verify(digest.pkcs1v15(), &hash, signature)
            .context("Signature verification failed!")
    }

    pub fn verify_signature(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        let public_key = rsa_public_from_cert(cert)?;

        // IKEv1 signs the bare hash (no DigestInfo), matching OpenSSL's raw
        // public_decrypt + compare: PKCS#1 v1.5 padding over the hash itself.
        public_key
            .verify(Pkcs1v15Sign::new_unprefixed(), hash, signature)
            .context("Signature verification failed!")
    }
}

/// Parse an RSA public key from a DER-encoded X.509 certificate.
fn rsa_public_from_cert(cert: &[u8]) -> anyhow::Result<RsaPublicKey> {
    use x509_parser::prelude::*;

    let (_, parsed) = X509Certificate::from_der(cert).map_err(|e| anyhow!("Cannot parse certificate: {e}"))?;

    match parsed
        .public_key()
        .parsed()
        .map_err(|e| anyhow!("Cannot parse public key: {e}"))?
    {
        x509_parser::public_key::PublicKey::RSA(rsa) => {
            let n = rsa::BigUint::from_bytes_be(rsa.modulus);
            let e = rsa::BigUint::from_bytes_be(rsa.exponent);
            RsaPublicKey::new(n, e).map_err(|e| anyhow!("Invalid RSA public key: {e}"))
        }
        _ => Err(anyhow!("Certificate does not contain an RSA public key")),
    }
}

/// AES/3DES-CBC with no padding (IKE/ESP pad the plaintext themselves).
pub(crate) fn cbc_encrypt(cipher: CipherType, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Vec<u8>> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};

    macro_rules! run {
        ($block:ty) => {{
            cbc::Encryptor::<$block>::new_from_slices(key, iv)
                .map_err(|e| anyhow!("CBC init failed: {e}"))?
                .encrypt_padded_vec_mut::<NoPadding>(data)
        }};
    }

    match cipher {
        CipherType::Aes128Cbc => Ok(run!(aes::Aes128)),
        CipherType::Aes192Cbc => Ok(run!(aes::Aes192)),
        CipherType::Aes256Cbc => Ok(run!(aes::Aes256)),
        CipherType::DesEde3Cbc => Ok(run!(des::TdesEde3)),
        other => Err(anyhow!("Cipher {:?} is not a CBC cipher", other)),
    }
}

pub(crate) fn cbc_decrypt(cipher: CipherType, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};

    macro_rules! run {
        ($block:ty) => {{
            cbc::Decryptor::<$block>::new_from_slices(key, iv)
                .map_err(|e| anyhow!("CBC init failed: {e}"))?
                .decrypt_padded_vec_mut::<NoPadding>(data)
                .map_err(|e| anyhow!("CBC decrypt failed: {e}"))?
        }};
    }

    match cipher {
        CipherType::Aes128Cbc => Ok(run!(aes::Aes128)),
        CipherType::Aes192Cbc => Ok(run!(aes::Aes192)),
        CipherType::Aes256Cbc => Ok(run!(aes::Aes256)),
        CipherType::DesEde3Cbc => Ok(run!(des::TdesEde3)),
        other => Err(anyhow!("Cipher {:?} is not a CBC cipher", other)),
    }
}

/// AES-GCM AEAD. Returns `ciphertext || tag`, the tag truncated to the
/// negotiated ICV length (ENCR_AES_GCM_8/12/16) via the tag-size type parameter.
pub(crate) fn gcm_encrypt(
    cipher: CipherType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{
        AesGcm, KeyInit,
        aead::{Aead, Payload},
    };

    macro_rules! run {
        ($aes:ty, $tag:ty) => {{
            let c = AesGcm::<$aes, U12, $tag>::new_from_slice(key).map_err(|_| anyhow!("Invalid GCM key"))?;
            c.encrypt(aes_gcm::Nonce::<U12>::from_slice(nonce), Payload { msg: data, aad })
                .map_err(|_| anyhow!("AEAD encryption failed"))?
        }};
    }

    Ok(gcm_match!(cipher, run))
}

pub(crate) fn gcm_decrypt(
    cipher: CipherType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{
        AesGcm, KeyInit,
        aead::{Aead, Payload},
    };

    macro_rules! run {
        ($aes:ty, $tag:ty) => {{
            let c = AesGcm::<$aes, U12, $tag>::new_from_slice(key).map_err(|_| anyhow!("Invalid GCM key"))?;
            c.decrypt(aes_gcm::Nonce::<U12>::from_slice(nonce), Payload { msg: data, aad })
                .map_err(|_| anyhow!("AEAD ICV mismatch"))?
        }};
    }

    Ok(gcm_match!(cipher, run))
}

/// ECDH shared secret (the x coordinate) from an SEC1 uncompressed peer point.
fn ecdh_shared(ec: &EcKex, sec1_peer: &[u8]) -> anyhow::Result<Bytes> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;

    match ec {
        EcKex::P256(secret) => {
            let point = p256::EncodedPoint::from_bytes(sec1_peer).map_err(|e| anyhow!("Malformed EC point: {e}"))?;
            let peer = Option::from(p256::PublicKey::from_encoded_point(&point))
                .context("Peer public key is not on the curve")?;
            Ok(Bytes::copy_from_slice(secret.diffie_hellman(&peer).raw_secret_bytes()))
        }
        EcKex::P384(secret) => {
            let point = p384::EncodedPoint::from_bytes(sec1_peer).map_err(|e| anyhow!("Malformed EC point: {e}"))?;
            let peer = Option::from(p384::PublicKey::from_encoded_point(&point))
                .context("Peer public key is not on the curve")?;
            Ok(Bytes::copy_from_slice(secret.diffie_hellman(&peer).raw_secret_bytes()))
        }
        EcKex::P521(secret) => {
            let point = p521::EncodedPoint::from_bytes(sec1_peer).map_err(|e| anyhow!("Malformed EC point: {e}"))?;
            let peer = Option::from(p521::PublicKey::from_encoded_point(&point))
                .context("Peer public key is not on the curve")?;
            Ok(Bytes::copy_from_slice(secret.diffie_hellman(&peer).raw_secret_bytes()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto(digest: DigestType, cipher: CipherType) -> Crypto {
        Crypto::with_parameters(digest, cipher, GroupType::Oakley2).unwrap()
    }

    /// prf+ key expansion, RFC 7296 §2.13. Known answers computed independently
    /// with Python's `hmac` over the same key/seed.
    #[test]
    fn test_prf_plus_known_answers() {
        let key: Vec<u8> = (0..32).collect();
        let seed = b"IKEv2 prf+ test seed";

        for (digest, out_len, expected) in [
            (
                DigestType::Sha256,
                100,
                "59e1e7fb5d67b2849d8ba06e3615cafdf318a857729681ad3b63c957201302b00f49671912437f29ccf49907d\
                 f788b42694ff309f825732d459b2432ea3f664ef9b5981ed1ba639d0942c940a4a4f20fc83ee1adbc31bcf48b\
                 22c4feb4252428348a6b5c",
            ),
            (
                DigestType::Sha1,
                64,
                "43584c1be65ad03f8049220aebaca5b9740ea97de63a7906f065cf17d56bd2a4f05c9d1842748c91255964d1\
                 ee9fa7b54db0997a85c8a7e23e92ae6388bc9136",
            ),
            (
                DigestType::Sha512,
                32,
                "187f484f55f93b9f4d2fc344a47e17238d804c4cf0f078c42b4d60cb20dd7cca",
            ),
        ] {
            let crypto = crypto(digest, CipherType::Aes256Cbc);
            let out = crypto.prf_plus(&key, seed, out_len).unwrap();

            assert_eq!(out.len(), out_len);
            assert_eq!(hex::encode(&out), expected.replace(' ', ""), "digest {digest:?}");
        }
    }

    /// Every prefix of prf+ output is itself prf+ output: the chain does not
    /// depend on the requested length.
    #[test]
    fn test_prf_plus_is_a_prefix_chain() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);
        let full = crypto.prf_plus(b"key", b"seed", 128).unwrap();

        for len in [1, 31, 32, 33, 64, 96, 127] {
            assert_eq!(crypto.prf_plus(b"key", b"seed", len).unwrap(), full.slice(..len));
        }
    }

    /// The first block of prf+ is prf(K, S | 0x01), the second prf(K, T1 | S | 0x02).
    #[test]
    fn test_prf_plus_matches_manual_chaining() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        let t1 = crypto.prf(b"key", [b"seed".as_ref(), &[1]]).unwrap();
        let t2 = crypto.prf(b"key", [t1.as_ref(), b"seed".as_ref(), &[2]]).unwrap();

        let mut expected = t1.to_vec();
        expected.extend_from_slice(&t2);

        assert_eq!(crypto.prf_plus(b"key", b"seed", 64).unwrap(), expected);
    }

    #[test]
    fn test_prf_plus_rejects_overlong_output() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        assert!(crypto.prf_plus(b"key", b"seed", 255 * 32).is_ok());
        assert!(crypto.prf_plus(b"key", b"seed", 255 * 32 + 1).is_err());
    }

    /// IKEv2 negotiates the PRF independently of the integrity algorithm.
    #[test]
    fn test_prf_is_independent_of_digest() {
        let integ_only = crypto(DigestType::Sha256, CipherType::Aes256Cbc);
        let with_prf = crypto(DigestType::Sha256, CipherType::Aes256Cbc).with_prf(DigestType::Sha512);

        assert_eq!(integ_only.prf_len(), 32);
        assert_eq!(with_prf.prf_len(), 64);
        assert_eq!(with_prf.hash_len(), 32, "hash still follows the integrity digest");
        assert_eq!(with_prf.prf_type(), DigestType::Sha512);
        assert_eq!(with_prf.digest_type(), DigestType::Sha256);

        let sha512 = crypto(DigestType::Sha512, CipherType::Aes256Cbc);
        assert_eq!(
            with_prf.prf(b"key", [b"data"]).unwrap(),
            sha512.prf(b"key", [b"data"]).unwrap()
        );
    }

    /// Without `with_prf` the PRF is the negotiated digest, as IKEv1 expects.
    #[test]
    fn test_prf_defaults_to_digest() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        assert_eq!(crypto.prf_type(), crypto.digest_type());
        assert_eq!(crypto.prf_len(), crypto.hash_len());
    }

    #[test]
    fn test_integrity_is_truncated() {
        for (digest, len) in [
            (DigestType::Sha1, 12),
            (DigestType::Sha256, 16),
            (DigestType::Sha384, 24),
            (DigestType::Sha512, 32),
        ] {
            let crypto = crypto(digest, CipherType::Aes256Cbc);
            let icv = crypto.integrity(b"key", [b"data"]).unwrap();

            assert_eq!(icv.len(), len, "digest {digest:?}");
            assert_eq!(icv, crypto.prf(b"key", [b"data"]).unwrap().slice(..len));
        }
    }

    // NIST/McGrew-Viega AES-GCM test cases 4 (128-bit key) and 16 (256-bit key).
    const GCM_IV: &str = "cafebabefacedbaddecaf888";
    const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                          1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

    #[test]
    fn test_aes_gcm_known_answers() {
        let cases = [
            (
                "feffe9928665731c6d6a8f9467308308",
                CipherType::Aes128Gcm(IcvLength::Sixteen),
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
            (
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                CipherType::Aes256Gcm(IcvLength::Sixteen),
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b",
            ),
        ];

        for (key, cipher_type, ciphertext, icv) in cases {
            let crypto = crypto(DigestType::Sha256, cipher_type);
            let key = hex::decode(key).unwrap();
            let nonce = hex::decode(GCM_IV).unwrap();
            let aad = hex::decode(GCM_AAD).unwrap();
            let plaintext = hex::decode(GCM_PT.replace(' ', "")).unwrap();
            let expected = format!("{}{}", ciphertext.replace(' ', ""), icv);

            let encrypted = crypto.encrypt_aead(&key, &plaintext, &nonce, &aad).unwrap();
            assert_eq!(hex::encode(&encrypted), expected, "cipher {cipher_type:?}");

            let decrypted = crypto.decrypt_aead(&key, &encrypted, &nonce, &aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    /// ENCR_AES_GCM_12 truncates the 16-octet tag; ENCR_AES_GCM_8 is unsupported
    /// by the RustCrypto backend (its TagSize floor is 12 octets).
    #[test]
    fn test_aes_gcm_truncated_icv() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode(GCM_IV).unwrap();
        let aad = hex::decode(GCM_AAD).unwrap();
        let plaintext = hex::decode(GCM_PT.replace(' ', "")).unwrap();

        let aead = crypto(DigestType::Sha256, CipherType::Aes128Gcm(IcvLength::Twelve));
        let encrypted = aead.encrypt_aead(&key, &plaintext, &nonce, &aad).unwrap();
        assert_eq!(encrypted.len(), plaintext.len() + IcvLength::Twelve.size());
        assert_eq!(hex::encode(&encrypted[plaintext.len()..]), "5bc94fbc3221a5db94fae95a");
        assert_eq!(aead.decrypt_aead(&key, &encrypted, &nonce, &aad).unwrap(), plaintext);

        // AES-GCM-8 is rejected rather than silently weakened.
        let gcm8 = crypto(DigestType::Sha256, CipherType::Aes128Gcm(IcvLength::Eight));
        assert!(gcm8.encrypt_aead(&key, &plaintext, &nonce, &aad).is_err());
    }

    #[test]
    fn test_aes_gcm_rejects_tampering() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Gcm(IcvLength::Sixteen));
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let aad = b"ikev2 header";

        let encrypted = crypto.encrypt_aead(&key, b"payload", &nonce, aad).unwrap();

        // flipping the ICV, the ciphertext, the AAD or the nonce all fail
        let mut bad_icv = encrypted.to_vec();
        *bad_icv.last_mut().unwrap() ^= 1;
        assert!(crypto.decrypt_aead(&key, &bad_icv, &nonce, aad).is_err());

        let mut bad_ct = encrypted.to_vec();
        bad_ct[0] ^= 1;
        assert!(crypto.decrypt_aead(&key, &bad_ct, &nonce, aad).is_err());

        assert!(crypto.decrypt_aead(&key, &encrypted, &nonce, b"other header").is_err());
        assert!(crypto.decrypt_aead(&key, &encrypted, &[0x12u8; 12], aad).is_err());
        assert!(crypto.decrypt_aead(&key, &encrypted[..8], &nonce, aad).is_err());
    }

    #[test]
    fn test_aead_and_cbc_apis_do_not_mix() {
        let gcm = crypto(DigestType::Sha256, CipherType::Aes256Gcm(IcvLength::Sixteen));
        assert!(gcm.encrypt(&[0x42; 32], b"payload_16bytes!", &[0x11; 16]).is_err());
        assert!(gcm.decrypt(&[0x42; 32], b"payload_16bytes!", &[0x11; 16]).is_err());

        let cbc = crypto(DigestType::Sha256, CipherType::Aes256Cbc);
        assert!(cbc.encrypt_aead(&[0x42; 32], b"payload", &[0x11; 12], b"").is_err());
        assert!(cbc.decrypt_aead(&[0x42; 32], b"payload", &[0x11; 12], b"").is_err());

        // wrong key or nonce length is caught before the cipher sees it
        assert!(gcm.encrypt_aead(&[0x42; 16], b"payload", &[0x11; 12], b"").is_err());
        assert!(gcm.encrypt_aead(&[0x42; 32], b"payload", &[0x11; 8], b"").is_err());
    }

    #[test]
    fn test_cipher_geometry() {
        let gcm = CipherType::Aes256Gcm(IcvLength::Sixteen);
        assert!(gcm.is_aead());
        assert_eq!((gcm.key_len(), gcm.salt_len(), gcm.key_material_len()), (32, 4, 36));
        assert_eq!((gcm.iv_len(), gcm.nonce_len(), gcm.icv_len()), (8, 12, 16));
        assert_eq!(gcm.block_size(), 4);

        let cbc = CipherType::Aes128Cbc;
        assert!(!cbc.is_aead());
        assert_eq!((cbc.key_len(), cbc.salt_len(), cbc.key_material_len()), (16, 0, 16));
        assert_eq!((cbc.iv_len(), cbc.nonce_len(), cbc.icv_len()), (16, 16, 0));
        assert_eq!(cbc.block_size(), 16);

        assert_eq!(CipherType::DesEde3Cbc.iv_len(), 8);
    }

    #[test]
    fn test_ikev2_encr_transform_ids() {
        assert_eq!(CipherType::new_for_ikev2(3, 24).unwrap(), CipherType::DesEde3Cbc);
        assert_eq!(CipherType::new_for_ikev2(12, 32).unwrap(), CipherType::Aes256Cbc);
        assert_eq!(
            CipherType::new_for_ikev2(18, 16).unwrap(),
            CipherType::Aes128Gcm(IcvLength::Eight)
        );
        assert_eq!(
            CipherType::new_for_ikev2(19, 24).unwrap(),
            CipherType::Aes192Gcm(IcvLength::Twelve)
        );
        assert_eq!(
            CipherType::new_for_ikev2(20, 32).unwrap(),
            CipherType::Aes256Gcm(IcvLength::Sixteen)
        );

        assert!(CipherType::new_for_ikev2(12, 20).is_err());
        assert!(CipherType::new_for_ikev2(3, 16).is_err());
        assert!(CipherType::new_for_ikev2(23, 16).is_err());
    }

    #[test]
    fn test_group_ids_round_trip() {
        for group in [
            GroupType::Oakley2,
            GroupType::Oakley14,
            GroupType::EcP256,
            GroupType::EcP384,
            GroupType::EcP521,
        ] {
            assert_eq!(GroupType::from_group_id(group.group_id()).unwrap(), group);
        }

        assert!(GroupType::from_group_id(1).is_err());
    }

    /// Both peers derive the same secret, and both the KE payload and the
    /// secret are zero-padded to the group's fixed width (RFC 7296 §2.14).
    #[test]
    fn test_key_exchange_agrees_and_is_padded() {
        for group in [
            GroupType::Oakley2,
            GroupType::Oakley14,
            GroupType::EcP256,
            GroupType::EcP384,
            GroupType::EcP521,
        ] {
            let initiator = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, group).unwrap();
            let responder = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, group).unwrap();

            let ke_i = initiator.public_key().unwrap();
            let ke_r = responder.public_key().unwrap();

            assert_eq!(ke_i.len(), group.public_key_len(), "KE payload width, {group:?}");
            assert_eq!(ke_r.len(), group.public_key_len(), "KE payload width, {group:?}");

            let secret_i = initiator.shared_secret(&ke_r).unwrap();
            let secret_r = responder.shared_secret(&ke_i).unwrap();

            assert_eq!(secret_i, secret_r, "shared secret mismatch, {group:?}");
            assert_eq!(secret_i.len(), group.shared_secret_len(), "secret width, {group:?}");
        }
    }

    #[test]
    fn test_modp_rejects_degenerate_peer_keys() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        // p - 1, p, 1 and 0 all yield a degenerate or invalid shared secret
        let mut p_minus_1 = G2_P.to_vec();
        *p_minus_1.last_mut().unwrap() = 254;

        for peer in [p_minus_1, G2_P.to_vec(), vec![1], vec![0], vec![0xff; 128]] {
            assert!(crypto.shared_secret(&peer).is_err(), "accepted {}", hex::encode(&peer));
        }

        // a legitimate peer key still works
        let peer = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2).unwrap();
        assert!(crypto.shared_secret(&peer.public_key().unwrap()).is_ok());
    }

    #[test]
    fn test_ecp_rejects_invalid_peer_keys() {
        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::EcP256).unwrap();

        // wrong width, and a correctly sized point that is not on the curve
        assert!(crypto.shared_secret(&[0u8; 32]).is_err());
        assert!(crypto.shared_secret(&[0u8; 65]).is_err());
        assert!(crypto.shared_secret(&[0u8; 64]).is_err());
        assert!(crypto.shared_secret(&[0xaa; 64]).is_err());
    }

    /// The DigestInfo prefixes of RFC 8017 §9.2, pinned against the hash of an
    /// empty input, and then shown to be exactly what a standard
    /// RSASSA-PKCS1-v1_5 signature is made over: signing this blob with raw
    /// (unprefixed) PKCS#1 padding must verify as an ordinary signature over the
    /// data.
    #[test]
    fn test_digest_info_is_an_rsa_pkcs1_signature_input() {
        use rsa::{RsaPrivateKey, RsaPublicKey};

        assert_eq!(
            hex::encode(DigestType::Sha1.digest_info(b"").unwrap()),
            "3021300906052b0e03021a05000414da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex::encode(DigestType::Sha256.digest_info(b"").unwrap()),
            "3031300d060960864801650304020105000420\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let data = b"InitiatorSignedOctets";

        for digest in [DigestType::Sha1, DigestType::Sha256, DigestType::Sha512] {
            let info = digest.digest_info(data).unwrap();

            // what `ClientCertificate::sign` does with the blob: raw PKCS#1 over
            // the DigestInfo, no second prefix.
            let signature = private.sign(Pkcs1v15Sign::new_unprefixed(), &info).unwrap();

            // and it verifies as an ordinary signature over the data
            let hash = hash_chunks(digest, [data.as_ref()]);
            assert!(
                public.verify(digest.pkcs1v15(), &hash, &signature).is_ok(),
                "{digest:?}"
            );
        }
    }

    #[test]
    fn test_left_pad() {
        assert_eq!(left_pad(&[1, 2], 4).unwrap(), Bytes::from_static(&[0, 0, 1, 2]));
        assert_eq!(left_pad(&[1, 2], 2).unwrap(), Bytes::from_static(&[1, 2]));
        assert!(left_pad(&[1, 2, 3], 2).is_err());
    }
}

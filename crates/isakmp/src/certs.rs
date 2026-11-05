use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, CertificateType, KeyType},
    session::{Session, UserType},
    types::AuthPin,
};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePrivateKey};
use secrecy::{ExposeSecret, SecretString};
use tracing::debug;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    crypto::{DigestType, hash_chunks},
    model::Identity,
};

/// Normalize a certificate to DER, accepting either DER or PEM input.
fn to_der(data: &[u8]) -> anyhow::Result<Bytes> {
    if X509Certificate::from_der(data).is_ok() {
        return Ok(Bytes::copy_from_slice(data));
    }
    let (_, pem) = x509_parser::pem::parse_x509_pem(data).map_err(|e| anyhow!("Cannot parse certificate: {e}"))?;
    Ok(Bytes::from(pem.contents))
}

/// Loads the client certificate an [`Identity`] names, alongside whether it
/// asks for hybrid authentication. Shared by both IKE versions' sessions,
/// which differ in what they do with the certificate, not in how they load it.
pub fn load_identity(identity: Identity) -> anyhow::Result<(bool, Option<Arc<dyn ClientCertificate + Send + Sync>>)> {
    Ok(match identity {
        Identity::Pkcs12 {
            data,
            password,
            hybrid_auth,
        } => (
            hybrid_auth,
            Some(Arc::new(Pkcs8Certificate::from_pkcs12(
                &data,
                password.expose_secret(),
            )?)),
        ),
        Identity::Pkcs8 { data, hybrid_auth } => (hybrid_auth, Some(Arc::new(Pkcs8Certificate::from_pkcs8(&data)?))),
        Identity::Pkcs11 {
            driver_path,
            pin,
            key_id,
            hybrid_auth,
        } => (
            hybrid_auth,
            Some(Arc::new(Pkcs11Certificate::new(driver_path, pin, key_id)?)),
        ),
        #[cfg(windows)]
        Identity::System { common_name } => (true, Some(Arc::new(windows::SystemCertificate::new(&common_name)?))),
        Identity::None => (false, None),
    })
}

pub trait ClientCertificate {
    fn issuer(&self) -> Bytes;

    fn issuer_name(&self) -> String;

    fn subject(&self) -> Bytes;

    fn subject_name(&self) -> String;

    fn fingerprint(&self) -> Bytes;

    fn certs(&self) -> Vec<Bytes>;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes>;
}

/// A certificate chain held as DER. Accessors parse on demand with x509-parser;
/// chain-path validation is not implemented here (it had no callers).
pub struct CertList(Vec<Bytes>);

impl CertList {
    pub fn from_ipsec(certs: &[&Bytes]) -> anyhow::Result<Self> {
        let mut list = Vec::with_capacity(certs.len());
        for cert in certs {
            list.push(to_der(cert)?);
        }
        Ok(Self(list))
    }

    fn with_first<T: Default>(&self, f: impl FnOnce(&X509Certificate) -> T) -> T {
        match self.0.first() {
            Some(der) => match X509Certificate::from_der(der) {
                Ok((_, cert)) => f(&cert),
                Err(_) => T::default(),
            },
            None => T::default(),
        }
    }

    pub fn issuer(&self) -> Bytes {
        self.with_first(|c| Bytes::copy_from_slice(c.issuer().as_raw()))
    }

    pub fn issuer_name(&self) -> String {
        self.with_first(|c| c.issuer().to_string())
    }

    pub fn subject(&self) -> Bytes {
        self.with_first(|c| Bytes::copy_from_slice(c.subject().as_raw()))
    }

    pub fn subject_name(&self) -> String {
        self.with_first(|c| c.subject().to_string())
    }

    pub fn fingerprint(&self) -> Bytes {
        self.0
            .first()
            .map(|der| Bytes::from(hash_chunks(DigestType::Sha1, [der.as_ref()])))
            .unwrap_or_default()
    }

    pub fn certs(&self) -> Vec<Bytes> {
        self.0.clone()
    }
}

pub struct Pkcs8Certificate {
    key: RsaPrivateKey,
    certs: CertList,
}

impl Pkcs8Certificate {
    pub fn from_pkcs12(data: &[u8], password: &str) -> anyhow::Result<Self> {
        let store = p12_keystore::KeyStore::from_pkcs12(data, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
            .map_err(|e| anyhow!("Cannot parse PKCS12: {e}"))?;

        let (_, chain) = store
            .private_key_chain()
            .context("No private key chain found in the PKCS12!")?;

        let key = RsaPrivateKey::from_pkcs8_der(chain.key().as_der())
            .map_err(|e| anyhow!("PKCS12 private key is not a supported RSA key: {e}"))?;

        let certs = chain
            .certs()
            .iter()
            .map(|c| Bytes::copy_from_slice(c.as_der()))
            .collect();

        Ok(Self {
            key,
            certs: CertList(certs),
        })
    }

    pub fn from_pkcs8(data: &[u8]) -> anyhow::Result<Self> {
        let pem = std::str::from_utf8(data).context("PKCS8 PEM is not valid UTF-8")?;
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| anyhow!("Cannot parse private key: {e}"))?;

        let mut certs = Vec::new();
        for pem in x509_parser::pem::Pem::iter_from_buffer(data) {
            let pem = pem.map_err(|e| anyhow!("Cannot parse PEM: {e}"))?;
            if pem.label == "CERTIFICATE" {
                certs.push(Bytes::from(pem.contents));
            }
        }

        Ok(Self {
            key,
            certs: CertList(certs),
        })
    }
}

impl ClientCertificate for Pkcs8Certificate {
    fn issuer(&self) -> Bytes {
        self.certs.issuer()
    }

    fn issuer_name(&self) -> String {
        self.certs.issuer_name()
    }

    fn subject(&self) -> Bytes {
        self.certs.subject()
    }

    fn subject_name(&self) -> String {
        self.certs.subject_name()
    }

    fn fingerprint(&self) -> Bytes {
        self.certs.fingerprint()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.certs()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        // RSASSA-PKCS1-v1_5 over the raw input (the caller already supplies either the bare hash or
        // the DigestInfo blob), i.e. no second DigestInfo prefix — matching OpenSSL private_encrypt.
        let signature = self
            .key
            .sign(Pkcs1v15Sign::new_unprefixed(), data)
            .map_err(|e| anyhow!("Signing failed: {e}"))?;
        Ok(Bytes::from(signature))
    }
}

pub(crate) struct Pkcs11Certificate {
    driver_path: PathBuf,
    pin: SecretString,
    key_id: Option<Bytes>,
    certs: CertList,
}

impl Pkcs11Certificate {
    fn init_session(driver_path: &Path, pin: &str) -> anyhow::Result<Session> {
        debug!("Initializing PKCS11");
        let pkcs11 = Pkcs11::new(driver_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slots = pkcs11.get_slots_with_token()?;

        debug!("Total slots: {}", slots.len());
        let slot = slots.into_iter().next().context("No slots found")?;

        let user_pin = AuthPin::new(pin.to_owned().into());

        debug!("Opening session");
        let session = pkcs11.open_ro_session(slot)?;

        debug!("Authenticating user");
        session.login(UserType::User, Some(&user_pin))?;

        Ok(session)
    }

    pub fn new(driver_path: PathBuf, pin: SecretString, key_id: Option<Bytes>) -> anyhow::Result<Self> {
        let session = Self::init_session(&driver_path, pin.expose_secret())?;

        let mut cert_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::CertificateType(CertificateType::X_509),
        ];

        if let Some(ref key_id) = key_id {
            cert_template.push(Attribute::Id(key_id.to_vec()));
        }

        let mut certs = Vec::new();

        debug!("Reading certificates");

        for obj in session.find_objects(&cert_template)? {
            if let Some(Attribute::Value(value)) =
                session.get_attributes(obj, &[AttributeType::Value])?.into_iter().next()
            {
                certs.push(Bytes::from(value));
            }
        }

        Ok(Self {
            driver_path,
            pin,
            key_id,
            certs: CertList(certs),
        })
    }
}

impl ClientCertificate for Pkcs11Certificate {
    fn issuer(&self) -> Bytes {
        self.certs.issuer()
    }

    fn issuer_name(&self) -> String {
        self.certs.issuer_name()
    }

    fn subject(&self) -> Bytes {
        self.certs.subject()
    }

    fn subject_name(&self) -> String {
        self.certs.subject_name()
    }

    fn fingerprint(&self) -> Bytes {
        self.certs.fingerprint()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.certs()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let session = Self::init_session(&self.driver_path, self.pin.expose_secret())?;

        let mut priv_key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::KeyType(KeyType::RSA),
        ];

        if let Some(ref key_id) = self.key_id {
            priv_key_template.push(Attribute::Id(key_id.to_vec()));
        }

        debug!("Looking up for private key");

        let key = session
            .find_objects(&priv_key_template)?
            .into_iter()
            .next()
            .context("No private key!")?;

        let always_auth = matches!(
            session
                .get_attributes(key, &[AttributeType::AlwaysAuthenticate])?
                .into_iter()
                .next(),
            Some(Attribute::AlwaysAuthenticate(true))
        );

        if always_auth {
            debug!("Authenticating for additional context");
            let user_pin = AuthPin::new(self.pin.expose_secret().to_owned().into());
            session.login(UserType::ContextSpecific, Some(&user_pin))?;
        }

        debug!("Signing data");

        Ok(session.sign(&Mechanism::RsaPkcs, key, data)?.into())
    }
}

#[cfg(windows)]
pub mod windows {
    use std::{mem, ptr, slice};

    use anyhow::anyhow;
    use bytes::Bytes;
    use tracing::debug;
    use windows_sys::Win32::{Foundation::GetLastError, Security::Cryptography::*};

    use super::{CertList, ClientCertificate};

    const HCCE_LOCAL_MACHINE: HCERTCHAINENGINE = 0x1 as HCERTCHAINENGINE;
    const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    pub struct SystemCertificate {
        cert_context: *const CERT_CONTEXT,
        key_handle: NCRYPT_KEY_HANDLE,
        certs: CertList,
    }

    unsafe impl Send for SystemCertificate {}
    unsafe impl Sync for SystemCertificate {}

    impl SystemCertificate {
        pub fn new(common_name: &str) -> anyhow::Result<Self> {
            unsafe {
                let store_name: Vec<u16> = "MY".encode_utf16().chain([0]).collect();

                debug!("Opening LocalMachine MY certificate store");

                let store = CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    HCRYPTPROV_LEGACY::default(),
                    (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
                        | CERT_STORE_OPEN_EXISTING_FLAG
                        | CERT_STORE_READONLY_FLAG,
                    store_name.as_ptr() as _,
                );
                if store.is_null() {
                    return Err(win32_err("CertOpenStore"));
                }

                let pattern: Vec<u16> = common_name.encode_utf16().chain([0]).collect();

                debug!("Searching for certificate with subject containing '{}'", common_name);

                let found = CertFindCertificateInStore(
                    store,
                    MY_ENCODING_TYPE,
                    0,
                    CERT_FIND_SUBJECT_STR,
                    pattern.as_ptr() as _,
                    ptr::null(),
                );

                if found.is_null() {
                    CertCloseStore(store, 0);
                    return Err(anyhow!("No certificate matching '{}' in LocalMachine\\MY", common_name));
                }

                let cert_context = CertDuplicateCertificateContext(found);
                CertCloseStore(store, 0);

                let chain = match Self::build_chain(cert_context) {
                    Ok(c) => c,
                    Err(e) => {
                        CertFreeCertificateContext(cert_context);
                        return Err(e);
                    }
                };

                let certs = CertList(chain.iter().map(|der| Bytes::copy_from_slice(der)).collect());

                debug!("Acquiring CNG private key (silent)");

                let mut handle: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = 0;
                let mut key_spec: CERT_KEY_SPEC = 0;
                let ok = CryptAcquireCertificatePrivateKey(
                    cert_context,
                    CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                    ptr::null(),
                    &mut handle,
                    &mut key_spec,
                    ptr::null_mut(),
                );
                if ok == 0 {
                    let err = win32_err("CryptAcquireCertificatePrivateKey");
                    CertFreeCertificateContext(cert_context);
                    return Err(err);
                }

                let key_handle = handle as NCRYPT_KEY_HANDLE;

                let group = match get_string_property(key_handle, NCRYPT_ALGORITHM_GROUP_PROPERTY) {
                    Ok(g) => g,
                    Err(e) => {
                        let _ = NCryptFreeObject(key_handle);
                        CertFreeCertificateContext(cert_context);
                        return Err(e);
                    }
                };
                if group != "RSA" {
                    let _ = NCryptFreeObject(key_handle);
                    CertFreeCertificateContext(cert_context);
                    return Err(anyhow!("Private key algorithm group is not RSA: {}", group));
                }

                Ok(Self {
                    cert_context,
                    key_handle,
                    certs,
                })
            }
        }

        unsafe fn build_chain(ctx: *const CERT_CONTEXT) -> anyhow::Result<Vec<Vec<u8>>> {
            unsafe {
                let param: CERT_CHAIN_PARA = CERT_CHAIN_PARA {
                    cbSize: mem::size_of::<CERT_CHAIN_PARA>() as u32,
                    ..mem::zeroed()
                };
                let mut chain_ctx: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

                let result = CertGetCertificateChain(
                    HCCE_LOCAL_MACHINE,
                    ctx,
                    ptr::null(),
                    ptr::null_mut(),
                    &param,
                    0,
                    ptr::null(),
                    &mut chain_ctx,
                );

                let mut out = Vec::new();

                if result != 0 && !chain_ctx.is_null() {
                    if (*chain_ctx).cChain > 0 {
                        let first = *(*chain_ctx).rgpChain;
                        let elements = slice::from_raw_parts((*first).rgpElement, (*first).cElement as usize);
                        for (idx, el) in elements.iter().enumerate() {
                            if idx != 0 && ((**el).TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED) != 0 {
                                break;
                            }
                            let c = (**el).pCertContext;
                            let der = slice::from_raw_parts((*c).pbCertEncoded, (*c).cbCertEncoded as usize);
                            out.push(der.to_vec());
                        }
                    }
                    CertFreeCertificateChain(chain_ctx);
                } else {
                    let der = slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize);
                    out.push(der.to_vec());
                }

                Ok(out)
            }
        }
    }

    impl Drop for SystemCertificate {
        fn drop(&mut self) {
            unsafe {
                if self.key_handle != 0 {
                    let _ = NCryptFreeObject(self.key_handle);
                }
                if !self.cert_context.is_null() {
                    CertFreeCertificateContext(self.cert_context);
                }
            }
        }
    }

    impl ClientCertificate for SystemCertificate {
        fn issuer(&self) -> Bytes {
            self.certs.issuer()
        }

        fn issuer_name(&self) -> String {
            self.certs.issuer_name()
        }

        fn subject(&self) -> Bytes {
            self.certs.subject()
        }

        fn subject_name(&self) -> String {
            self.certs.subject_name()
        }

        fn fingerprint(&self) -> Bytes {
            self.certs.fingerprint()
        }

        fn certs(&self) -> Vec<Bytes> {
            self.certs.certs()
        }

        fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
            unsafe {
                let flags = NCRYPT_SILENT_FLAG | NCRYPT_PAD_PKCS1_FLAG;
                let mut needed: u32 = 0;

                let status = NCryptEncrypt(
                    self.key_handle,
                    data.as_ptr(),
                    data.len() as u32,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut needed,
                    flags,
                );
                if status != 0 {
                    return Err(anyhow!("NCryptEncrypt(size) failed: 0x{:08x}", status));
                }

                let mut buf = vec![0u8; needed as usize];
                let mut written: u32 = 0;
                let status = NCryptEncrypt(
                    self.key_handle,
                    data.as_ptr(),
                    data.len() as u32,
                    ptr::null(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut written,
                    flags,
                );
                if status != 0 {
                    return Err(anyhow!("NCryptEncrypt failed: 0x{:08x}", status));
                }

                buf.truncate(written as usize);
                Ok(Bytes::from(buf))
            }
        }
    }

    fn win32_err(label: &str) -> anyhow::Error {
        let code = unsafe { GetLastError() };
        anyhow!("{} failed: 0x{:08x}", label, code)
    }

    unsafe fn get_string_property(
        key: NCRYPT_KEY_HANDLE,
        property: windows_sys::core::PCWSTR,
    ) -> anyhow::Result<String> {
        unsafe {
            let mut size: u32 = 0;
            let status = NCryptGetProperty(key, property, ptr::null_mut(), 0, &mut size, 0);
            if status != 0 {
                return Err(anyhow!("NCryptGetProperty(size) failed: 0x{:08x}", status));
            }
            let mut buf = vec![0u8; size as usize];
            let status = NCryptGetProperty(key, property, buf.as_mut_ptr(), buf.len() as u32, &mut size, 0);
            if status != 0 {
                return Err(anyhow!("NCryptGetProperty failed: 0x{:08x}", status));
            }
            let utf16 = slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len() / 2);
            let len = utf16.iter().position(|&c| c == 0).unwrap_or(utf16.len());
            Ok(String::from_utf16_lossy(&utf16[..len]))
        }
    }
}

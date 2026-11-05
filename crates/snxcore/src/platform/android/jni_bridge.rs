//! JNI boundary between the Rust core and the Android `VpnService`.
//!
//! Two directions cross here:
//!
//! * Java -> Rust: lifecycle entry points (`nativeConnect`, `nativeDisconnect`) invoked from the
//!   `VpnService`. They start/stop the tokio runtime and the connection controller.
//! * Rust -> Java: the [`VpnServiceHandle`] callbacks. `establish_tun` builds the interface with
//!   `VpnService.Builder` and returns its fd; `protect_socket` keeps gateway sockets off the tunnel;
//!   `keystore_*` back the Android keychain.
//!
//! The concrete handle (holding a `JavaVM` + `GlobalRef` to the service) is implemented with the
//! `jni` crate behind the `android-jni` feature. The rest of `snxcore` only sees this trait, so no
//! `jni` types leak into the platform-independent code.

#![allow(unsafe_code)] // platform module: JNI FFI lives here

use std::{
    net::Ipv4Addr,
    os::fd::RawFd,
    sync::{Mutex, OnceLock},
};

use anyhow::{Context, anyhow};
use ipnet::Ipv4Net;
use uuid::Uuid;

/// Everything Java needs to build the tunnel with `VpnService.Builder`, flattened to plain types the
/// bridge can marshal across JNI.
#[derive(Debug, Clone, Default)]
pub struct TunBuilderConfig {
    pub address: Ipv4Net,
    pub mtu: u16,
    /// Empty => full tunnel: Java installs `0.0.0.0/0`.
    pub routes: Vec<Ipv4Net>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub search_domains: Vec<String>,
    /// The gateway address; informational — gateway sockets are kept off the tunnel via
    /// [`VpnServiceHandle::protect_socket`], not via excluded routes.
    pub gateway: Option<Ipv4Addr>,
}

/// Callbacks into the live `VpnService`. Implemented by the `android-jni` layer.
pub trait VpnServiceHandle: Send + Sync {
    /// Runs `VpnService.Builder` with `config`, calls `establish()`, and returns the raw fd of the
    /// resulting `ParcelFileDescriptor` (ownership transferred to the caller via `detachFd`).
    fn establish_tun(&self, config: &TunBuilderConfig) -> anyhow::Result<RawFd>;

    /// `VpnService.protect(fd)` — every socket the core opens toward the gateway must be protected or
    /// its traffic routes back into the tunnel and deadlocks.
    fn protect_socket(&self, fd: RawFd) -> anyhow::Result<()>;

    /// Stable per-install identifier (derived from `ANDROID_ID`).
    fn android_id(&self) -> anyhow::Result<String>;

    fn keystore_get(&self, key: &str) -> anyhow::Result<Option<String>>;
    fn keystore_set(&self, key: &str, value: &str) -> anyhow::Result<()>;
    fn keystore_delete(&self, key: &str) -> anyhow::Result<()>;
}

static HANDLE: OnceLock<Mutex<Option<Box<dyn VpnServiceHandle>>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Box<dyn VpnServiceHandle>>> {
    HANDLE.get_or_init(|| Mutex::new(None))
}

pub fn set_handle(handle: Box<dyn VpnServiceHandle>) {
    *slot().lock().unwrap() = Some(handle);
}

pub fn clear_handle() {
    *slot().lock().unwrap() = None;
    super::staging::clear();
}

fn with_handle<T>(f: impl FnOnce(&dyn VpnServiceHandle) -> anyhow::Result<T>) -> anyhow::Result<T> {
    let guard = slot().lock().unwrap();
    let handle = guard
        .as_deref()
        .ok_or_else(|| anyhow!("No VpnService handle registered; not running under the Android service"))?;
    f(handle)
}

pub fn establish_tun(config: &TunBuilderConfig) -> anyhow::Result<RawFd> {
    with_handle(|h| h.establish_tun(config)).context("VpnService.establish() failed")
}

pub fn protect_socket(fd: RawFd) -> anyhow::Result<()> {
    with_handle(|h| h.protect_socket(fd))
}

pub fn machine_uuid() -> anyhow::Result<Uuid> {
    let id = with_handle(|h| h.android_id())?;
    // Stable UUIDv5 over ANDROID_ID in the snx-rs namespace; mirrors how other platforms derive a
    // stable machine id without exposing the raw device identifier.
    Ok(Uuid::new_v5(&Uuid::NAMESPACE_OID, id.as_bytes()))
}

pub fn keystore_get(key: &str) -> anyhow::Result<Option<String>> {
    with_handle(|h| h.keystore_get(key))
}

pub fn keystore_set(key: &str, value: &str) -> anyhow::Result<()> {
    with_handle(|h| h.keystore_set(key, value))
}

pub fn keystore_delete(key: &str) -> anyhow::Result<()> {
    with_handle(|h| h.keystore_delete(key))
}

// ---------------------------------------------------------------------------
// JNI entry points (Java -> Rust).
//
// These are the `extern "system"` symbols the Kotlin `VpnClientService` binds with `external fun`.
// The real bodies decode the jobject/jstring args with the `jni` crate, construct the concrete
// `VpnServiceHandle`, and drive `crate::controller`. Compiled behind `android-jni`.
// ---------------------------------------------------------------------------

/// `external fun nativeConnect(service: VpnClientService, configJson: String): Int`
#[cfg(feature = "android-jni")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeConnect(
    mut _env: jni::JNIEnv,
    _service: jni::objects::JObject,
    _config_json: jni::objects::JString,
) -> jni::sys::jint {
    // 1. let params: TunnelParams = serde_json::from_str(&env.get_string(&config_json)?)?;
    // 2. let vm = env.get_java_vm()?; let service = env.new_global_ref(service)?;
    //    set_handle(Box::new(AndroidVpnServiceHandle::new(vm, service)));
    // 3. start the cached tokio runtime and spawn crate::controller::ServiceController on it,
    //    forcing TunnelType::IPsec with the userspace ESP path (features.ipsec_native == false).
    unimplemented!("wire up the jni crate, then start crate::controller")
}

/// `external fun nativeDisconnect()`
#[cfg(feature = "android-jni")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeDisconnect(
    _env: jni::JNIEnv,
    _service: jni::objects::JObject,
) {
    // signal the controller to disconnect, then clear_handle()
    unimplemented!()
}

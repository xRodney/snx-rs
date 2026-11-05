//! JNI boundary between the Rust core and the Android `VpnService`.
//!
//! Two directions cross here:
//!
//! * Java -> Rust: lifecycle entry points (`nativeConnect`, `nativeDisconnect`) invoked from
//!   the `VpnService`. These start/stop the tokio runtime and the tunnel controller.
//! * Rust -> Java: the `establish_tun` callback. On desktop the core *creates* a TUN device and
//!   *then* applies routes/DNS. On Android the OS owns all of that: addresses, routes, DNS and
//!   MTU must be handed to `VpnService.Builder` *before* `establish()` returns a file descriptor.
//!   So the core collects the desired configuration and calls back into Java to build the tunnel
//!   and return the fd, which the core then adopts (see [`super::tun_fd`]).
//!
//! This module only sketches the shape. Wiring it up needs the `jni` crate and a cached
//! `JavaVM` captured in `JNI_OnLoad`.

#![allow(unsafe_code)] // platform module: JNI FFI lives here

use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Context};
use ipnet::Ipv4Net;

/// Everything the Java side needs to build the tunnel with `VpnService.Builder`.
///
/// The core fills this in after the session is negotiated (office-mode address, pushed routes,
/// DNS servers and search domains) and hands it to [`establish_tun`].
#[derive(Debug, Clone, Default)]
pub struct TunBuilderConfig {
    pub address: Ipv4Net,
    pub mtu: u16,
    /// Empty means "default route" (full tunnel): the Java side installs `0.0.0.0/0`.
    pub routes: Vec<Ipv4Net>,
    pub dns_servers: Vec<std::net::Ipv4Addr>,
    pub search_domains: Vec<String>,
    /// Addresses the tunnel must *not* capture (e.g. the gateway itself), installed as
    /// `VpnService.Builder.addDisallowedApplication` is not the right tool — these become
    /// excluded routes handled on the Java side.
    pub bypass: Vec<std::net::Ipv4Addr>,
}

/// Opaque handle to the live `VpnService` instance, cached on connect.
///
/// In the real implementation this is a `jni::objects::GlobalRef` to the service object plus the
/// cached `JavaVM`. Kept behind a trait so the platform code never names `jni` types directly and
/// the rest of `snxcore` stays JNI-free.
pub trait VpnServiceHandle: Send + Sync {
    /// Calls `VpnService.Builder` with `config`, invokes `establish()`, and returns the raw fd of
    /// the resulting `ParcelFileDescriptor`. The fd is owned by the caller afterwards.
    fn establish_tun(&self, config: &TunBuilderConfig) -> anyhow::Result<std::os::fd::RawFd>;

    /// Calls `VpnService.protect(fd)` so the given socket bypasses the tunnel (otherwise the
    /// gateway-bound TLS/UDP socket would route back into the tunnel and deadlock). Every outbound
    /// socket the core opens to the gateway must be protected.
    fn protect_socket(&self, fd: std::os::fd::RawFd) -> anyhow::Result<()>;

    /// Android Keystore access for [`super::keychain`].
    fn keystore_get(&self, key: &str) -> anyhow::Result<Option<String>>;
    fn keystore_set(&self, key: &str, value: &str) -> anyhow::Result<()>;
}

static HANDLE: OnceLock<Mutex<Option<Box<dyn VpnServiceHandle>>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Box<dyn VpnServiceHandle>>> {
    HANDLE.get_or_init(|| Mutex::new(None))
}

/// Registered from `nativeConnect` once the `VpnService` is up.
pub fn set_handle(handle: Box<dyn VpnServiceHandle>) {
    *slot().lock().unwrap() = Some(handle);
}

pub fn clear_handle() {
    *slot().lock().unwrap() = None;
}

fn with_handle<T>(f: impl FnOnce(&dyn VpnServiceHandle) -> anyhow::Result<T>) -> anyhow::Result<T> {
    let guard = slot().lock().unwrap();
    let handle = guard
        .as_deref()
        .ok_or_else(|| anyhow!("No VpnService handle registered; not running under Android service"))?;
    f(handle)
}

/// Called by the Android TUN device adapter instead of opening `/dev/net/tun`.
pub fn establish_tun(config: &TunBuilderConfig) -> anyhow::Result<std::os::fd::RawFd> {
    with_handle(|h| h.establish_tun(config)).context("VpnService.establish() failed")
}

/// Called by every transport before it connects its gateway socket.
pub fn protect_socket(fd: std::os::fd::RawFd) -> anyhow::Result<()> {
    with_handle(|h| h.protect_socket(fd))
}

pub fn keystore_get(key: &str) -> anyhow::Result<Option<String>> {
    with_handle(|h| h.keystore_get(key))
}

pub fn keystore_set(key: &str, value: &str) -> anyhow::Result<()> {
    with_handle(|h| h.keystore_set(key, value))
}

// ---------------------------------------------------------------------------
// JNI entry points (Java -> Rust).
//
// These are the `extern "C"` symbols the Kotlin `VpnClientService` binds via `external fun`.
// Signatures follow the JNI name-mangling scheme `Java_<pkg>_<Class>_<method>`.
// The bodies here are stubs: the real versions decode the `jobject`/`jstring` arguments with the
// `jni` crate, build a concrete `VpnServiceHandle`, and drive the controller.
// ---------------------------------------------------------------------------

/// `external fun nativeConnect(service: VpnClientService, configJson: String): Int`
///
/// Parses the profile JSON, registers a `VpnServiceHandle` wrapping `service`, spins up the tokio
/// runtime and starts the SSL tunnel controller on it. Returns 0 on success.
#[cfg(feature = "android-jni")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeConnect(
    _env: jni_sys::JNIEnv,
    _service: jni_sys::jobject,
    _config_json: jni_sys::jstring,
) -> jni_sys::jint {
    // 1. decode config_json -> TunnelParams
    // 2. set_handle(Box::new(AndroidVpnServiceHandle::new(vm, service_global_ref)))
    // 3. spawn controller on a cached tokio runtime
    unimplemented!("wire up jni crate, then start crate::controller")
}

/// `external fun nativeDisconnect(): Unit`
#[cfg(feature = "android-jni")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeDisconnect(
    _env: jni_sys::JNIEnv,
    _class: jni_sys::jobject,
) {
    // signal the controller to terminate, then clear_handle()
    unimplemented!()
}

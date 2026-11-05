use std::{
    net::Ipv4Addr,
    os::fd::RawFd,
    sync::{Mutex, OnceLock},
};

use anyhow::{Context, anyhow};
use ipnet::Ipv4Net;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct TunBuilderConfig {
    pub address: Ipv4Net,
    pub mtu: u16,
    /// Empty => full tunnel: Java installs `0.0.0.0/0`.
    pub routes: Vec<Ipv4Net>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub search_domains: Vec<String>,
}

/// Callbacks into the app's `VpnService`, implemented by `apps/snxrs-android`.
pub trait VpnServiceHandle: Send + Sync {
    /// Returns a detached fd that the caller owns.
    fn establish_tun(&self, config: &TunBuilderConfig) -> anyhow::Result<RawFd>;

    /// Sockets to the gateway must be protected, or their traffic loops back into the tunnel.
    fn protect_socket(&self, fd: RawFd) -> anyhow::Result<()>;

    fn android_id(&self) -> anyhow::Result<String>;

    fn keystore_get(&self, key: &str) -> anyhow::Result<Option<String>>;
    fn keystore_set(&self, key: &str, value: &str) -> anyhow::Result<()>;
    fn keystore_delete(&self, key: &str) -> anyhow::Result<()>;

    fn open_url(&self, url: &str) -> anyhow::Result<()>;

    /// The tunnel dropped after having been up; the runner is about to reconnect.
    fn reconnecting(&self) -> anyhow::Result<()>;
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

pub fn open_url(url: &str) -> anyhow::Result<()> {
    with_handle(|h| h.open_url(url))
}

pub fn reconnecting() -> anyhow::Result<()> {
    with_handle(|h| h.reconnecting())
}

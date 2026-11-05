//! Android platform implementation.
//!
//! Mirrors the symbol surface re-exported by `platform/linux.rs` so `platform.rs` can select it
//! with a single `cfg`. The big difference from desktop is the TUN device: it is not created here
//! but handed down by `VpnService.establish()` through the [`jni_bridge`], and routing/DNS are set
//! on the Java `VpnService.Builder` rather than applied via `ip`/resolver.
//!
//! IPsec is stubbed (see [`ipsec_stub`]); Android uses the SSL tunnel.

#![allow(unsafe_code)] // platform module: JNI FFI

use std::time::Duration;

use anyhow::anyhow;
use tokio::net::UdpSocket;
use uuid::Uuid;

pub use ipsec_stub::XfrmConfigurator as IpsecImpl;
pub use resolver::new_resolver_configurator;

use crate::platform::{UdpEncap, UdpSocketExt};

pub mod ipsec_stub;
pub mod jni_bridge;
pub mod keychain;
pub mod net;
pub mod resolver;
pub mod tun_fd;

/// On Android we do not open `/dev/net/tun`, so the returned config is a placeholder; the real fd
/// is adopted in `tunnel::ssl::device` via [`tun_fd::adopt_from_vpn_service`]. Kept so shared code
/// that calls `platform::new_tun_config()` still compiles.
pub fn new_tun_config() -> tun::Configuration {
    tun::Configuration::default()
}

#[async_trait::async_trait]
impl UdpSocketExt for UdpSocket {
    fn set_encap(&self, _encap: UdpEncap) -> anyhow::Result<()> {
        // UDP_ENCAP is a kernel-IPsec (XFRM) concern. Unused on Android (SSL tunnel only).
        Ok(())
    }

    fn set_no_check(&self, _flag: bool) -> anyhow::Result<()> {
        Ok(())
    }

    async fn send_receive(&self, data: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
        super::udp_send_receive(self, data, timeout).await
    }
}

pub async fn acquire_password(user_name: &str) -> anyhow::Result<String> {
    keychain::acquire_password(user_name).await
}

pub async fn store_password(user_name: &str, password: &str) -> anyhow::Result<()> {
    keychain::store_password(user_name, password).await
}

/// No separate interface to delete: the fd closes when the tunnel future drops and
/// `VpnService.Builder`'s establish is torn down by stopping the service.
pub async fn delete_device(_device_name: &str) {}

/// No "unmanage" step on Android (no NetworkManager). The VpnService owns the interface.
pub async fn configure_device(_device_name: &str) -> anyhow::Result<()> {
    Ok(())
}

/// A stable per-install id. `ANDROID_ID` via the bridge is the usual source; v5 UUID keeps it in
/// the shape the protocol expects. Skeleton returns a nil placeholder.
pub fn get_machine_uuid() -> anyhow::Result<Uuid> {
    // Real impl: hash Settings.Secure.ANDROID_ID through the bridge into a UUIDv5.
    Err(anyhow!("get_machine_uuid: wire up ANDROID_ID via jni_bridge"))
}

/// Single-instance is meaningless inside one app sandbox; the service lifecycle enforces it.
pub struct SingleInstance;

impl SingleInstance {
    pub fn new<N: AsRef<str>>(_name: N) -> anyhow::Result<Self> {
        Ok(SingleInstance)
    }

    pub fn is_single(&self) -> bool {
        true
    }
}

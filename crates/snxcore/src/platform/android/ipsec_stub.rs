//! Native (kernel XFRM) IPsec is unavailable on Android — it needs CAP_NET_ADMIN and netlink.
//!
//! This is the same situation as macOS: `get_features().ipsec_native == false` forces the connector
//! to pick the **userspace** ESP data path (`tunnel/ipsec/imp/tun.rs`, `isakmp::esp::EspCodec` over a
//! normal UDP/TCP socket), which works fine for an unprivileged app. So this configurator is never
//! actually invoked; it exists to satisfy `PlatformAccess::new_ipsec_configurator`.

use std::net::Ipv4Addr;

use async_trait::async_trait;

use crate::{
    model::IPsecSession,
    platform::{DeviceConfig, IPsecConfigurator},
};

pub struct AndroidIPsecStub {
    _device_config: DeviceConfig,
    _ipsec_session: IPsecSession,
    _src_ip: Ipv4Addr,
    _src_port: u16,
    _dest_ip: Ipv4Addr,
    _dest_port: u16,
}

impl AndroidIPsecStub {
    pub fn new(
        device_config: DeviceConfig,
        ipsec_session: IPsecSession,
        src_ip: Ipv4Addr,
        src_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> Self {
        Self {
            _device_config: device_config,
            _ipsec_session: ipsec_session,
            _src_ip: src_ip,
            _src_port: src_port,
            _dest_ip: dest_ip,
            _dest_port: dest_port,
        }
    }
}

#[async_trait]
impl IPsecConfigurator for AndroidIPsecStub {
    async fn configure(&self) -> anyhow::Result<()> {
        anyhow::bail!("Native IPsec is not available on Android; the userspace ESP path is used instead")
    }

    async fn rekey(&mut self, _session: &IPsecSession) -> anyhow::Result<()> {
        anyhow::bail!("Native IPsec is not available on Android")
    }

    async fn cleanup(&self) {}
}

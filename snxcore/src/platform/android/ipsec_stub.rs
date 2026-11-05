//! IPsec is not available on Android in this fork.
//!
//! The Linux IPsec data path (`platform/linux/xfrm.rs`) drives the kernel XFRM stack over netlink,
//! which needs CAP_NET_ADMIN and is unreachable from an unprivileged app. Upstream snx-rs 6.x added
//! a *userspace* ESP data path (`tunnel/ipsec/imp/tun.rs`, using `isakmp::esp::EspCodec` over a
//! normal UDP/TCP socket); porting that is the path to IPsec-on-Android, but it is out of scope for
//! this skeleton. Until then, Android must use `TunnelType::Ssl`.

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::bail;
use async_trait::async_trait;
use ipnet::Ipv4Net;

use crate::model::{params::TunnelParams, IpsecSession};
use crate::platform::IpsecConfigurator;

pub struct XfrmConfigurator;

impl XfrmConfigurator {
    pub fn new(
        _tunnel_params: Arc<TunnelParams>,
        _ipsec_session: IpsecSession,
        _src_port: u16,
        _dest_ip: Ipv4Addr,
        _subnets: Vec<Ipv4Net>,
    ) -> anyhow::Result<Self> {
        bail!("IPsec is not supported on Android; use the SSL tunnel (tunnel-type=ssl). \
               Userspace ESP (isakmp EspCodec) must be ported from upstream snx-rs 6.x first.")
    }
}

#[async_trait]
impl IpsecConfigurator for XfrmConfigurator {
    async fn configure(&mut self) -> anyhow::Result<()> {
        bail!("IPsec not supported on Android")
    }

    async fn rekey(&mut self, _session: &IpsecSession) -> anyhow::Result<()> {
        bail!("IPsec not supported on Android")
    }

    async fn cleanup(&mut self) {}
}

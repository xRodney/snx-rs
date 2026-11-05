//! Adopting the `VpnService` file descriptor as a `tun::AsyncDevice`.
//!
//! An unprivileged app cannot open `/dev/net/tun` or configure an interface. The fd is minted by
//! `VpnService.establish()` and arrives already configured. This module drains the staged config
//! (device/routing/DNS), asks Java to build the tunnel, and wraps the returned fd.
//!
//! tun 0.8's Android backend is built for exactly this: `Device::new` *requires* `raw_fd` and does
//! no interface configuration (verified against tun-0.8.14).

use std::os::fd::RawFd;

use anyhow::{Context, anyhow};

use super::{
    jni_bridge::{self, TunBuilderConfig},
    staging,
};
use crate::platform::RoutingConfig;

/// Build `TunBuilderConfig` from the staged pieces, establish via the VpnService, wrap the fd.
pub(crate) fn adopt_from_staged() -> anyhow::Result<tun::AsyncDevice> {
    let snap = staging::snapshot();

    let device = snap
        .device
        .ok_or_else(|| anyhow!("TUN establish before configure_device was staged"))?;

    let (routes, gateway) = match snap.routing {
        Some(RoutingConfig::Full { destination, .. }) => (Vec::new(), Some(destination)),
        Some(RoutingConfig::Split { destination, routes }) => (routes, Some(destination)),
        Some(RoutingConfig::Cleanup { destination, .. }) => (Vec::new(), Some(destination)),
        None => (Vec::new(), None),
    };

    let (dns_servers, search_domains) = match snap.resolver {
        Some(r) => (r.dns_servers, r.search_domains.into_iter().map(|d| d.name).collect()),
        None => (Vec::new(), Vec::new()),
    };

    let config = TunBuilderConfig {
        address: device.address,
        mtu: device.mtu,
        routes,
        dns_servers,
        search_domains,
        gateway,
    };

    let fd = jni_bridge::establish_tun(&config).context("establish_tun")?;
    from_raw_fd(fd)
}

fn from_raw_fd(fd: RawFd) -> anyhow::Result<tun::AsyncDevice> {
    let mut cfg = tun::Configuration::default();
    // tun 0.8's Android backend requires raw_fd and does zero interface configuration; do NOT set
    // address/up here (VpnService already did, and those paths need CAP_NET_ADMIN).
    cfg.raw_fd(fd);
    // We detached the fd from the Java ParcelFileDescriptor, so Rust owns it and closes it on drop.
    cfg.close_fd_on_drop(true);
    tun::create_as_async(&cfg).context("wrap VpnService fd as tun device")
}

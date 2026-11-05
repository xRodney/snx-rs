use std::os::fd::RawFd;

use anyhow::{Context, anyhow};
use ipnet::Ipv4Net;

use super::{
    jni_bridge::{self, TunBuilderConfig},
    staging,
};
use crate::platform::RoutingConfig;

pub(crate) fn adopt_from_staged() -> anyhow::Result<tun::AsyncDevice> {
    let snap = staging::snapshot();

    let device = snap
        .device
        .ok_or_else(|| anyhow!("TUN establish before configure_device was staged"))?;

    let routes = match snap.routing {
        // The keepalive to the gateway must go inside the tunnel; the protected IKE/ESP sockets still bypass it.
        Some(RoutingConfig::Split {
            destination,
            mut routes,
        }) => {
            routes.push(Ipv4Net::from(destination));
            routes
        }
        _ => Vec::new(),
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
    };

    let fd = jni_bridge::establish_tun(&config).context("establish_tun")?;
    from_raw_fd(fd)
}

fn from_raw_fd(fd: RawFd) -> anyhow::Result<tun::AsyncDevice> {
    let mut cfg = tun::Configuration::default();
    cfg.raw_fd(fd);
    // Java detached the fd from its ParcelFileDescriptor.
    cfg.close_fd_on_drop(true);
    tun::create_as_async(&cfg).context("wrap VpnService fd as tun device")
}

//! `NetworkInterface` for Android.
//!
//! `configure_device` does not touch the interface (VpnService owns it); it stages the device
//! config so [`super::tun_fd`] can fold it into the `VpnService.Builder` call. Likewise the online
//! check and default-IP lookup defer to the OS rather than reading netlink.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use super::{staging, stats::AndroidStatsPoller};
use crate::platform::{DeviceConfig, NetworkInterface, StatsPoller};

#[derive(Default)]
pub struct AndroidNetworkInterface;

impl AndroidNetworkInterface {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInterface for AndroidNetworkInterface {
    async fn start_network_state_monitoring(&self) -> anyhow::Result<()> {
        // Real impl: register a ConnectivityManager.NetworkCallback on the Java side. Not needed for
        // the skeleton; is_online() assumes connectivity.
        Ok(())
    }

    async fn get_default_ipv4(&self) -> anyhow::Result<Ipv4Addr> {
        // The core does not bind gateway sockets to a specific source address on Android; the OS
        // picks it and VpnService.protect keeps them off the tunnel. Returning UNSPECIFIED lets the
        // transport bind 0.0.0.0.
        Ok(Ipv4Addr::UNSPECIFIED)
    }

    async fn delete_device(&self, _device_name: &str) -> anyhow::Result<()> {
        // The utun-equivalent disappears when the fd is dropped and the VpnService is stopped.
        Ok(())
    }

    async fn configure_device(&self, device_config: &DeviceConfig) -> anyhow::Result<()> {
        // Stage only; the real interface is built later by VpnService.Builder (see tun_fd).
        staging::set_device(device_config.clone());
        Ok(())
    }

    async fn replace_ip_address(
        &self,
        _device_name: &str,
        _old_address: Ipv4Net,
        new_address: Ipv4Net,
    ) -> anyhow::Result<()> {
        // Changing the office-mode address on Android means re-establishing the tunnel with a new
        // Builder. For the skeleton, restage the device address so a subsequent establish picks it up.
        let mut device = staging::snapshot().device.unwrap_or_default();
        device.address = new_address;
        staging::set_device(device);
        Ok(())
    }

    async fn new_stats_poller(&self, device_name: &str) -> anyhow::Result<impl StatsPoller + Send + Sync + 'static> {
        AndroidStatsPoller::new(device_name)
    }

    fn is_online(&self) -> bool {
        true
    }
}

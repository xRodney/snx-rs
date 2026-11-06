use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
};

use ipnet::Ipv4Net;

use super::{staging, stats::AndroidStatsPoller};
use crate::platform::{DeviceConfig, NetworkInterface, StatsPoller};

static ONLINE: AtomicBool = AtomicBool::new(true);

pub fn set_online(online: bool) {
    ONLINE.store(online, Ordering::SeqCst);
}

#[derive(Default)]
pub struct AndroidNetworkInterface;

impl AndroidNetworkInterface {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInterface for AndroidNetworkInterface {
    async fn start_network_state_monitoring(&self) -> anyhow::Result<()> {
        // The service's NetworkCallback reports through set_online.
        Ok(())
    }

    async fn get_default_ipv4(&self) -> anyhow::Result<Ipv4Addr> {
        // Protected sockets follow the underlying network, so let the kernel pick the source address.
        Ok(Ipv4Addr::UNSPECIFIED)
    }

    async fn delete_device(&self, _device_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn configure_device(&self, device_config: &DeviceConfig) -> anyhow::Result<()> {
        staging::set_device(device_config.clone());
        Ok(())
    }

    async fn replace_ip_address(
        &self,
        _device_name: &str,
        _old_address: Ipv4Net,
        new_address: Ipv4Net,
    ) -> anyhow::Result<()> {
        // An established VpnService interface cannot change its address; it applies on the next establish().
        let mut device = staging::snapshot().device.unwrap_or_default();
        device.address = new_address;
        staging::set_device(device);
        Ok(())
    }

    async fn new_stats_poller(&self, device_name: &str) -> anyhow::Result<impl StatsPoller + Send + Sync + 'static> {
        AndroidStatsPoller::new(device_name)
    }

    fn is_online(&self) -> bool {
        ONLINE.load(Ordering::SeqCst)
    }
}

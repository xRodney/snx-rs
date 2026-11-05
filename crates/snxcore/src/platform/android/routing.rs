//! `RoutingConfigurator` for Android.
//!
//! Routes are declared on `VpnService.Builder.addRoute` before `establish()`, so there is nothing to
//! apply here. `configure` stages the `RoutingConfig`; `tun_fd` turns it into the Builder's routes
//! (empty routes => `0.0.0.0/0` full tunnel). A `Cleanup` config is a no-op — stopping the service
//! drops all routing.

use async_trait::async_trait;

use super::staging;
use crate::{
    model::params::TunnelType,
    platform::{RoutingConfig, RoutingConfigurator},
};

pub struct AndroidRoutingConfigurator {
    _device: String,
    _tunnel_type: TunnelType,
}

impl AndroidRoutingConfigurator {
    pub fn new<S: AsRef<str>>(device: S, tunnel_type: TunnelType) -> Self {
        Self {
            _device: device.as_ref().to_owned(),
            _tunnel_type: tunnel_type,
        }
    }
}

#[async_trait]
impl RoutingConfigurator for AndroidRoutingConfigurator {
    async fn configure(&self, config: &RoutingConfig) -> anyhow::Result<()> {
        if !matches!(config, RoutingConfig::Cleanup { .. }) {
            staging::set_routing(config.clone());
        }
        Ok(())
    }
}

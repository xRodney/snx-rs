//! `ResolverConfigurator` for Android.
//!
//! DNS servers and search domains are set on `VpnService.Builder` (`addDnsServer`,
//! `addSearchDomain`) before `establish()`, so `configure` only stages them. Android's builder has
//! no split-DNS primitive equivalent to macOS supplemental domains; `ResolverConfig::split_dns` is
//! carried through but currently collapses to plain search domains (see docs/android-port.md).

use async_trait::async_trait;

use super::staging;
use crate::platform::{ResolverConfig, ResolverConfigurator};

pub fn new_resolver_configurator<S: AsRef<str>>(
    _device: S,
) -> anyhow::Result<Box<dyn ResolverConfigurator + Send + Sync>> {
    Ok(Box::new(AndroidResolverConfigurator))
}

pub struct AndroidResolverConfigurator;

#[async_trait]
impl ResolverConfigurator for AndroidResolverConfigurator {
    async fn configure(&self, config: &ResolverConfig) -> anyhow::Result<()> {
        staging::set_resolver(config.clone());
        Ok(())
    }

    async fn cleanup(&self, _config: &ResolverConfig) -> anyhow::Result<()> {
        // Stopping the VpnService drops its DNS; nothing to undo.
        Ok(())
    }
}

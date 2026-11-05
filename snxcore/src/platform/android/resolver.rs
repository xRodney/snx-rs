//! DNS resolver shim for Android.
//!
//! DNS servers and search domains are not applied here; they are set on `VpnService.Builder`
//! (`addDnsServer`, `addSearchDomain`) before `establish()`. `configure` stages them so the
//! Android `TunDevice` can fold them into the [`TunBuilderConfig`](super::jni_bridge::TunBuilderConfig).

use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;

use crate::platform::{ResolverConfig, ResolverConfigurator};

pub fn new_resolver_configurator<S: AsRef<str>>(_device: S) -> anyhow::Result<impl ResolverConfigurator> {
    Ok(AndroidResolverConfigurator)
}

fn staging() -> &'static Mutex<ResolverConfig> {
    static S: OnceLock<Mutex<ResolverConfig>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(ResolverConfig::default()))
}

pub(super) fn take_staged_dns() -> ResolverConfig {
    std::mem::take(&mut *staging().lock().unwrap())
}

pub struct AndroidResolverConfigurator;

#[async_trait]
impl ResolverConfigurator for AndroidResolverConfigurator {
    async fn configure(&self, config: &ResolverConfig) -> anyhow::Result<()> {
        *staging().lock().unwrap() = config.clone();
        Ok(())
    }

    async fn cleanup(&self, _config: &ResolverConfig) -> anyhow::Result<()> {
        *staging().lock().unwrap() = ResolverConfig::default();
        Ok(())
    }
}

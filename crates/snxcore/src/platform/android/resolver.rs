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
        Ok(())
    }
}

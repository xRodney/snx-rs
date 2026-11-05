use std::sync::{Mutex, OnceLock};

use crate::platform::{DeviceConfig, ResolverConfig, RoutingConfig};

#[derive(Default)]
struct Staged {
    device: Option<DeviceConfig>,
    routing: Option<RoutingConfig>,
    resolver: Option<ResolverConfig>,
}

fn staged() -> &'static Mutex<Staged> {
    static S: OnceLock<Mutex<Staged>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Staged::default()))
}

pub(super) fn set_device(config: DeviceConfig) {
    staged().lock().unwrap().device = Some(config);
}

pub(super) fn set_routing(config: RoutingConfig) {
    staged().lock().unwrap().routing = Some(config);
}

pub(super) fn set_resolver(config: ResolverConfig) {
    staged().lock().unwrap().resolver = Some(config);
}

pub(super) struct StagedSnapshot {
    pub device: Option<DeviceConfig>,
    pub routing: Option<RoutingConfig>,
    pub resolver: Option<ResolverConfig>,
}

pub(super) fn snapshot() -> StagedSnapshot {
    let s = staged().lock().unwrap();
    StagedSnapshot {
        device: s.device.clone(),
        routing: s.routing.clone(),
        resolver: s.resolver.clone(),
    }
}

pub(super) fn clear() {
    *staged().lock().unwrap() = Staged::default();
}

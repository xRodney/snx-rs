//! Config staging for the VpnService inversion.
//!
//! On desktop the core creates the TUN device and *then* applies address/MTU, routes and DNS to it.
//! On Android all of that must be declared on `VpnService.Builder` *before* `establish()` returns a
//! file descriptor — the fd arrives already configured and read-only to us.
//!
//! The three platform configurators ([`super::net`], [`super::routing`], [`super::resolver`]) do not
//! apply anything; they record their inputs here. When the tunnel finally needs the device,
//! [`super::tun_fd::adopt_from_staged`] drains this and hands the combined config to Java.
//!
//! This is process-global because the trait seam delivers the three pieces through separate objects.
//! One tunnel runs at a time inside the app sandbox, so a single slot set is sufficient; it is
//! cleared on teardown.

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

/// Snapshot taken by `tun_fd` at establish time.
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

//! Network/routing shims for Android.
//!
//! On desktop these functions run `ip route ...` to install routes after the device is up. On
//! Android routing is declarative and set on `VpnService.Builder` *before* the fd exists, so there
//! is nothing to do here at tunnel-run time. The desired routes are instead collected into the
//! [`TunBuilderConfig`](super::jni_bridge::TunBuilderConfig) that `establish_tun` consumes.
//!
//! The collection lives in a thread-local staging area because the shared SSL tunnel code calls
//! `setup_routing`/`setup_dns` on the `TunDevice` *before* it reads the fd. The Android `TunDevice`
//! (see `platform/android.rs`) drains this staging area when it finally calls `establish_tun`.

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
};

use ipnet::Ipv4Net;

static ONLINE_STATE: AtomicBool = AtomicBool::new(true);

#[derive(Debug, Default, Clone)]
pub(super) struct StagedRouting {
    pub routes: Vec<Ipv4Net>,
    pub default_route: bool,
    pub bypass: Vec<Ipv4Addr>,
}

fn staging() -> &'static Mutex<StagedRouting> {
    static S: OnceLock<Mutex<StagedRouting>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(StagedRouting::default()))
}

pub(super) fn take_staged_routing() -> StagedRouting {
    std::mem::take(&mut *staging().lock().unwrap())
}

// --- API mirrored from platform::linux::net ---

pub async fn start_network_state_monitoring() -> anyhow::Result<()> {
    // Real impl: register a ConnectivityManager.NetworkCallback on the Java side and push state
    // changes down through the bridge. For the skeleton, assume online.
    ONLINE_STATE.store(true, Ordering::SeqCst);
    Ok(())
}

pub fn is_online() -> bool {
    ONLINE_STATE.load(Ordering::SeqCst)
}

pub fn poll_online() {
    // ConnectivityManager.getActiveNetwork() != null, via the bridge. No-op in the skeleton.
}

/// On desktop this reads the default-route interface address. On Android the core does not bind to
/// a specific local address (VpnService.protect handles socket routing), so `0.0.0.0` lets the OS
/// pick. Transports must still call `jni_bridge::protect_socket` on the resulting socket.
pub async fn get_default_ip() -> anyhow::Result<String> {
    Ok("0.0.0.0".to_string())
}

pub async fn add_route(route: Ipv4Net, _device: &str, _ipaddr: Ipv4Addr) -> anyhow::Result<()> {
    staging().lock().unwrap().routes.push(route);
    Ok(())
}

pub async fn add_routes(
    routes: &[Ipv4Net],
    _device: &str,
    _ipaddr: Ipv4Addr,
    ignore_routes: &[Ipv4Net],
) -> anyhow::Result<()> {
    let mut s = staging().lock().unwrap();
    for r in routes {
        if !ignore_routes.contains(r) {
            s.routes.push(*r);
        }
    }
    Ok(())
}

/// Full-tunnel: record intent; the Java side installs `0.0.0.0/0` and excludes `ipaddr` (gateway).
pub async fn setup_default_route(_device: &str, ipaddr: Ipv4Addr) -> anyhow::Result<()> {
    let mut s = staging().lock().unwrap();
    s.default_route = true;
    s.bypass.push(ipaddr);
    Ok(())
}

pub async fn remove_default_route(_ipaddr: Ipv4Addr) -> anyhow::Result<()> {
    // Tearing down the VpnService drops all routing; nothing to undo here.
    Ok(())
}

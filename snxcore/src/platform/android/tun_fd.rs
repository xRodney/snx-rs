//! Adopting the `VpnService` file descriptor as a `tun::AsyncDevice`.
//!
//! On desktop, `tun::create_as_async` opens `/dev/net/tun` and configures the interface. An
//! unprivileged Android app can do neither: the fd is minted by `VpnService.establish()` and the
//! kernel interface is already configured (address/routes/DNS/MTU set on the Builder).
//!
//! So the Android path is: ask Java to establish the tunnel (passing the collected config), get a
//! raw fd back, and wrap it in a `tun::AsyncDevice` without touching interface configuration.
//!
//! NOTE: the exact constructor depends on the `tun` crate version. tun 0.7 exposes
//! `Configuration::raw_fd(..)`; verify against the pinned version and adjust. The shared SSL
//! tunnel code only needs `.into_framed().split()` on the returned device, so any constructor that
//! yields a valid `tun::AsyncDevice` over this fd works.

use std::os::fd::RawFd;

use anyhow::Context;

use super::jni_bridge::{self, TunBuilderConfig};

/// Build the tunnel on the Java side and wrap the returned fd.
pub fn adopt_from_vpn_service(config: &TunBuilderConfig) -> anyhow::Result<tun::AsyncDevice> {
    let fd: RawFd = jni_bridge::establish_tun(config).context("establish_tun")?;
    from_raw_fd(fd)
}

fn from_raw_fd(fd: RawFd) -> anyhow::Result<tun::AsyncDevice> {
    let mut cfg = tun::Configuration::default();
    // Adopt the existing fd rather than creating a device. With `raw_fd` set, tun 0.7 skips opening
    // `/dev/net/tun` and all interface ioctls (verified against tun-0.7.5), so we must NOT call
    // `.up()`/`.address()` — VpnService already configured the interface and those need CAP_NET_ADMIN.
    // The tun crate's Android backend *requires* raw_fd (it errors otherwise) — it is purpose-built
    // for the VpnService fd and does no interface configuration. Its PlatformConfig is a unit struct
    // (no packet_information knob); VpnService fds carry raw IP packets with no PI header.
    cfg.raw_fd(fd);
    // We detached the fd from the Java ParcelFileDescriptor, so Rust owns it and must close it on drop.
    cfg.close_fd_on_drop(true);
    let dev = tun::create_as_async(&cfg).context("wrap VpnService fd as tun device")?;
    Ok(dev)
}

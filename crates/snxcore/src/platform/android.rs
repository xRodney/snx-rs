#![allow(unsafe_code)]

//! The TUN interface belongs to Android's `VpnService`: address, routes, DNS and MTU must be given to
//! `VpnService.Builder` before `establish()` returns the fd. The configurators therefore only stage
//! their input ([`staging`]) and the device is adopted from that fd later ([`tun_fd`]).

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::{
    model::{IPsecSession, params::TunnelType},
    platform::{
        DeviceConfig, IPsecConfigurator, Keychain, NetworkInterface, PlatformAccess, PlatformFeatures,
        ResolverConfigurator, RoutingConfigurator, SingleInstance, UdpEncapType, UdpSocketExt,
    },
};

pub mod ipsec_stub;
pub mod jni_bridge;
pub mod keychain;
pub mod machine_uuid;
pub mod net;
pub mod resolver;
pub mod routing;
pub mod runner;
pub mod single_instance;
pub mod staging;
pub mod stats;
pub mod tun_fd;

pub use runner::{LoginTypeInfo, login_types, network_changed, request_stop, run_tunnel, set_online};

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_data_dir(path: PathBuf) {
    let _ = DATA_DIR.set(path);
}

// asm-generic/socket.h; the libc crate does not export it for Android targets.
const SO_NO_CHECK: libc::c_int = 11;

impl UdpSocketExt for UdpSocket {
    fn set_encapsulation(&self, _encap: UdpEncapType) -> anyhow::Result<()> {
        Ok(())
    }

    // The gateway echoes the request's checksum in keepalive replies; the kernel would drop them.
    fn set_no_check(&self, flag: bool) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        let value: libc::c_int = flag.into();
        let rc = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_NO_CHECK,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(i18n::tr!(
                "error-so-no-check-failed",
                code = std::io::Error::last_os_error()
            )))
        }
    }

    fn bind_to_tunnel(&self, _device: &str) -> anyhow::Result<()> {
        // Sockets that must bypass the tunnel are VpnService.protect()ed instead.
        Ok(())
    }

    async fn send_receive(&self, data: &[u8], timeout: Duration, target: SocketAddr) -> anyhow::Result<Vec<u8>> {
        super::udp_send_receive(self, data, timeout, target).await
    }
}

pub struct AndroidPlatformAccess;

impl PlatformAccess for AndroidPlatformAccess {
    async fn get_features(&self) -> PlatformFeatures {
        PlatformFeatures {
            ipsec_native: false,
            ipsec_keepalive: true,
            split_dns: false,
        }
    }

    fn new_resolver_configurator<S: AsRef<str>>(
        &self,
        device: S,
    ) -> anyhow::Result<Box<dyn ResolverConfigurator + Send + Sync>> {
        resolver::new_resolver_configurator(device)
    }

    fn new_keychain(&self) -> impl Keychain + Send + Sync {
        keychain::AndroidKeychain::new()
    }

    fn get_machine_uuid(&self) -> anyhow::Result<Uuid> {
        machine_uuid::get_machine_uuid()
    }

    fn check_privileges(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn init(&self) {}

    fn new_ipsec_configurator(
        &self,
        device_config: DeviceConfig,
        ipsec_session: IPsecSession,
        src_ip: Ipv4Addr,
        src_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> impl IPsecConfigurator + use<> + Send + Sync {
        ipsec_stub::AndroidIPsecStub::new(device_config, ipsec_session, src_ip, src_port, dest_ip, dest_port)
    }

    async fn new_routing_configurator<S: AsRef<str> + Send>(
        &self,
        device: S,
        tunnel_type: TunnelType,
    ) -> anyhow::Result<impl RoutingConfigurator + Send + Sync + 'static> {
        Ok(routing::AndroidRoutingConfigurator::new(device, tunnel_type))
    }

    fn new_network_interface(&self) -> impl NetworkInterface + Send + Sync + 'static {
        net::AndroidNetworkInterface::new()
    }

    fn new_single_instance<S: AsRef<str>>(&self, name: S) -> anyhow::Result<impl SingleInstance + 'static> {
        single_instance::AndroidSingleInstance::new(name)
    }

    fn trusted_library_path(&self, _path: &Path) -> Option<PathBuf> {
        None
    }

    fn data_dir(&self) -> PathBuf {
        DATA_DIR.get().cloned().unwrap_or_else(std::env::temp_dir)
    }

    async fn authorize_socket_peer(&self, _stream: &interprocess::local_socket::tokio::Stream) -> bool {
        // There is no command socket on Android: the tunnel runs inside the app's own service.
        false
    }
}

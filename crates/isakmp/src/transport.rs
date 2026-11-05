use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;

pub mod tcpt;
mod udp;

pub use tcpt::{TcptDataType, TcptTransport};
pub use udp::UdpTransport;

// =====================================================================================================
// SNX-RS ANDROID PATCH — not in upstream isakmp (https://github.com/ancwrd1/isakmp, vendored at ce07353)
// -----------------------------------------------------------------------------------------------------
// Socket hook for outgoing TCPT connections. On Android the gateway's /32 is routed into the VPN (so the
// IPsec keepalive travels inside the tunnel), so the IKE channel to the same address must be exempted
// with VpnService.protect() before it connects. snxcore's Android runner installs the hook; it is unset
// everywhere else, where connect_tcp behaves exactly like TcpStream::connect.
// Touches: this block, and the `connect_tcp` call in transport/tcpt.rs (marked the same way).
// Candidate for an upstream PR to isakmp; drop the vendored copy once it lands.
// =====================================================================================================

/// Called with the raw socket of every outgoing connection before it connects.
pub type SocketHook = Arc<dyn Fn(i32) -> anyhow::Result<()> + Send + Sync>;

static SOCKET_HOOK: RwLock<Option<SocketHook>> = RwLock::new(None);

pub fn set_socket_hook(hook: Option<SocketHook>) {
    *SOCKET_HOOK.write().unwrap_or_else(|e| e.into_inner()) = hook;
}

pub async fn connect_tcp(address: SocketAddr) -> anyhow::Result<tokio::net::TcpStream> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    #[cfg(unix)]
    if let Some(hook) = SOCKET_HOOK.read().unwrap_or_else(|e| e.into_inner()).clone() {
        use std::os::fd::AsRawFd;
        hook(socket.as_raw_fd())?;
    }

    Ok(socket.connect(address).await?)
}

// ===================================== END SNX-RS ANDROID PATCH ======================================

/// A received message that may carry a fatal error notification. Each IKE
/// version decides which notifies abort the exchange, so the transport calls
/// through this rather than inspecting payloads itself.
pub trait CheckInformational {
    fn check_informational(&self) -> anyhow::Result<()>;
}

/// What a transport requires of the messages it carries.
pub trait TransportMessage: CheckInformational + fmt::Debug + Send + Sync {}

impl<T> TransportMessage for T where T: CheckInformational + fmt::Debug + Send + Sync {}

#[async_trait]
pub trait IsakmpTransport<M> {
    async fn send(&mut self, message: &M) -> anyhow::Result<()>;

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<M>;

    async fn send_receive(&mut self, message: &M, timeout: Duration) -> anyhow::Result<M>
    where
        M: Sync,
    {
        self.send(message).await?;
        self.receive(timeout).await
    }

    /// Keeps an idle IKE channel open from now on. Off until the IKE SA is established: a gateway may drop
    /// a negotiation that receives a NAT-keepalive while it waits for the user to log in (snx-rs#279).
    fn enable_keepalive(&mut self) {}

    fn disconnect(&mut self);
}

//! Drives a connection on Android, mirroring the desktop standalone flow in apps/snx-rs but without
//! any interactive prompts: the password and any MFA code come from [`TunnelParams`], and
//! identity-provider (SSO) login opens the browser through the VpnService. Other interactive factors
//! are rejected for now.
//!
//! Once the tunnel has been up, losing it (keepalive failure, or the service reporting a switch of
//! the underlying network) is not fatal: the runner waits for connectivity and reconnects, resuming
//! the saved IKE session when `ike-persist` is on so that no new sign-in is needed.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::bail;
use secrecy::ExposeSecret;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, info, warn};

use crate::{
    model::{MfaType, SessionState, params::TunnelParams},
    otp::OtpListener,
    platform::{NetworkInterface, Platform, PlatformAccess},
    tunnel::{
        TunnelCommand, TunnelConnector, TunnelConnectorFactory, TunnelEvent, connector::CheckPointConnectorFactory,
        ipsec::SessionStore,
    },
};

const MAX_RECONNECT_ATTEMPTS: u32 = 10;
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const EVENTS_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Control {
    running: AtomicBool,
    stop: AtomicBool,
    commands: Mutex<Option<mpsc::Sender<TunnelCommand>>>,
    wake: Notify,
}

fn control() -> &'static Control {
    static CONTROL: std::sync::OnceLock<Control> = std::sync::OnceLock::new();
    CONTROL.get_or_init(Control::default)
}

impl Control {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn send(&self, command: TunnelCommand) {
        if let Some(tx) = self.commands.lock().unwrap().as_ref() {
            let _ = tx.try_send(command);
        }
    }

    /// Returns when `ready()` holds, the stop flag is set, or `timeout` elapses (if given).
    async fn wait_until(&self, ready: impl Fn() -> bool, timeout: Option<Duration>) {
        let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if ready() || self.stopped() {
                return;
            }
            match deadline {
                Some(deadline) => {
                    if tokio::time::timeout_at(deadline, notified).await.is_err() {
                        return;
                    }
                }
                None => notified.await,
            }
        }
    }
}

/// User-initiated disconnect: cancels a pending sign-in or reconnect wait, stops the tunnel and
/// forgets the saved IKE session.
pub fn request_stop() {
    let ctl = control();
    ctl.stop.store(true, Ordering::SeqCst);
    ctl.wake.notify_waiters();
    ctl.send(TunnelCommand::Terminate(true));
}

/// The underlying network changed: drop the tunnel so the runner rebuilds it over the new network.
pub fn network_changed() {
    let ctl = control();
    info!("Underlying network changed, restarting the tunnel");
    ctl.send(TunnelCommand::Terminate(false));
    ctl.wake.notify_waiters();
}

pub fn set_online(online: bool) {
    super::net::set_online(online);
    if online {
        control().wake.notify_waiters();
    }
}

fn is_online() -> bool {
    Platform::get().new_network_interface().is_online()
}

/// Authenticate and run the tunnel until [`request_stop`], reconnecting after the tunnel is lost.
/// Fails without retrying if the first connection attempt fails.
pub async fn run_tunnel(params: Arc<TunnelParams>) -> anyhow::Result<()> {
    let ctl = control();
    if ctl.running.swap(true, Ordering::SeqCst) {
        bail!(i18n::tr!("error-connection-in-progress"));
    }
    ctl.stop.store(false, Ordering::SeqCst);
    isakmp::transport::set_socket_hook(Some(Arc::new(super::jni_bridge::protect_socket)));

    let result = run_with_reconnect(params.clone()).await;

    if ctl.stopped()
        && params.ike_persist
        && let Err(e) = SessionStore::delete_all(params.profile_id, &params.server_name)
    {
        warn!("Cannot delete the saved IKE session: {e}");
    }
    isakmp::transport::set_socket_hook(None);
    ctl.running.store(false, Ordering::SeqCst);
    result
}

async fn run_with_reconnect(params: Arc<TunnelParams>) -> anyhow::Result<()> {
    let ctl = control();
    let mut ever_connected = false;
    let mut attempt = 0;

    loop {
        let connected = Arc::new(AtomicBool::new(false));
        let result = run_once(params.clone(), connected.clone()).await;
        *ctl.commands.lock().unwrap() = None;

        if ctl.stopped() {
            return Ok(());
        }
        if connected.load(Ordering::SeqCst) {
            ever_connected = true;
            attempt = 0;
        }
        if !ever_connected {
            return result;
        }

        attempt += 1;
        if attempt > MAX_RECONNECT_ATTEMPTS {
            return result;
        }
        match &result {
            Ok(()) => info!("Tunnel stopped, reconnecting"),
            Err(e) => warn!("Tunnel lost: {e:#}; reconnecting (attempt {attempt})"),
        }
        let _ = super::jni_bridge::reconnecting();

        ctl.wait_until(is_online, None).await;
        if attempt > 1 {
            let delay = Duration::from_secs(1 << (attempt - 1).min(5)).min(MAX_RECONNECT_DELAY);
            ctl.wait_until(|| false, Some(delay)).await;
        }
        if ctl.stopped() {
            return Ok(());
        }
    }
}

async fn run_once(params: Arc<TunnelParams>, connected: Arc<AtomicBool>) -> anyhow::Result<()> {
    let factory = CheckPointConnectorFactory::default();

    let (mut connector, session) = tokio::select! {
        result = login(&factory, params.clone()) => result?,
        () = control().wait_until(|| false, None) => bail!(i18n::tr!("error-connection-cancelled")),
    };

    let (command_sender, command_receiver) = mpsc::channel(16);
    let mut tunnel = connector.create_tunnel(session, command_sender.clone()).await?;
    *control().commands.lock().unwrap() = Some(command_sender);
    if control().stopped() {
        return Ok(());
    }

    if let Err(e) = Platform::get()
        .new_network_interface()
        .start_network_state_monitoring()
        .await
    {
        warn!("Unable to start network monitoring: {e}");
    }

    let (event_sender, mut event_receiver) = mpsc::channel::<TunnelEvent>(16);

    let events = tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            let _ = connector
                .handle_tunnel_event(event.clone())
                .await
                .inspect_err(|e| warn!("{e}"));
            match event {
                TunnelEvent::Connected(_) => {
                    debug!("Android tunnel connected");
                    connected.store(true, Ordering::SeqCst);
                }
                TunnelEvent::Disconnected => break,
                _ => {}
            }
        }
    });

    let result = tunnel.run(command_receiver, event_sender).await;
    debug!("Android tunnel stopped");
    // Background tunnel tasks keep event senders alive, so without a Disconnected event the loop never ends.
    let abort = events.abort_handle();
    if tokio::time::timeout(EVENTS_DRAIN_TIMEOUT, events).await.is_err() {
        warn!("Tunnel event handling did not finish, abandoning it");
        abort.abort();
    }
    result
}

async fn login(
    factory: &CheckPointConnectorFactory,
    params: Arc<TunnelParams>,
) -> anyhow::Result<(Box<dyn TunnelConnector + Send + Sync>, Arc<crate::model::TunnelSession>)> {
    let gateway = factory.new_gateway_connector(params.clone());
    let info = gateway.get_gateway_information().await?;
    if !info.is_supported_login_type(&params.login_type) {
        bail!(i18n::tr!("error-unsupported-login-type"));
    }

    let mut connector = factory.new_tunnel_connector(params.clone()).await?;

    if params.ike_persist {
        match connector.restore_session().await {
            Ok(session) => {
                info!("Resumed the saved IKE session");
                return Ok((connector, session));
            }
            Err(e) => debug!("No saved IKE session to resume: {e}"),
        }
    }

    let mut session = connector.authenticate().await?;

    let mut mfa_index = 0;
    while let SessionState::PendingChallenge(challenge) = session.state.clone() {
        match challenge.mfa_type {
            MfaType::PasswordInput => {
                mfa_index += 1;
                let input = if !params.password.expose_secret().is_empty() && mfa_index == params.password_factor {
                    params.password.expose_secret().to_owned()
                } else if let Some(ref code) = params.mfa_code {
                    code.clone()
                } else {
                    bail!(i18n::tr!(
                        "error-interactive-mfa-unsupported",
                        prompt = challenge.prompt
                    ));
                };
                session = connector.challenge_code(session, &input).await?;
            }
            MfaType::IdentityProvider => {
                let listener = OtpListener::new().await?;
                super::jni_bridge::open_url(&challenge.prompt)?;
                let otp = listener.acquire_otp().await?;
                session = connector.challenge_code(session, &otp).await?;
            }
            other => bail!(i18n::tr!(
                "error-unsupported-auth-factor",
                factor = format!("{other:?}")
            )),
        }
    }

    Ok((connector, session))
}

pub struct LoginTypeInfo {
    pub id: String,
    pub display_name: String,
    pub factors: String,
}

/// The login types the gateway offers, as `snx-rs -m info` lists them.
pub async fn login_types(params: Arc<TunnelParams>) -> anyhow::Result<Vec<LoginTypeInfo>> {
    let info = CheckPointConnectorFactory::default()
        .new_gateway_connector(params)
        .get_gateway_information()
        .await?;

    let mut options = info
        .login_options_data
        .map(|data| data.login_options_list)
        .unwrap_or_default();
    if options.is_empty() {
        options.insert(String::new(), crate::model::proto::LoginOption::unspecified());
    }

    Ok(options
        .into_values()
        .filter(|opt| opt.show_realm != 0)
        .map(|opt| LoginTypeInfo {
            factors: opt
                .factors
                .into_values()
                .map(|f| f.factor_type)
                .collect::<Vec<_>>()
                .join(", "),
            id: opt.id,
            display_name: opt.display_name,
        })
        .collect())
}

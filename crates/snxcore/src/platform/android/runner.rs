//! Drives a connection on Android, mirroring the desktop standalone flow in apps/snx-rs but without
//! any interactive prompts: the password and any MFA code come from [`TunnelParams`], and
//! identity-provider (SSO) login opens the browser through the VpnService. Other interactive factors
//! are rejected for now.

use std::sync::Arc;

use anyhow::bail;
use secrecy::ExposeSecret;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{
    model::{MfaType, SessionState, params::TunnelParams},
    otp::OtpListener,
    platform::{NetworkInterface, Platform, PlatformAccess},
    tunnel::{TunnelCommand, TunnelConnectorFactory, TunnelEvent, connector::CheckPointConnectorFactory},
};

/// Authenticate and run the tunnel until a `Terminate` command or a fatal error. The caller owns both
/// ends of the command channel: `command_sender` is handed to the tunnel (and kept for rekey), while
/// `command_receiver` is what `Terminate` is delivered on from `nativeDisconnect`.
pub async fn run_tunnel(
    params: Arc<TunnelParams>,
    command_sender: mpsc::Sender<TunnelCommand>,
    command_receiver: mpsc::Receiver<TunnelCommand>,
) -> anyhow::Result<()> {
    let factory = CheckPointConnectorFactory::default();

    let gateway = factory.new_gateway_connector(params.clone());
    let info = gateway.get_gateway_information().await?;
    if !info.is_supported_login_type(&params.login_type) {
        bail!(i18n::tr!("error-unsupported-login-type"));
    }

    let mut connector = factory.new_tunnel_connector(params.clone()).await?;
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
                    bail!("Interactive MFA is not supported on Android yet: {}", challenge.prompt);
                };
                session = connector.challenge_code(session, &input).await?;
            }
            MfaType::IdentityProvider => {
                // Same flow as the desktop: the gateway's SSO page hands the OTP to a listener on
                // 127.0.0.1:7779, which the phone's browser reaches since it shares the loopback.
                let listener = OtpListener::new().await?;
                super::jni_bridge::open_url(&challenge.prompt)?;
                let otp = listener.acquire_otp().await?;
                session = connector.challenge_code(session, &otp).await?;
            }
            other => bail!("Unsupported authentication factor on Android: {other:?}"),
        }
    }

    let mut tunnel = connector.create_tunnel(session, command_sender).await?;

    if let Err(e) = Platform::get()
        .new_network_interface()
        .start_network_state_monitoring()
        .await
    {
        warn!("Unable to start network monitoring: {e}");
    }

    let (event_sender, mut event_receiver) = mpsc::channel::<TunnelEvent>(16);

    tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            let _ = connector
                .handle_tunnel_event(event.clone())
                .await
                .inspect_err(|e| warn!("{e}"));
            match event {
                TunnelEvent::Connected(_) => debug!("Android tunnel connected"),
                TunnelEvent::Disconnected => break,
                _ => {}
            }
        }
    });

    tunnel.run(command_receiver, event_sender).await?;
    debug!("Android tunnel stopped");
    Ok(())
}

/// A login type offered by the gateway, as `snx-rs -m info` lists it.
pub struct LoginTypeInfo {
    pub id: String,
    pub display_name: String,
    pub factors: String,
}

/// Queries the gateway for the login types it offers (HTTPS only, no tunnel).
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

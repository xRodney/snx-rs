use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use tracing::debug;
#[cfg(not(target_os = "android"))]
use tun::AbstractDevice;

#[cfg(not(target_os = "android"))]
pub struct TunDevice {
    inner: Arc<tun::AsyncDevice>,
    dev_name: String,
}

#[cfg(not(target_os = "android"))]
impl TunDevice {
    pub fn new(name: &str) -> anyhow::Result<Self> {
        let mut config = tun::Configuration::default();

        // macOS utun devices must be named `utunN`; the custom hint is rejected, so let the
        // kernel assign a name (read back below). Linux/Windows keep honoring the hint.
        #[cfg(not(target_os = "macos"))]
        config.tun_name(name).up();
        #[cfg(target_os = "macos")]
        {
            let _ = name;
            config.up();
        }

        let dev = tun::create_as_async(&config)?;

        let dev_name = dev.tun_name()?;

        debug!("Created tun device: {dev_name}");

        Ok(Self {
            inner: Arc::new(dev),
            dev_name,
        })
    }

    pub fn name(&self) -> &str {
        &self.dev_name
    }

    pub fn inner(&self) -> Arc<tun::AsyncDevice> {
        self.inner.clone()
    }
}

// Android: the device is not created here — it is adopted from the VpnService fd, which only exists
// after addresses/routes/DNS have been declared on VpnService.Builder. So `new` stores just the name
// hint, and `inner` lazily establishes the tunnel from the staged config on first use. Callers MUST
// therefore call `inner()` only after configure_device + routing + DNS have been staged (the IPsec
// userspace path is ordered to do exactly that).
#[cfg(target_os = "android")]
pub struct TunDevice {
    inner: std::sync::Mutex<Option<Arc<tun::AsyncDevice>>>,
    dev_name: String,
}

#[cfg(target_os = "android")]
impl TunDevice {
    pub fn new(name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            inner: std::sync::Mutex::new(None),
            dev_name: name.to_owned(),
        })
    }

    pub fn name(&self) -> &str {
        &self.dev_name
    }

    pub fn inner(&self) -> Arc<tun::AsyncDevice> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dev) = guard.as_ref() {
            return dev.clone();
        }
        // Establishment can fail (no VpnService handle, Builder error). The call sites treat the
        // returned device as infallible, so surface failures as a panic with context; a production
        // build should instead restructure the path to establish fallibly before the pump starts.
        let dev = Arc::new(
            crate::platform::android::tun_fd::adopt_from_staged()
                .expect("failed to establish VpnService tunnel from staged config"),
        );
        *guard = Some(dev.clone());
        dev
    }
}

//! `StatsPoller` for Android.
//!
//! Android is a Linux kernel, so `/sys/class/net/<iface>/statistics/*` holds the counters. The catch
//! is the interface name: the VpnService tunnel is named by the OS (typically `tun0`), not by our
//! `if_name` hint, so a production poller should resolve the real name from the established fd
//! (e.g. `TUNGETIFF`) rather than trusting `device_name`. The skeleton reads by the given name when
//! it exists and otherwise returns zeroes.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::{model::LiveStats, platform::StatsPoller};

pub struct AndroidStatsPoller {
    device_name: String,
    prev_rx: AtomicU64,
    prev_tx: AtomicU64,
}

impl AndroidStatsPoller {
    pub fn new(device_name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            device_name: device_name.to_owned(),
            prev_rx: AtomicU64::new(0),
            prev_tx: AtomicU64::new(0),
        })
    }

    fn read_counter(&self, which: &str) -> Option<u64> {
        let path = format!("/sys/class/net/{}/statistics/{which}", self.device_name);
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }
}

#[async_trait]
impl StatsPoller for AndroidStatsPoller {
    async fn poll(&self) -> anyhow::Result<LiveStats> {
        let bytes_rx = self.read_counter("rx_bytes").unwrap_or(0);
        let bytes_tx = self.read_counter("tx_bytes").unwrap_or(0);

        // bps left at 0 in the skeleton; a real poller would delta against the previous sample and
        // the elapsed time, as the macOS poller does.
        self.prev_rx.store(bytes_rx, Ordering::Relaxed);
        self.prev_tx.store(bytes_tx, Ordering::Relaxed);

        Ok(LiveStats {
            bytes_rx,
            bytes_tx,
            packets_rx: self.read_counter("rx_packets").unwrap_or(0),
            packets_tx: self.read_counter("tx_packets").unwrap_or(0),
            errors_rx: self.read_counter("rx_errors").unwrap_or(0),
            errors_tx: self.read_counter("tx_errors").unwrap_or(0),
            ..Default::default()
        })
    }
}

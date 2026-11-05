use async_trait::async_trait;

use crate::{model::LiveStats, platform::StatsPoller};

pub struct AndroidStatsPoller {
    device_name: String,
}

impl AndroidStatsPoller {
    pub fn new(device_name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            device_name: device_name.to_owned(),
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
        Ok(LiveStats {
            bytes_rx: self.read_counter("rx_bytes").unwrap_or(0),
            bytes_tx: self.read_counter("tx_bytes").unwrap_or(0),
            packets_rx: self.read_counter("rx_packets").unwrap_or(0),
            packets_tx: self.read_counter("tx_packets").unwrap_or(0),
            errors_rx: self.read_counter("rx_errors").unwrap_or(0),
            errors_tx: self.read_counter("tx_errors").unwrap_or(0),
            ..Default::default()
        })
    }
}

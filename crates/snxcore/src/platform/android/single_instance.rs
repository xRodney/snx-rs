//! Single-instance guard. Inside one Android app sandbox only one `VpnService` runs at a time, so
//! this is always the single instance; the service lifecycle enforces it.

use crate::platform::SingleInstance;

pub struct AndroidSingleInstance;

impl AndroidSingleInstance {
    pub fn new<N: AsRef<str>>(_name: N) -> anyhow::Result<Self> {
        Ok(Self)
    }
}

impl SingleInstance for AndroidSingleInstance {
    fn is_single(&self) -> bool {
        true
    }
}

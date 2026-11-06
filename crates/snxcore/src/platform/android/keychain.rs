use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::jni_bridge;
use crate::platform::Keychain;

const PREFIX: &str = "snx-rs.password";

fn key_for(profile_id: Uuid) -> String {
    format!("{PREFIX}.{profile_id}")
}

#[derive(Default)]
pub struct AndroidKeychain;

impl AndroidKeychain {
    pub fn new() -> Self {
        Self
    }
}

impl Keychain for AndroidKeychain {
    async fn acquire_password(&self, profile_id: Uuid) -> anyhow::Result<String> {
        jni_bridge::keystore_get(&key_for(profile_id))?
            .ok_or_else(|| anyhow::anyhow!("No stored password for profile {profile_id}"))
    }

    async fn store_password(&self, profile_id: Uuid, password: &SecretString) -> anyhow::Result<()> {
        jni_bridge::keystore_set(&key_for(profile_id), password.expose_secret())
    }

    async fn delete_password(&self, profile_id: Uuid) -> anyhow::Result<()> {
        jni_bridge::keystore_delete(&key_for(profile_id))
    }
}

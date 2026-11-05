//! Password storage backed by the Android Keystore / `EncryptedSharedPreferences`, reached through
//! the [`jni_bridge`](super::jni_bridge). Mirrors the `acquire_password`/`store_password` free
//! functions that `platform/linux.rs` implements against the Secret Service.

use super::jni_bridge;

fn key_for(user_name: &str) -> String {
    format!("snx-rs.password.{user_name}")
}

pub async fn acquire_password(user_name: &str) -> anyhow::Result<String> {
    jni_bridge::keystore_get(&key_for(user_name))?
        .ok_or_else(|| anyhow::anyhow!("No stored password for {user_name}"))
}

pub async fn store_password(user_name: &str, password: &str) -> anyhow::Result<()> {
    jni_bridge::keystore_set(&key_for(user_name), password)
}

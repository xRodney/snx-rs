use uuid::Uuid;

use super::jni_bridge;

pub fn get_machine_uuid() -> anyhow::Result<Uuid> {
    jni_bridge::machine_uuid()
}

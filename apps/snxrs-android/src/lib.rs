//! JNI wrapper that exports `libsnxrs.so` for the Android app.
//!
//! On Android this provides the `nativeConnect`/`nativeDisconnect` entry points the Kotlin
//! `VpnClientService` binds, a concrete [`VpnServiceHandle`](snxcore::platform::android::jni_bridge::VpnServiceHandle)
//! that calls back into the service, and a tokio runtime that drives the tunnel. On any other target
//! the crate is empty.
//!
//! NOTE: this file can only be compiled for an Android target (it depends on `snxcore::platform::android`,
//! which is `cfg(target_os = "android")`), so it has not been compiled in the dev container that lacks
//! the NDK. Expect to iterate on the `jni` 0.21 calls when first building with cargo-ndk.

#![allow(unsafe_code)]

#[cfg(target_os = "android")]
mod android {
    use std::{
        os::fd::RawFd,
        sync::{Mutex, OnceLock},
    };

    use jni::{
        JNIEnv, JavaVM,
        objects::{GlobalRef, JObject, JString, JValue},
        sys::{jboolean, jint, jstring},
    };
    use secrecy::SecretString;
    use serde::{Deserialize, Serialize};
    use snxcore::{
        model::params::{TunnelParams, TunnelType},
        platform::android::jni_bridge::{self, TunBuilderConfig, VpnServiceHandle},
        tunnel::TunnelCommand,
    };
    use tokio::sync::mpsc;
    use tracing::{error, info};

    /// Config the app passes to `nativeConnect` as JSON. Only the fields a minimal client needs; the
    /// rest fall back to `TunnelParams::default()`.
    #[derive(Debug, Default, Deserialize)]
    struct AndroidConfig {
        server_name: String,
        login_type: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        mfa_code: Option<String>,
        #[serde(default)]
        tunnel_type: Option<String>,
        #[serde(default)]
        ignore_server_cert: bool,
    }

    /// What `establishTun` receives as JSON on the Java side.
    #[derive(Serialize)]
    struct TunSpec {
        address: String,
        prefix: u8,
        mtu: u16,
        routes: Vec<String>,
        dns_servers: Vec<String>,
        search_domains: Vec<String>,
    }

    fn runtime() -> &'static tokio::runtime::Runtime {
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime")
        })
    }

    fn command_tx() -> &'static Mutex<Option<mpsc::Sender<TunnelCommand>>> {
        static TX: OnceLock<Mutex<Option<mpsc::Sender<TunnelCommand>>>> = OnceLock::new();
        TX.get_or_init(|| Mutex::new(None))
    }

    struct AndroidVpnServiceHandle {
        vm: JavaVM,
        service: GlobalRef,
    }

    impl AndroidVpnServiceHandle {
        fn call_string_ret_string(&self, method: &str, arg: &str) -> anyhow::Result<Option<String>> {
            let mut env = self.vm.attach_current_thread()?;
            let jarg = env.new_string(arg)?;
            let ret = env.call_method(
                &self.service,
                method,
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&jarg)],
            )?;
            let obj = ret.l()?;
            if obj.is_null() {
                Ok(None)
            } else {
                let s: String = env.get_string(&JString::from(obj))?.into();
                Ok(Some(s))
            }
        }
    }

    impl VpnServiceHandle for AndroidVpnServiceHandle {
        fn establish_tun(&self, config: &TunBuilderConfig) -> anyhow::Result<RawFd> {
            let spec = TunSpec {
                address: config.address.addr().to_string(),
                prefix: config.address.prefix_len(),
                mtu: config.mtu,
                routes: config.routes.iter().map(|r| r.to_string()).collect(),
                dns_servers: config.dns_servers.iter().map(|d| d.to_string()).collect(),
                search_domains: config.search_domains.clone(),
            };
            let json = serde_json::to_string(&spec)?;

            let mut env = self.vm.attach_current_thread()?;
            let jjson = env.new_string(&json)?;
            let ret = env.call_method(
                &self.service,
                "establishTun",
                "(Ljava/lang/String;)I",
                &[JValue::Object(&jjson)],
            )?;
            let fd = ret.i()?;
            if fd < 0 {
                anyhow::bail!("VpnService.establishTun returned {fd}");
            }
            Ok(fd as RawFd)
        }

        fn protect_socket(&self, fd: RawFd) -> anyhow::Result<()> {
            let mut env = self.vm.attach_current_thread()?;
            let ret = env.call_method(&self.service, "protectSocket", "(I)Z", &[JValue::Int(fd)])?;
            if ret.z()? {
                Ok(())
            } else {
                anyhow::bail!("VpnService.protect({fd}) failed")
            }
        }

        fn android_id(&self) -> anyhow::Result<String> {
            let mut env = self.vm.attach_current_thread()?;
            let ret = env.call_method(&self.service, "androidId", "()Ljava/lang/String;", &[])?;
            Ok(env.get_string(&JString::from(ret.l()?))?.into())
        }

        fn keystore_get(&self, key: &str) -> anyhow::Result<Option<String>> {
            self.call_string_ret_string("keystoreGet", key)
        }

        fn keystore_set(&self, key: &str, value: &str) -> anyhow::Result<()> {
            let mut env = self.vm.attach_current_thread()?;
            let jkey = env.new_string(key)?;
            let jval = env.new_string(value)?;
            env.call_method(
                &self.service,
                "keystoreSet",
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[JValue::Object(&jkey), JValue::Object(&jval)],
            )?;
            Ok(())
        }

        fn open_url(&self, url: &str) -> anyhow::Result<()> {
            let mut env = self.vm.attach_current_thread()?;
            let jurl = env.new_string(url)?;
            env.call_method(
                &self.service,
                "openUrl",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&jurl)],
            )?;
            Ok(())
        }

        fn keystore_delete(&self, key: &str) -> anyhow::Result<()> {
            let mut env = self.vm.attach_current_thread()?;
            let jkey = env.new_string(key)?;
            env.call_method(
                &self.service,
                "keystoreDelete",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&jkey)],
            )?;
            Ok(())
        }
    }

    fn build_params(cfg: AndroidConfig) -> TunnelParams {
        let mut params = TunnelParams::default();
        params.server_name = cfg.server_name;
        params.login_type = cfg.login_type;
        params.user_name = cfg.user_name;
        params.password = SecretString::from(cfg.password);
        params.mfa_code = cfg.mfa_code;
        params.ignore_server_cert = cfg.ignore_server_cert;
        params.tunnel_type = match cfg.tunnel_type.as_deref() {
            Some("ssl") => TunnelType::SSL,
            _ => TunnelType::IPsec,
        };
        params
    }

    fn init_logging() {
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Debug)
                    .with_tag("snx-rs"),
            );
        });
    }

    fn connect(env: &mut JNIEnv, service: &JObject, config_json: JString) -> anyhow::Result<()> {
        let json: String = env.get_string(&config_json)?.into();
        let cfg: AndroidConfig = serde_json::from_str(&json)?;
        let params = std::sync::Arc::new(build_params(cfg));

        let vm = env.get_java_vm()?;
        let service = env.new_global_ref(service)?;
        jni_bridge::set_handle(Box::new(AndroidVpnServiceHandle { vm, service }));

        let (tx, rx) = mpsc::channel(16);
        *command_tx().lock().unwrap() = Some(tx.clone());

        // Blocks this (dedicated Java) thread until the tunnel stops.
        let result = runtime().block_on(snxcore::platform::android::run_tunnel(params, tx, rx));

        *command_tx().lock().unwrap() = None;
        jni_bridge::clear_handle();
        result
    }

    #[derive(Serialize)]
    struct LoginTypeJson {
        id: String,
        name: String,
        factors: String,
    }

    fn login_types_json(env: &mut JNIEnv, server: JString, ignore_cert: bool) -> anyhow::Result<String> {
        let mut params = TunnelParams::default();
        params.server_name = env.get_string(&server)?.into();
        params.ignore_server_cert = ignore_cert;
        let types = runtime().block_on(snxcore::platform::android::login_types(std::sync::Arc::new(params)))?;
        let out: Vec<LoginTypeJson> = types
            .into_iter()
            .map(|t| LoginTypeJson {
                id: t.id,
                name: t.display_name,
                factors: t.factors,
            })
            .collect();
        Ok(serde_json::to_string(&out)?)
    }

    /// Instance method `MainActivity.nativeLoginTypes(server: String, ignoreCert: Boolean): String`.
    /// Returns a JSON array of `{id, name, factors}`, or `{"error": "..."}`. Blocks; call off the UI thread.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_MainActivity_nativeLoginTypes(
        mut env: JNIEnv,
        _activity: JObject,
        server: JString,
        ignore_cert: jboolean,
    ) -> jstring {
        init_logging();
        let json = login_types_json(&mut env, server, ignore_cert != 0).unwrap_or_else(|e| {
            error!("Fetching login types failed: {e:#}");
            serde_json::json!({ "error": format!("{e:#}") }).to_string()
        });
        env.new_string(json)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }

    /// Instance method `private external fun nativeConnect(configJson: String): Int` — the second JNI
    /// argument is the `VpnClientService` receiver (`this`).
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeConnect(
        mut env: JNIEnv,
        service: JObject,
        config_json: JString,
    ) -> jint {
        init_logging();
        match connect(&mut env, &service, config_json) {
            Ok(()) => 0,
            Err(e) => {
                error!("Connection failed: {e:#}");
                1
            }
        }
    }

    /// Instance method `private external fun nativeDisconnect()`.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeDisconnect(_env: JNIEnv, _service: JObject) {
        if let Some(tx) = command_tx().lock().unwrap().take() {
            info!("Disconnect requested");
            let _ = tx.blocking_send(TunnelCommand::Terminate(true));
        }
    }
}

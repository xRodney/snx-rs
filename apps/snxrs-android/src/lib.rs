//! JNI wrapper that exports `libsnxrs.so` for the Android app.
//!
//! On Android this provides the `nativeConnect`/`nativeDisconnect` entry points the Kotlin
//! `VpnClientService` binds, a concrete [`VpnServiceHandle`](snxcore::platform::android::jni_bridge::VpnServiceHandle)
//! that calls back into the service, and a tokio runtime that drives the tunnel. On any other target
//! the crate is empty.

#![allow(unsafe_code)]

#[cfg(target_os = "android")]
mod android {
    use std::{os::fd::RawFd, path::PathBuf, sync::OnceLock};

    use jni::{
        JNIEnv, JavaVM,
        objects::{GlobalRef, JObject, JString, JValue},
        sys::{jboolean, jstring},
    };
    use serde::Serialize;
    use snxcore::{
        model::params::TunnelParams,
        platform::android::{
            self,
            jni_bridge::{self, TunBuilderConfig, VpnServiceHandle},
        },
    };
    use tracing::{error, info};

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

        fn reconnecting(&self) -> anyhow::Result<()> {
            let mut env = self.vm.attach_current_thread()?;
            env.call_method(&self.service, "onReconnecting", "()V", &[])?;
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

    /// Profile text in the desktop config-file format, parsed by the same code as `snx-rs.conf`.
    fn parse_profile(env: &mut JNIEnv, config: &JString) -> anyhow::Result<TunnelParams> {
        let text: String = env.get_string(config)?.into();
        let mut params = TunnelParams::parse(text)?;
        runtime().block_on(params.load_cert_data())?;
        Ok(params)
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

    fn connect(env: &mut JNIEnv, service: &JObject, config: JString, files_dir: JString) -> anyhow::Result<()> {
        let files_dir: String = env.get_string(&files_dir)?.into();
        android::set_data_dir(PathBuf::from(files_dir));
        let params = std::sync::Arc::new(parse_profile(env, &config)?);

        let vm = env.get_java_vm()?;
        let service = env.new_global_ref(service)?;
        jni_bridge::set_handle(Box::new(AndroidVpnServiceHandle { vm, service }));

        // Blocks this (dedicated Java) thread until the tunnel stops.
        let result = runtime().block_on(android::run_tunnel(params));

        jni_bridge::clear_handle();
        result
    }

    #[derive(Serialize)]
    struct LoginTypeJson {
        id: String,
        name: String,
        factors: String,
    }

    fn login_types_json(env: &mut JNIEnv, config: JString) -> anyhow::Result<String> {
        let params = parse_profile(env, &config)?;
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

    /// `Native.loginTypes(config: String): String` (static) — profile text in config-file format.
    /// Returns a JSON array of `{id, name, factors}`, or `{"error": "..."}`. Blocks; call off the UI thread.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_Native_loginTypes(
        mut env: JNIEnv,
        _class: jni::objects::JClass,
        config: JString,
    ) -> jstring {
        init_logging();
        let json = login_types_json(&mut env, config).unwrap_or_else(|e| {
            error!("Fetching login types failed: {e:#}");
            serde_json::json!({ "error": format!("{e:#}") }).to_string()
        });
        env.new_string(json)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }

    /// Instance method `private external fun nativeConnect(config: String, filesDir: String): String` —
    /// the second JNI argument is the `VpnClientService` receiver (`this`). Blocks across reconnects;
    /// returns "" on a clean stop, else the error.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeConnect(
        mut env: JNIEnv,
        service: JObject,
        config: JString,
        files_dir: JString,
    ) -> jstring {
        init_logging();
        let message = match connect(&mut env, &service, config, files_dir) {
            Ok(()) => String::new(),
            Err(e) => {
                error!("Connection failed: {e:#}");
                format!("{e:#}")
            }
        };
        env.new_string(message)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }

    /// Instance method `private external fun nativeDisconnect()`.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeDisconnect(_env: JNIEnv, _service: JObject) {
        info!("Disconnect requested");
        android::request_stop();
    }

    /// Instance method `private external fun nativeSetOnline(online: Boolean)`.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeSetOnline(
        _env: JNIEnv,
        _service: JObject,
        online: jboolean,
    ) {
        android::set_online(online != 0);
    }

    /// Instance method `private external fun nativeNetworkChanged()`.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_net_pankratov_snxrs_VpnClientService_nativeNetworkChanged(
        _env: JNIEnv,
        _service: JObject,
    ) {
        android::network_changed();
    }
}

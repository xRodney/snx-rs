# Android port — skeleton and design notes (v6.x)

Status: **skeleton.** The `crates/snxcore/src/platform/android/` module implements the full
`PlatformAccess` trait surface and mirrors the macOS module structure. It is compiled out on every
non-Android target; the host build is unaffected. The JNI handle, the cdylib wrapper, and the NDK
build are stubbed (`unimplemented!()` / `TODO`). It has not been built against the Android target in
this repo (no NDK here — see "Build").

## Why v6 is a good base

- **Clean platform seam.** `platform.rs` selects one `PlatformAccess` impl per target. Adding Android
  = one new module, exactly as Windows and macOS were added. No shared logic forked.
- **Userspace ESP data path exists.** `tunnel/ipsec/imp/tun.rs` does ESP in userspace
  (`isakmp::esp::EspCodec`) over an ordinary UDP (NAT-T) or TCP socket. With `ipsec_native = false`
  the connector picks it automatically — so **IPsec works on an unprivileged app**, not just the SSL
  fallback. Native kernel XFRM (`platform/linux/xfrm.rs`) is Linux-only and stays unused, like on
  macOS.

## The core design decision: inverting device/route/DNS setup

Desktop flow (`imp/tun.rs::run`): create TUN device → `configure_device` (addr/MTU) → `setup_routing`
→ `setup_dns` → pump packets.

Android: `VpnService.Builder` must be given address, routes, DNS and MTU **before** `establish()`
returns the fd; the fd is read-only to us afterwards. So the three configurators do not apply
anything — they **stage** their inputs, and the device is adopted from the VpnService fd once
everything is known:

| Trait seam | Desktop | Android (`platform/android/`) |
|------------|---------|-------------------------------|
| `NetworkInterface::configure_device` | ioctl addr/MTU | `net.rs` → `staging::set_device` |
| `RoutingConfigurator::configure` | PF_ROUTE / netlink | `routing.rs` → `staging::set_routing` |
| `ResolverConfigurator::configure` | resolver API | `resolver.rs` → `staging::set_resolver` |
| TUN device | `tun::create_as_async` | `tun_fd.rs` adopts the VpnService fd (`raw_fd`) |

```
imp/tun.rs::run
  configure_device         → stage device (addr/mtu)
  setup_routing            → stage routes
  setup_dns                → stage dns
  tun.inner()  (Android: deferred until here)
      └─ tun_fd::adopt_from_staged
            └─ jni_bridge::establish_tun ─JNI─► VpnClientService.establishTun
                                                    VpnService.Builder{addAddress/addRoute/addDnsServer}.establish()
            ◄──────────────── raw fd ──────────── pfd.detachFd()
      wrap fd as tun::AsyncDevice (tun 0.8 android backend requires raw_fd)
  pump: tun ↔ EspCodec ↔ protected UDP/TCP socket
```

### Shared-code touchpoints (minimal, all `#[cfg]`-gated; desktop unchanged)

1. `platform.rs` — select `AndroidPlatformAccess`; `pub mod android`; add `Clone` to `RoutingConfig`
   (needed to stage it; the other config structs were already `Clone`).
2. `tunnel/device.rs` — on Android `TunDevice` holds no eager device; `inner()` lazily adopts the
   VpnService fd from the staged config on first call.
3. `tunnel/ipsec/imp/tun.rs` — on Android, defer the `tun.inner()` capture until after
   `setup_routing`/`setup_dns` have staged their config.
4. `tunnel/ipsec/imp/udp.rs` — on Android, `protect_socket()` the NAT-T socket right after bind.
   **Not optional**: an unprotected gateway socket routes back into the tunnel and deadlocks.

## JNI interface

| Direction | Symbol | Purpose |
|-----------|--------|---------|
| Java→Rust | `nativeConnect(service, configJson)` | parse profile, register handle, start controller |
| Java→Rust | `nativeDisconnect()` | stop controller, clear handle + staging |
| Rust→Java | `establishTun(addr, mtu, routes[], dns[], domains[]) → fd` | build interface, return fd |
| Rust→Java | `protectSocket(fd) → bool` | `VpnService.protect()` |
| Rust→Java | `androidId() → String` | stable id → UUIDv5 machine id |
| Rust→Java | `keystoreGet/Set/Delete` | Android Keystore / EncryptedSharedPreferences |

Rust side: `platform/android/jni_bridge.rs` (`VpnServiceHandle` trait + the `extern "system"`
entry points behind `android-jni`). Kotlin side: `android/app/.../VpnClientService.kt`.

## Platform module map (`crates/snxcore/src/platform/android/`)

| File | Implements | Notes |
|------|------------|-------|
| `android.rs` | `PlatformAccess`, `UdpSocketExt` | `ipsec_native=false`; mirrors `macos.rs` |
| `net.rs` | `NetworkInterface` | stages device; `get_default_ipv4` → UNSPECIFIED |
| `routing.rs` | `RoutingConfigurator` | stages routes; `Cleanup` is a no-op |
| `resolver.rs` | `ResolverConfigurator` | stages DNS |
| `keychain.rs` | `Keychain` | Keystore via bridge |
| `stats.rs` | `StatsPoller` | reads `/sys/class/net/<if>/statistics` |
| `machine_uuid.rs` | — | `ANDROID_ID` → UUIDv5 |
| `single_instance.rs` | `SingleInstance` | always single (app sandbox) |
| `ipsec_stub.rs` | `IPsecConfigurator` | unused (userspace path) |
| `tun_fd.rs` | — | adopt VpnService fd |
| `staging.rs` | — | process-global staged config |
| `jni_bridge.rs` | — | JNI boundary |

## Build (the work beyond this skeleton)

- Add `apps/snxrs-android` with `crate-type = ["cdylib"]`, depending on `snxcore` with
  `features = ["android-jni"]`, producing `libsnxrs.so`. snxcore stays an rlib.
- Build with `cargo-ndk` for `arm64-v8a`, `armeabi-v7a`, `x86_64`.
- **OpenSSL/NDK**: `reqwest`/`tokio-native-tls` pull OpenSSL; the `android` target deps set
  `openssl/vendored`, which needs the NDK clang. **Strongly consider switching to rustls** — it drops
  the C dependency, makes the build NDK-free for the crypto, and lets the Android code be
  type-checked on a plain host (this container has no NDK, so the current target build stops at
  `openssl-sys`).
- Gradle module under `android/` to bundle the `.so`, host `VpnClientService`, add the VPN consent
  flow (`VpnService.prepare`) and a connect/disconnect UI.

## Remaining gaps (checklist)

- [ ] `apps/snxrs-android` cdylib + `cargo-ndk` build
- [ ] Concrete `AndroidVpnServiceHandle` (jni crate): cache `JavaVM` + `GlobalRef`, implement
      `establish_tun` / `protect_socket` / `android_id` / `keystore_*`
- [ ] `nativeConnect`/`nativeDisconnect` bodies: parse `TunnelParams`, run `controller` on a tokio
      runtime, force `TunnelType::IPsec`
- [ ] `protect_socket` for the TCPT transport and the SSL tunnel (udp.rs is wired; others TODO)
- [ ] EncryptedSharedPreferences in `SecurePrefs`
- [ ] Foreground-service notification + VPN consent
- [ ] Real DNS/online monitoring via `ConnectivityManager.NetworkCallback`
- [ ] Split DNS: Android has no supplemental-domain primitive; decide per-app DNS vs. full
- [ ] Browser/SSO auth (`browser.rs`) → Custom Tabs + deep-link redirect, if IdP login is needed
- [ ] UI (profiles, MFA challenge prompt)
- [ ] Consider rustls to drop OpenSSL/NDK (also enables host type-checking of the Android code)

# Android port: design notes

The app is a Kotlin `VpnService` (`android/`) around the Rust core, built as `libsnxrs.so` from
`apps/snxrs-android`. The core's Android support is the `crates/snxcore/src/platform/android/`
module, which implements the `PlatformAccess` trait like the other platforms; it is compiled out on
every other target.

## Why it fits the existing design

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

### Changes to shared code

1. `platform.rs`: selects `AndroidPlatformAccess`; `RoutingConfig` derives `Clone` so it can be staged.
2. `tunnel/device.rs`: on Android, `TunDevice::inner()` adopts the VpnService fd on first use.
3. `tunnel/ipsec/imp/tun.rs`: on Android, the device is taken after routing and DNS are staged.
4. `tunnel/ipsec/imp/udp.rs`: on Android, the NAT-T socket is protected right after bind. Without it,
   gateway traffic loops back into the tunnel.
5. `tunnel/ssl.rs`: connects through `isakmp::transport::connect_tcp`, so the socket hook can protect
   the SSL tunnel socket too (a plain connect on other platforms).
6. `model/params.rs`: `TunnelParams::parse` parses config text; `load` reads the file and calls it.
   The app keeps profiles in its own storage and hands their text to the native side.
7. `tunnel/ipsec.rs`: the IKEv1/IKEv2 session table names are constants, and an Android-only
   `SessionStore::delete_all` forgets both on disconnect.

## JNI interface

| Direction | Call | Purpose |
|-----------|------|---------|
| Kotlin→Rust | `VpnClientService.nativeConnect(config, filesDir)` | parse the profile, run until disconnect |
| Kotlin→Rust | `VpnClientService.nativeDisconnect()` | user disconnect |
| Kotlin→Rust | `VpnClientService.nativeSetOnline(online)` | feeds `NetworkInterface::is_online()` |
| Kotlin→Rust | `VpnClientService.nativeNetworkChanged()` | restart the tunnel on the new network |
| Kotlin→Rust | `Native.loginTypes(config)` | login types the gateway offers, as JSON |
| Rust→Kotlin | `establishTun(json) → fd` | `VpnService.Builder` + `establish()`, detached fd |
| Rust→Kotlin | `protectSocket(fd) → bool` | `VpnService.protect()` |
| Rust→Kotlin | `openUrl(url)` | SSO sign-in page in `SsoActivity` |
| Rust→Kotlin | `onReconnecting()` | status and notification |
| Rust→Kotlin | `androidId()`, `keystoreGet/Set/Delete` | machine id, keychain |

The Rust side of the callbacks is the `VpnServiceHandle` trait in `platform/android/jni_bridge.rs`,
implemented with the `jni` crate in `apps/snxrs-android`, so `snxcore` itself does not depend on `jni`.

## Platform module map (`crates/snxcore/src/platform/android/`)

| File | Implements | Notes |
|------|------------|-------|
| `android.rs` | `PlatformAccess`, `UdpSocketExt` | `ipsec_native=false`; `SO_NO_CHECK` via libc |
| `runner.rs` | — | login, tunnel and reconnect loop |
| `net.rs` | `NetworkInterface` | stages the device; online flag |
| `routing.rs` | `RoutingConfigurator` | stages routes |
| `resolver.rs` | `ResolverConfigurator` | stages DNS |
| `tun_fd.rs` | — | adopts the VpnService fd |
| `staging.rs` | — | staged config for `tun_fd` |
| `jni_bridge.rs` | — | `VpnServiceHandle` trait |
| `keychain.rs` | `Keychain` | EncryptedSharedPreferences via the bridge |
| `stats.rs` | `StatsPoller` | `/sys/class/net/<if>/statistics` |
| `machine_uuid.rs` | — | `ANDROID_ID` → UUIDv5 |
| `single_instance.rs` | `SingleInstance` | always single |
| `ipsec_stub.rs` | `IPsecConfigurator` | unused, as on macOS |

`android.rs` uses `unsafe` for one `setsockopt` call (the `libc` crate does not export `SO_NO_CHECK`
for Android), and `apps/snxrs-android` for the `#[unsafe(no_mangle)]` JNI exports.

## Build

See [android-build.md](android-build.md). The `apps/snxrs-android` cdylib produces `libsnxrs.so`; the
Gradle project runs cargo-ndk for arm64-v8a, armeabi-v7a and x86_64. OpenSSL (TLS for the gateway HTTPS
client and isakmp's crypto) is vendored for the Android target and compiles with the NDK toolchain.

## isakmp patch

`crates/isakmp` is upstream isakmp (rev `ce07353`) vendored with one local change, marked
`SNX-RS ANDROID PATCH`: a socket hook on outgoing TCPT connections so the Android runner can
`VpnService.protect()` the IKE channel. It is needed because the gateway's /32 is routed into the VPN
for the keepalive. It should go upstream as a small PR, after which the vendored copy can be dropped.

## Network changes

`NetworkMonitor.kt` follows the non-VPN networks (the app's own default network is its VPN) and picks
the one Android prefers: validated, then non-cellular. It reports to Rust through two JNI calls:
`nativeSetOnline` feeds `NetworkInterface::is_online()`, which pauses keepalive and rekey while
offline, and `nativeNetworkChanged` (debounced) terminates the running tunnel. The service also passes
the network to `setUnderlyingNetworks`.

`runner.rs` treats any loss of a tunnel that had connected as recoverable: it waits for connectivity,
backs off, and runs the login again, first trying `restore_session()` when `ike-persist` is set. A
failure before the first connection is reported as before. A user disconnect deletes the saved IKE
sessions (`SessionStore::delete_all`).

## Open


- Interactive MFA prompts (typed codes) and the Mobile Access portal.
- Keep the VPN interface across reconnects (re-`establish()` instead of closing the fd) so traffic does
  not briefly bypass the tunnel and apps do not see the VPN go down.
- Split DNS: Android has no supplemental-domain primitive; search domains apply globally.
- Device testing of certificate login, the SSL tunnel and IKEv2.

# Android port — skeleton and design notes

Status: **skeleton only.** The files under `snxcore/src/platform/android/` and `android/` compile
conceptually but are not wired to a running build; `unimplemented!()`/`TODO` mark the gaps. This
document explains the design so the port can be finished.

## What already works in our favour

- All protocol logic (CCC, SSL tunnel, S-expr, auth flows) is portable Rust and needs no changes.
- The **SSL tunnel** (`tunnel/ssl.rs`) is a pure userspace packet pump: it reads/writes IP packets
  on a `tun::AsyncDevice` and shuttles them over a framed TLS stream. That is exactly what an
  unprivileged Android `VpnService` can host.
- The platform layer is a single seam (`platform.rs` re-exports one `platform_impl`), so adding an
  OS means adding one module.

## What does NOT port (this fork, v2.8.2)

- **IPsec.** This fork's IPsec path is kernel XFRM over netlink (`platform/linux/xfrm.rs`), which
  needs `CAP_NET_ADMIN`. Unavailable to an app. `platform/android/ipsec_stub.rs` returns an error;
  Android must use `tunnel-type=ssl`. Upstream snx-rs 6.x added a *userspace* ESP path
  (`tunnel/ipsec/imp/tun.rs`, `isakmp::esp::EspCodec` over a normal socket) — porting that is the
  route to IPsec-on-Android later.
- Secret Service keychain, NetworkManager state, `ip`/`nmcli` routing — all replaced (see below).

## The core design decision: inverting device/route/DNS setup

Desktop order: create TUN device → apply address/routes/DNS with `ip`/resolver → pump packets.

Android order: **declare** address/routes/DNS/MTU on `VpnService.Builder` → `establish()` returns a
pre-configured fd → pump packets. Nothing can be applied *after* the fd exists.

The skeleton bridges the two without rewriting the shared tunnel code:

1. `platform/android/net.rs` and `resolver.rs` implement the usual `add_routes` / resolver
   `configure` calls as **staging** — they record the desired routes/DNS in process-global slots
   instead of applying them.
2. `tunnel/ssl/device.rs::TunDevice` is made lazy on Android (two small `#[cfg]` branches): `new()`
   creates no device; `take_inner()` drains the staged routing+DNS, builds a `TunBuilderConfig`, and
   calls `tun_fd::adopt_from_vpn_service()`.
3. That calls back through `jni_bridge` into `VpnClientService.establishTun(...)`, which runs the
   `VpnService.Builder`, calls `establish()`, and returns `detachFd()`.
4. The fd is wrapped as a `tun::AsyncDevice` and the existing SSL run loop pumps it unchanged.

```
controller → SslTunnel::run
                │ client_hello() negotiates office-mode addr, routes, DNS
                ├─ TunDevice::new()          (android: no-op, stores reply)
                ├─ setup_routing()           → net.rs stages routes
                ├─ setup_dns()               → resolver.rs stages DNS
                └─ take_inner()              → build TunBuilderConfig
                      └─ jni_bridge::establish_tun(cfg)   ─JNI─►  VpnClientService.establishTun
                                                                      VpnService.Builder{…}.establish()
                      ◄───────────────────── raw fd ──────────────  pfd.detachFd()
                   wrap fd as tun::AsyncDevice → pump packets ↔ TLS
```

## JNI interface

| Direction | Symbol | Purpose |
|-----------|--------|---------|
| Java→Rust | `nativeConnect(service, configJson)` | parse profile, register handle, start controller |
| Java→Rust | `nativeDisconnect()` | terminate controller |
| Rust→Java | `establishTun(addr, mtu, routes[], dns[], domains[]) → fd` | build interface, return fd |
| Rust→Java | `protectSocket(fd) → bool` | `VpnService.protect()` so gateway sockets bypass the tunnel |
| Rust→Java | `keystoreGet/Set` | Android Keystore / EncryptedSharedPreferences |

`protectSocket` is **not optional**: every socket the core opens to the gateway (the TLS socket in
`tunnel/ssl.rs::SslTunnel::create`, and any keepalive socket) must be protected, or traffic to the
VPN server routes back into the VPN and the tunnel deadlocks. Wiring this means threading a
"protect this fd" hook into the transport right after socket creation — the one remaining shared-code
change not yet sketched.

## Build / packaging (the real work beyond this skeleton)

- Add a thin `cdylib` wrapper crate (e.g. `apps/snxrs-android`) with
  `crate-type = ["cdylib"]`, depending on `snxcore` with `features = ["android-jni"]`, producing
  `libsnxrs.so`. snxcore stays an rlib.
- Build with `cargo-ndk` for `arm64-v8a`, `armeabi-v7a`, `x86_64`.
- **OpenSSL**: `reqwest`/`tokio-native-tls` pull in OpenSSL. Use the `vendored` feature (already set
  for the android target) with the NDK toolchain, or — cleaner long-term — switch `reqwest` and the
  TLS connector to **rustls** to drop the C dependency entirely.
- `libc`/`nix` socket bits used by the SSL path are fine on Android (it is a Linux kernel).
- Gradle module under `android/` builds the APK, bundles the `.so`, and ships the
  `VpnClientService` + a small connect/disconnect UI.

## Remaining gaps (checklist)

- [ ] `cdylib` wrapper crate + `cargo-ndk` build
- [ ] Real `AndroidVpnServiceHandle` (jni crate): cache `JavaVM`, `GlobalRef` to the service,
      implement `establish_tun`/`protect_socket`/`keystore_*`
- [ ] Thread `protect_socket` into `tunnel/ssl.rs` socket creation
- [ ] `get_machine_uuid` from `ANDROID_ID`
- [ ] Foreground service notification + VPN consent (`VpnService.prepare`)
- [ ] MTU: derive from the gateway reply instead of the hard-coded 1400
- [ ] Browser/SSO auth (`browser.rs`) → Custom Tabs + deep-link redirect (if IdP login is needed)
- [ ] UI (profiles, MFA challenge prompt) — Slint-on-Android or native Compose

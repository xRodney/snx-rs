# Building the Android APK

This builds `libsnxrs.so` (the Rust core) with cargo-ndk and packages it into an APK with Gradle. The app
runs on Android 8.0 (API 26) and later.

> Status: builds end to end (NDK r28c `28.2.13676358`, Android Studio's JBR 21, Gradle 8.9 wrapper)
> and connects on a Galaxy S23 (Android 16) to a Check Point gateway over IKEv1 + ESP/UDP with Azure
> SSO login: office-mode address, split routes, internal DNS and keepalive all work.

## Prerequisites

1. **Rust** (1.88+) with the Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```
2. **cargo-ndk**:
   ```bash
   cargo install cargo-ndk
   ```
3. **Android SDK + NDK** (via Android Studio's SDK Manager, or `sdkmanager`):
   - Platform `android-34`, build-tools 34.x
   - NDK `28.2.13676358` (pinned as `ndkVersion` in `app/build.gradle.kts`):
     `sdkmanager --install "ndk;28.2.13676358"`. Set `ANDROID_HOME` and `ANDROID_NDK_HOME`.
4. **A full JDK 17+ that ships `jlink`** — Android Studio's bundled `jbr` works; some distro
   `openjdk-*-jre`/headless packages lack `jlink` and fail in `compileDebugJavaWithJavac`.

## Build

From the repo root:

```bash
cd android
export JAVA_HOME=/path/to/android-studio/jbr
export ANDROID_HOME=~/Android/Sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358

# Debug APK (also compiles the .so for all three ABIs via the cargoNdkBuild task):
./gradlew assembleDebug
```

The cargo-ndk step runs automatically (`app` module's `preBuild` depends on `cargoNdkBuild`) and drops
`libsnxrs.so` into `app/src/main/jniLibs/<abi>/`. To build the Rust in debug instead of release, pass
`-PrustProfile=debug`.

The APK lands at:

```
android/app/build/outputs/apk/debug/app-debug.apk
```

Install it on a device/emulator:

```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

## Using the app

The main screen picks a **profile** and connects/disconnects; **Edit** opens the profile's settings,
**New**/**Delete** manage profiles. Settings mirror the desktop options that apply on Android, grouped as
Connection, Certificates, Routing, DNS and Advanced, and are stored per profile (encrypted) under the
same keys as `snx-rs.conf`; on connect the profile is rendered as config-file text and parsed by
snxcore's own config parser. In the profile, set the gateway, tap **Load login types from gateway** and
pick one. Username/password are hidden for identity-provider (SSO) login types: **Connect** then opens
the sign-in page inside the app. CA and client certificate files are picked with the system file picker
and copied into app-private storage.

If the tunnel drops after it was up — the keepalive fails, or the phone moves between Wi-Fi and mobile
data — the app reconnects by itself: it waits until a network is available and retries with back-off
(up to 10 attempts). With **Persist IKE session** on, the reconnect resumes the saved IKE session, so
SSO profiles do not ask to sign in again; without it, the sign-in page opens again. The VPN interface
is rebuilt on every reconnect, so open TCP connections through the tunnel are reset. **Disconnect**
forgets the saved session.

Not offered on Android: kernel transport, PKCS#11 tokens, split DNS / routing domains, IP forwarding,
keychain, themes and notification level.

Logs: `adb logcat -s snx-rs`.

Current limitations (see docs/android-port.md):
- Interactive MFA prompts (e.g. a typed one-time code) and the Mobile Access portal are not supported yet.
- Certificate login (PKCS#12/PKCS#8) is configurable but untested on a device.
- The SSL tunnel type is configurable but untested on a device.
- Only IKEv1 has been exercised on a device.

## CI

`.github/workflows/android.yml` runs clippy for the Android target and Android lint, and builds the debug APK on every push and pull request (and on manual
dispatch) and uploads it as the `snx-rs-android-debug` artifact. CI signs with a throwaway debug key, so
`adb install -r` of a CI build over a locally built one fails with a signature mismatch — uninstall first.

`.github/workflows/release.yml` also builds a release APK on version tags and attaches it to the GitHub
release as `snx-rs-<tag>-android.apk`. The app version comes from the workspace `Cargo.toml`. The APK
must be signed with the same key in every release, or Android refuses to update the installed app, so
it is published only when these repository secrets are set (otherwise the release has no APK):

| Secret | Value |
|--------|-------|
| `ANDROID_KEYSTORE_BASE64` | the keystore file, base64-encoded (`base64 -w0 release.jks`) |
| `ANDROID_KEYSTORE_PASSWORD` | the keystore password |
| `ANDROID_KEY_ALIAS` | the alias of the signing key |
| `ANDROID_KEY_PASSWORD` | the key password |

A keystore can be created with
`keytool -genkeypair -keystore release.jks -alias snx-rs -keyalg RSA -keysize 4096 -validity 10000`.
Keep it backed up: losing it means users must uninstall the app before they can install a newer release.

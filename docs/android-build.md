# Building the Android APK

This builds `libsnxrs.so` (the Rust core) with cargo-ndk and packages it into an APK with Gradle.

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

Enter the gateway host and tap **Load login types**; pick one from the list the gateway offers. For
password login types enter the username and password; for identity-provider (SSO) types such as Azure,
leave the password empty — tapping **Connect** opens the sign-in page inside the app, and the code the
page hands to `127.0.0.1:7779` is captured there. Accept the Android VPN consent dialog the first time.

Logs: `adb logcat -s snx-rs`.

Current limitations (see docs/android-port.md and docs/deopenssl-plan.md):
- Interactive MFA prompts (e.g. a typed one-time code) and the Mobile Access portal are not supported yet.
- Certificate (PKCS#12/PKCS#11) login is not wired into the app UI.
- IPv6 is blocked while connected (the VPN carries IPv4 only); `allowFamily(AF_INET6)` would fix it.
- AES-GCM-8 is unsupported (rarely negotiated).
- Only IKEv1 has been exercised on a device.

## CI alternative

A GitHub Actions workflow on a runner with the Android toolchain can produce the APK as a downloadable
artifact without a local NDK. Not included here; ask if you want it added.

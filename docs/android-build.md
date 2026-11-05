# Building the Android APK

This builds `libsnxrs.so` (the Rust core) with cargo-ndk and packages it into an APK with Gradle.

> Status: builds end to end (verified with NDK r28c `28.2.13676358`, Android Studio's JBR 21, Gradle
> 8.9 wrapper). Not yet tested on a device or against a real gateway.

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

Enter the gateway host, login type (e.g. `vpn`), username and password, tap **Connect**, and accept the
Android VPN consent dialog. The service runs the IPsec userspace path.

Current limitations (see docs/android-port.md and docs/deopenssl-plan.md):
- Password / certificate auth only — interactive and browser/IdP MFA are rejected for now.
- AES-GCM-8 is unsupported (rarely negotiated).
- Not yet tested against a real gateway; wire-level interop needs verification.

## CI alternative

A GitHub Actions workflow on a runner with the Android toolchain can produce the APK as a downloadable
artifact without a local NDK. Not included here; ask if you want it added.

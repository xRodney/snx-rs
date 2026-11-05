# Building the Android APK

This builds `libsnxrs.so` (the Rust core) with cargo-ndk and packages it into an APK with Gradle.

> Status: this is a bring-up build. The Rust Android code (the `apps/snxrs-android` cdylib, the
> `snxcore::platform::android` modules, `snxcore::platform::android::run_tunnel`) has **not been
> compiled on an Android target yet** — the dev container has no NDK. Expect to fix a few `jni` 0.21
> call sites on the first `cargo-ndk` build. The IKE/ESP crypto (isakmp) is pure-Rust and tested;
> OpenSSL (for the gateway TLS) is vendored and compiles under the NDK.

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
   - NDK (r26+); set `ANDROID_NDK_HOME` (or `ANDROID_HOME`/`ndk/<version>`) so cargo-ndk finds it.
4. **JDK 17** and Gradle (Android Studio bundles both).

## Build

From the repo root:

```bash
cd android
# First time only (generates gradlew + the wrapper jar); Android Studio does this automatically:
gradle wrapper --gradle-version 8.9

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

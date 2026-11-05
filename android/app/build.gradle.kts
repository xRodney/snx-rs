import org.gradle.internal.os.OperatingSystem

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "net.pankratov.snxrs"
    compileSdk = 34
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "net.pankratov.snxrs"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            // Debug-signed by default so `./gradlew assembleRelease` still yields an installable APK;
            // supply your own signingConfig for distribution.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}

// --- Rust (cargo-ndk) ------------------------------------------------------------------------------
// Builds libsnxrs.so for each ABI straight into src/main/jniLibs via cargo-ndk, so it is packaged by
// the normal Android build. Requires: rustup, the android targets, the NDK, and `cargo install cargo-ndk`.
// See docs/android-build.md. ANDROID_NDK_HOME must point at the installed NDK.
val cargoNdkBuild by tasks.registering(Exec::class) {
    workingDir = rootProject.projectDir.parentFile // repo root (the cargo workspace)
    val cargo = if (OperatingSystem.current().isWindows) "cargo.exe" else "cargo"
    val profile = (project.findProperty("rustProfile") as String?) ?: "release"
    val args = mutableListOf(
        cargo, "ndk",
        "-t", "arm64-v8a", "-t", "armeabi-v7a", "-t", "x86_64",
        "-o", file("src/main/jniLibs").absolutePath,
        "build", "-p", "snxrs-android",
    )
    if (profile == "release") args += "--release"
    commandLine(args)
}

tasks.named("preBuild").configure {
    dependsOn(cargoNdkBuild)
}

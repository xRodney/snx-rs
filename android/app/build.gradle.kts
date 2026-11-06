import org.gradle.internal.os.OperatingSystem

// The app takes its version from the cargo workspace, so releases match the desktop packages.
val workspaceVersion: String = Regex("""(?m)^version\s*=\s*"([^"]+)"""")
    .find(rootProject.file("../Cargo.toml").readText())!!.groupValues[1]
val versionParts = workspaceVersion.split(".").map { it.toInt() }

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
        minSdk = 26
        targetSdk = 34
        versionCode = versionParts[0] * 10000 + versionParts[1] * 100 + versionParts[2]
        versionName = workspaceVersion
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    signingConfigs {
        System.getenv("ANDROID_KEYSTORE_FILE")?.let { keystore ->
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            // Without ANDROID_KEYSTORE_FILE, debug-signed so a local `assembleRelease` is still installable.
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
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
    implementation("androidx.preference:preference-ktx:1.2.1")
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

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

fun String.asBuildConfigString(): String = replace("\\", "\\\\").replace("\"", "\\\"")

val configuredBaseUrl = providers.environmentVariable("ENIGMA_BASE_URL")
val debugBaseUrl = configuredBaseUrl
    .orElse("http://10.0.2.2:8080/")
    .get()
    .asBuildConfigString()
val releaseBaseUrl = configuredBaseUrl
    .orElse("https://relay.example.invalid/")
    .get()
    .asBuildConfigString()
val pinnedHost = providers.environmentVariable("ENIGMA_PINNED_HOST")
    .orElse("")
    .get()
    .asBuildConfigString()
val pinnedSha256 = providers.environmentVariable("ENIGMA_PINNED_SHA256")
    .orElse("")
    .get()
    .asBuildConfigString()
val pinningEnabled = pinnedHost.isNotBlank() && pinnedSha256.startsWith("sha256/")
val updateEd25519PublicKey = providers.environmentVariable("ENIGMA_UPDATE_ED25519_PUBLIC_KEY")
    .orElse("")
    .get()
    .asBuildConfigString()
val releaseStoreFile = providers.environmentVariable("ENIGMA_RELEASE_STORE_FILE")
    .orElse("")
    .get()
val releaseStorePassword = providers.environmentVariable("ENIGMA_RELEASE_STORE_PASSWORD")
    .orElse("")
    .get()
val releaseKeyAlias = providers.environmentVariable("ENIGMA_RELEASE_KEY_ALIAS")
    .orElse("")
    .get()
val releaseKeyPassword = providers.environmentVariable("ENIGMA_RELEASE_KEY_PASSWORD")
    .orElse("")
    .get()
val releaseSigningConfigured = listOf(
    releaseStoreFile,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all(String::isNotBlank)
val requestedGradleTasks = gradle.startParameter.taskNames.joinToString(" ").lowercase()
val releaseAbiBuild = requestedGradleTasks.contains("release")
val releaseDeviceAbis = listOf("arm64-v8a", "armeabi-v7a")
val debugAndEmulatorAbis = releaseDeviceAbis + "x86_64"

android {
    namespace = "com.enigma.securechat"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.enigma.securechat"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "DEFAULT_BASE_URL", "\"$debugBaseUrl\"")
        buildConfigField("Boolean", "CLEARTEXT_ALLOWED", "true")
        buildConfigField("Boolean", "PINNING_ENABLED_BY_DEFAULT", "false")
        buildConfigField("String", "PINNED_HOST", "\"\"")
        buildConfigField("String", "PINNED_SHA256", "\"\"")
        buildConfigField("String", "UPDATE_ED25519_PUBLIC_KEY", "\"\"")
    }

    signingConfigs {
        create("envRelease") {
            if (releaseSigningConfigured) {
                storeFile = file(releaseStoreFile)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
            buildConfigField("String", "DEFAULT_BASE_URL", "\"$debugBaseUrl\"")
            buildConfigField("Boolean", "CLEARTEXT_ALLOWED", "true")
            buildConfigField("Boolean", "PINNING_ENABLED_BY_DEFAULT", "false")
            buildConfigField("String", "UPDATE_ED25519_PUBLIC_KEY", "\"$updateEd25519PublicKey\"")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            buildConfigField("String", "DEFAULT_BASE_URL", "\"$releaseBaseUrl\"")
            buildConfigField("Boolean", "CLEARTEXT_ALLOWED", "false")
            buildConfigField("Boolean", "PINNING_ENABLED_BY_DEFAULT", pinningEnabled.toString())
            buildConfigField("String", "PINNED_HOST", "\"$pinnedHost\"")
            buildConfigField("String", "PINNED_SHA256", "\"$pinnedSha256\"")
            buildConfigField("String", "UPDATE_ED25519_PUBLIC_KEY", "\"$updateEd25519PublicKey\"")
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("envRelease")
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    sourceSets {
        getByName("androidTest").assets.srcDirs("$projectDir/schemas")
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        resources.excludes += setOf("**/*.dylib", "**/*.dll")
        jniLibs.excludes += setOf("**/libsignal_jni_testing.so")
    }

    splits {
        abi {
            isEnable = true
            reset()
            include(*(if (releaseAbiBuild) releaseDeviceAbis else debugAndEmulatorAbis).toTypedArray())
            isUniversalApk = !releaseAbiBuild
        }
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.4")

    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:3.0.0")
    implementation("com.squareup.retrofit2:converter-moshi:3.0.0")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.2")
    implementation("com.google.zxing:core:3.5.4")

    implementation(libs.libsignal.android)
    implementation(libs.webrtc.android)
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    implementation(platform("com.google.firebase:firebase-bom:33.5.1"))
    implementation("com.google.firebase:firebase-messaging-ktx")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

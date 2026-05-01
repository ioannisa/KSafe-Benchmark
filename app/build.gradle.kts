plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "eu.anifantakis.ksafe_benchmark"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "eu.anifantakis.ksafe_benchmark"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    // KSafe (local version with deferred encryption)
    implementation("eu.anifantakis:ksafe:2.0.0")
    implementation("eu.anifantakis:ksafe-compose:2.0.0")

    // Competitor libraries for benchmarking
    implementation(libs.androidx.security.crypto)  // EncryptedSharedPreferences
    implementation(libs.mmkv)                       // MMKV
    implementation(libs.androidx.datastore)         // DataStore Preferences
    implementation(libs.kotlinx.serialization.json) // For KSafe serialization
    implementation(libs.multiplatform.settings)     // Russell Wolf's multiplatform-settings
    implementation(libs.multiplatform.settings.no.arg)
    implementation(libs.kvault)                     // KVault - encrypted KMP storage

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
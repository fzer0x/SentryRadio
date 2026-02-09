plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    id("com.google.devtools.ksp")
}

android {
    namespace = "dev.fzer0x.imsicatcherdetector2"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.fzer0x.imsicatcherdetector2"
        minSdk = 29
        targetSdk = 36
        versionCode = 4
        versionName = "0.3.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlin {
        jvmToolchain(21)
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

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    implementation("org.osmdroid:osmdroid-android:6.1.18")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // SECURITY: Encrypted SharedPreferences
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // SECURITY: Network Security Configuration
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // GOOGLE PLAY SERVICES: Location
    implementation(libs.google.play.services.location)

    // SECURITY: Kotlin Coroutines for safe async operations
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    // ROOT ACCESS: libsu for stable shell management
    implementation(libs.libsu.core)
    implementation(libs.libsu.io)

    compileOnly(libs.xposed.api)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

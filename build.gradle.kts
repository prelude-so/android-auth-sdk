plugins {
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.jetbrains.kotlin.serialization)
    alias(libs.plugins.android.library)
}

android {
    namespace = "so.prelude.android.auth"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    testOptions {
        // Lets unit tests reach android.* surfaces without Robolectric.
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    // Social login (opt-in) opens the provider page in a Custom
    // Tab. Compile-only so apps that skip social pull no extra
    // dependency; social integrators add it themselves.
    compileOnly(libs.androidx.browser)
    // Anti-fraud signals dispatch is provided by the Prelude Android
    // SDK; wired as a project reference at dev time and swapped for
    // the published `so.prelude.android:sdk` coordinate at release.
    implementation("so.prelude.android:sdk:0.6.1")

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}


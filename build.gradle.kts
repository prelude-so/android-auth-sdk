plugins {
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.jetbrains.kotlin.serialization)
    alias(libs.plugins.android.library)
}

android {
    namespace = "so.prelude.android.session"
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
    // Anti-fraud signals dispatch is provided by the Prelude Android
    // SDK; wired as a project reference at dev time and swapped for
    // the published `so.prelude.android:sdk` coordinate at release.
    implementation("so.prelude.android:sdk:0.5.0")

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}


plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.daal.desktop.platform"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.9.0")
    implementation("androidx.appcompat:appcompat:1.6.0")
    implementation(project(":tauri-android"))
    // JVM unit tests for the pure decision logic (SwitchPolicy,
    // StartSequence): no Android classes, no emulator.
    //   ./gradlew :tauri-plugin-daal-platform:testDebugUnitTest
    // `./daal test` runs the same tests without Gradle or the Android
    // SDK (tools/test-android-jvm.sh), so they are part of the gate.
    testImplementation("junit:junit:4.13.2")
}

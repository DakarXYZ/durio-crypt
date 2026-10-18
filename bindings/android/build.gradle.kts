// AAR `io.github.dakarxyz.durio:stoat-crypto` (CR-13). Inputs from
// scripts/build-aar.sh: src/main/jniLibs/<abi>/libstoat_crypto_ffi.so
// (cargo ndk) and src/main/kotlin (uniffi-bindgen from the host library).
plugins {
    id("com.android.library") version "9.3.2"
    `maven-publish`
}

group = "io.github.dakarxyz.durio"
// = version of the Rust crates (Cargo.toml), passed by the build script
version = providers.gradleProperty("stoatCrypto.version").getOrElse("0.0.0-dev")

// host build of the library (linux-x86-64) for the JVM unit tests
val hostLibDir = providers.gradleProperty("stoatCrypto.hostLibDir")
    .getOrElse(layout.buildDirectory.dir("host").get().asFile.path)
val fixturesDir = rootDir.resolve("../../fixtures").canonicalPath

android {
    namespace = "io.github.dakarxyz.durio.crypto"
    compileSdk = 37

    defaultConfig {
        // as the app (for-android libs.versions.toml)
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("test").kotlin.srcDir("src/sharedTest/kotlin")
        getByName("androidTest").kotlin.srcDir("src/sharedTest/kotlin")
    }

    packaging {
        // .so stay uncompressed and 16 KB aligned in the APK
        jniLibs.useLegacyPackaging = false
    }

    testOptions {
        unitTests.all {
            it.systemProperty("jna.library.path", hostLibDir)
            it.systemProperty("stoat.fixtures", fixturesDir)
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    // JNA with libjnidispatch.so for every ABI; the app declares the same
    // `@aar` and nothing else of JNA (30-android AN-20)
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")

    // JVM unit tests load the host library: the JAR has the desktop jnidispatch
    testImplementation("net.java.dev.jna:jna:5.17.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "stoat-crypto"
            afterEvaluate { from(components["release"]) }
            pom {
                name = "stoat-crypto"
                description = "dur.io end-to-end encryption core (matrix-sdk-crypto behind a Stoat adapter), UniFFI bindings"
                licenses {
                    license {
                        name = "Apache-2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0"
                    }
                }
            }
        }
    }
    repositories {
        // local maven repo for for-android (dev) and the release upload
        maven {
            name = "local"
            url = uri(layout.buildDirectory.dir("maven"))
        }
    }
}

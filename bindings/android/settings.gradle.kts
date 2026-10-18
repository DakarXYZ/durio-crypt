// AAR of the crypto core (CR-13): jniLibs + UniFFI Kotlin bindings.
// Standalone build; scripts/build-aar.sh fills src/main/jniLibs and
// src/main/kotlin first. for-android consumes the result (README.md).
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "stoat-crypto"

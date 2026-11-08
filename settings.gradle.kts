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
        // libadb-android / sun-security-android 只发布在 JitPack
        maven("https://jitpack.io")
    }
}

rootProject.name = "ic-timer-lpe"
include(":app")

pluginManagement {
    repositories {
        // 阿里云镜像优先：Maven Central 上的部分 jar 会被 302 到 github.com，
        // 而 GitHub 的 release 资源偶发 504（见 CI 日志 kotlin-compiler-embeddable）。
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
        // libadb-android / sun-security-android 只发布在 JitPack
        maven("https://jitpack.io")
    }
}

rootProject.name = "ic-timer-lpe"
include(":app")

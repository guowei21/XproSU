import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// 可选：项目根目录放 keystore.properties（已 gitignore）即可给 release 签名，
// 否则回退到 debug 签名，方便本机自测。
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}
val hasReleaseKey = keystoreProps.getProperty("storeFile") != null

android {
    namespace = "com.xprosu"
    compileSdk = 35
    buildToolsVersion = "35.0.1"

    defaultConfig {
        applicationId = "com.xprosu"
        minSdk = 33
        targetSdk = 35
        versionCode = 20
        versionName = "0.18.0"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            // 与已安装的 0.13.5 并存，便于对比测试
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
        }
        release {
            // 体积大头在这一步：不 shrink 的 Compose 包 11 MB，shrink 后约 4 MB
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = if (hasReleaseKey) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/DEPENDENCIES")
        dex {
            // 压缩 dex：debug 包从 ~55 MB 降到 ~11 MB
            useLegacyPackaging = true
        }
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

// The exploit payload is a build artifact, not source. Fail early with a clear
// message instead of shipping an APK that dies at "missing /data/local/tmp/ic-timer".
val payload: File = file("src/main/assets/ic-timer")
tasks.matching { it.name == "preBuild" }.configureEach {
    doFirst {
        if (!payload.exists()) {
            throw GradleException(
                "assets/ic-timer 缺失：先运行 scripts/build-core.sh 生成（需要 Android NDK r27+，API 29 target）。"
            )
        }
        // V2324A 的 cred 以 4 字节 usage 开头；pd2571 载荷会把 uid 写到
        // cred+8，表现为 fake uid write missed，构建阶段直接拦下。
        if (payload.readBytes().toString(Charsets.ISO_8859_1).contains("pd2571-6.1.145")) {
            throw GradleException(
                "assets/ic-timer 是 pd2571 profile（8 字节 cred usage）；" +
                    "V2324A 需要 qemu_iqoo12，重新运行 scripts/build-core.sh"
            )
        }
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // 无线 ADB：libadb-android 负责 adbd 协议与 TLS，sun-security-android 提供
    // 造自签证书用的 android.sun.security.x509.*，hiddenapibypass 放开隐藏 API 限制，
    // conscrypt 提供 TLSv1.3 Provider（库里的反射首选路径）。
    implementation("com.github.MuntashirAkon:libadb-android:3.1.1")
    implementation("com.github.MuntashirAkon:sun-security-android:1.1")
    implementation("org.lsposed.hiddenapibypass:hiddenapibypass:6.1")
    implementation("org.conscrypt:conscrypt-android:2.5.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
}

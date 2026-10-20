@file:Suppress("UnstableApiUsage")

import java.net.URI
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val appName = "XproSU"
val appVersionName = "1.1"

// 原构建用 `git rev-list --count HEAD`（= 93）。从无 .git 的源码目录构建时会回退成 1，
// 导致无法覆盖安装已装的版本。故改为手工固定；升级时手工递增。
val gitVersionCode = 99
// 授权服务配置：从 local.properties（或同名环境变量）读取，构建期注入 BuildConfig。
// 留空表示未配置 —— App 会在激活时明确报错，不会静默放行。
val localProps = Properties()
runCatching { localProps.load(rootProject.file("local.properties").inputStream()) }

fun cfg(name: String): String = (localProps.getProperty(name) ?: System.getenv(name) ?: "").trim()

fun cfgField(name: String): String =
    "\"" + cfg(name).replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "com.ghostlock.pro"
    compileSdk {
        version = release(37) {
            minorApiLevel = 2
        }
    }
    defaultConfig {
        applicationId = "com.ghostlock.pro"
        minSdk = 34
        targetSdk = 37
        versionCode = gitVersionCode
        versionName = appVersionName

        // 自建授权服务地址（见 server/gl-license/）。留空 = 未配置，App 激活时明确报错。
        // 服务端凭据（master_key 等）只留在服务器上，绝不进 APK。
        buildConfigField("String", "LICENSE_BASE_URL", cfgField("LICENSE_BASE_URL"))
        buildConfigField("String", "APP_VER", "\"$appVersionName\"")
    }
    val properties = Properties()
    runCatching { properties.load(project.rootProject.file("local.properties").inputStream()) }
    val keystorePath = (properties.getProperty("KEYSTORE_PATH") ?: System.getenv("KEYSTORE_PATH"))?.trim()?.takeIf { it.isNotEmpty() }
    val keystorePwd = properties.getProperty("KEYSTORE_PASS") ?: System.getenv("KEYSTORE_PASS")
    val alias = properties.getProperty("KEY_ALIAS") ?: System.getenv("KEY_ALIAS")
    val pwd = properties.getProperty("KEY_PASSWORD") ?: System.getenv("KEY_PASSWORD")
    val keystoreFile = keystorePath?.let(::file)?.takeIf { it.isFile && it.length() > 0L }
    if (keystoreFile != null) {
        signingConfigs {
            create("release") {
                storeFile = keystoreFile
                storePassword = keystorePwd
                keyAlias = alias
                keyPassword = pwd
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }
    buildTypes {
        release {
            optimization.enable = true
            vcsInfo.include = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // 没有正式 keystore 就让构建失败，**绝不**回退到 debug 签名。
            //
            // 回退的代价不是"包丑一点"：Android Debug 证书是 SDK 自带的公开证书，
            // 任何人用它签一个同名包都能覆盖安装，系统视为同 UID，于是新包继承了
            // /data/data/com.ghostlock.pro 和 AndroidKeyStore 里的载荷密钥 ——
            // 等于把 Kd 白送出去。宁可构建失败。
            signingConfig = if (keystoreFile != null) {
                signingConfigs.getByName("release")
            } else {
                throw GradleException(
                    "release 构建需要正式 keystore：请在 local.properties（或环境变量）配置 " +
                        "KEYSTORE_PATH / KEYSTORE_PASS / KEY_ALIAS / KEY_PASSWORD",
                )
            }
        }
        // Debug 仍允许回退：本机调试不该被签名挡住。注意有正式 keystore 时
        // debug 也会用它签名，这样 debug/release 可以互相覆盖安装。
        debug {
            signingConfig = signingConfigs.getByName(if (keystoreFile != null) "release" else "debug")
        }
    }
    buildFeatures {
        buildConfig = true
    }
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
            excludes += "lib/*/libandroidx.graphics.path.so"
        }
    }
    splits {
        abi {
            isEnable = true
            isUniversalApk = false
            reset()
            include("arm64-v8a")
        }
    }

    // 明文放行范围由构建期生成的 network security config 决定，见下方
    // generateNetworkSecurityConfig。生成目录挂进 res，不污染源码树。
    sourceSets["main"].res.directories.add(
        layout.buildDirectory.dir("generated/glres").get().asFile.absolutePath,
    )
}

androidComponents {
    onVariants(selector().withBuildType("release")) {
        it.packaging.resources.excludes
            .add("**")
    }
}

base {
    archivesName.set("$appName-v$appVersionName($gitVersionCode)")
}

kotlin {
    jvmToolchain(21)
}

/**
 * 生成 network security config：默认拒绝明文。
 *
 * 只有授权服务地址是 `http://` 时才需要放行那**一个**主机的明文；`https://` 一律
 * 不放行。之前是全局 `android:usesCleartextTraffic="true"` —— 那等于对所有域名放开
 * 明文，而自建授权服务常以 `http://IP:PORT` 部署，于是"为了能连上自己的服务"把整个
 * App 的明文策略都松掉了。这里把范围收敛回它该有的那一个主机。
 */
val licenseCleartextHost: String = runCatching {
    val uri = URI(cfg("LICENSE_BASE_URL"))
    if (uri.scheme.equals("http", ignoreCase = true)) uri.host else null
}.getOrNull().orEmpty()

val generateNetworkSecurityConfig = tasks.register("generateNetworkSecurityConfig") {
    val outDir = layout.buildDirectory.dir("generated/glres")
    val host = licenseCleartextHost
    inputs.property("licenseCleartextHost", host)
    outputs.dir(outDir)
    doLast {
        val xmlDir = outDir.get().asFile.resolve("xml")
        xmlDir.mkdirs()
        val allowed = if (host.isEmpty()) {
            "    <!-- 授权服务是 https（或未配置）：不放行任何明文 -->\n"
        } else {
            "    <!-- 授权服务是 http：只对构建期配置的那一个主机放行明文 -->\n" +
                    "    <domain-config cleartextTrafficPermitted=\"true\">\n" +
                    "        <domain includeSubdomains=\"false\">$host</domain>\n" +
                    "    </domain-config>\n"
        }
        xmlDir.resolve("network_security_config.xml").writeText(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<network-security-config>\n" +
                    "    <base-config cleartextTrafficPermitted=\"false\" />\n" +
                    allowed +
                    "</network-security-config>\n",
        )
    }
}

tasks.named("preBuild") {
    dependsOn(rootProject.tasks.named("prepareGhostlockJniLibs"))
    dependsOn(generateNetworkSecurityConfig)
}

dependencies {
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.foundation:foundation:1.12.0")
    implementation("androidx.compose.material:material-icons-extended:1.7.8")
    implementation("top.yukonga.miuix.kmp:miuix-ui:0.9.4-rc01")
    implementation("top.yukonga.miuix.kmp:miuix-icons:0.9.4-rc01")
    implementation("top.yukonga.miuix.kmp:miuix-preference:0.9.4-rc01")
}

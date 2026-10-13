package com.ghostlock.pro

import android.app.Application
import com.ghostlock.pro.data.AndroidGhostlockRepository
import com.ghostlock.pro.domain.repository.GhostlockRepository
import com.ghostlock.pro.license.LicenseClient
import com.ghostlock.pro.license.LicenseRepository

/**
 * Application composition root. It is the only place that binds data
 * implementations to domain ports.
 *
 * [license] is deliberately a single instance: the payload key, the container
 * file and the Keystore aliases must have exactly one owner, and the login
 * screen, the main screen and the engine launcher all read the same one.
 */
class GhostlockApplication : Application() {

    /** 授权仓库（单例）。未配置服务地址时内部 client 为 null，激活会明确报错。 */
    val license: LicenseRepository by lazy {
        LicenseRepository(this, createLicenseClient())
    }

    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(
        context = this,
        payloadKey = { license.payloadKey() },
        deviceFpHex = { license.deviceFpHex },
        cardTagHex = { license.cardTagHex() },
    )

    /**
     * 自建授权服务客户端。
     *
     * 地址在构建期烧进 `BuildConfig`，运行时改不了 —— 否则用户把地址指向自己的
     * 假服务就能绕开全部校验。留空 = 未配置 = 激活明确报错，不会静默放行。
     */
    private fun createLicenseClient(): LicenseClient? {
        val url = BuildConfig.LICENSE_BASE_URL.trim()
        if (url.isEmpty()) return null
        return LicenseClient(url, BuildConfig.APP_VER)
    }
}

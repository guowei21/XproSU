package com.ghostlock.pro

import android.app.Application
import com.ghostlock.pro.data.AndroidGhostlockRepository
import com.ghostlock.pro.data.DeviceLogStore
import com.ghostlock.pro.data.GlobalLog
import com.ghostlock.pro.domain.repository.GhostlockRepository

/**
 * Application composition root. It is the only place that binds data
 * implementations to domain ports.
 *
 * 公开版没有授权服务，也没有任何网络请求：偏移表随 APK 走、运行时本地解密，
 * 这里只装配本机日志与仓库。
 */
class GhostlockApplication : Application() {

    /** 本机日志落盘（跑到一半死机之后仍能取出来）。 */
    val deviceLog: DeviceLogStore by lazy { DeviceLogStore(this) }

    /** 全局流水：运行日志 + WebUI 控制台 + 失败的接口，跨运行保留。 */
    val globalLog: GlobalLog by lazy { GlobalLog.get(this) }

    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(this)
}

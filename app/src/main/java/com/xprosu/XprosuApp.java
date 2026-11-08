package com.xprosu;

import android.app.Application;
import android.content.Context;
import android.os.Build;

import org.conscrypt.Conscrypt;
import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.security.Security;

/**
 * 进程级初始化。移植自 AdbShellTool 的 App.java（MIT, Copyright (c) 2026 Pablo Ajo）。
 *
 * 两件事必须在最早发生：
 * 1. attachBaseContext：解开 android.sun.security.x509.* 的隐藏 API 限制，
 *    否则生成 ADB 客户端证书时 NoClassDefFoundError / 不可访问。
 * 2. onCreate：把 Conscrypt 插到 Provider 首位，保证 TLSv1.3 可用（ADB 无线调试要求）。
 */
public class XprosuApp extends Application {

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            HiddenApiBypass.addHiddenApiExemptions("L");
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        com.xprosu.adb.AdbTransport.INSTANCE.attach(this);
    }
}

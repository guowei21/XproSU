package com.xprosu.adb;

import android.content.Context;

import androidx.annotation.NonNull;

import io.github.muntashirakon.adb.AdbStream;

/**
 * 连接门面。移植自 AdbShellTool 的 AdbManager.java（MIT, Copyright (c) 2026 Pablo Ajo）。
 *
 * 只负责"配对 / 连接 / 断开 / 开流"四件事，具体 ADB 服务（shell:、sync:）由
 * AdbTransport 组装。连接对象是本机 adbd：主机固定 127.0.0.1。
 */
public final class AdbBridge {

    public static final String ADB_HOST = "127.0.0.1";

    private static volatile AdbBridge sInstance;

    private final Context mContext;

    private AdbBridge(@NonNull Context context) {
        mContext = context.getApplicationContext();
    }

    @NonNull
    public static AdbBridge get(@NonNull Context context) {
        if (sInstance == null) {
            synchronized (AdbBridge.class) {
                if (sInstance == null) {
                    sInstance = new AdbBridge(context);
                }
            }
        }
        return sInstance;
    }

    /** SPAKE2 配对，失败抛异常。阻塞调用，勿在主线程调用。 */
    public void pair(int port, @NonNull String code) throws Exception {
        XprosuAdbKeyManager.getInstance(mContext).pair(ADB_HOST, port, code);
    }

    /** 连接会话端口；已连接直接返回 true。阻塞调用，勿在主线程调用。 */
    public boolean connect(int port) throws Exception {
        XprosuAdbKeyManager manager = XprosuAdbKeyManager.getInstance(mContext);
        if (manager.isConnected()) return true;
        return manager.connect(ADB_HOST, port);
    }

    public void disconnect() {
        try {
            XprosuAdbKeyManager.getInstance(mContext).close();
        } catch (Exception ignored) {
            // 断开失败不改变可用性判断：下一次 openStream 会重新报错
        }
    }

    public boolean isConnected() {
        try {
            return XprosuAdbKeyManager.getInstance(mContext).isConnected();
        } catch (Exception e) {
            return false;
        }
    }

    /** 打开一个 ADB 服务流："shell:<cmd>"、"sync:" 等。 */
    @NonNull
    public AdbStream openStream(@NonNull String service) throws Exception {
        XprosuAdbKeyManager manager = XprosuAdbKeyManager.getInstance(mContext);
        if (!manager.isConnected()) {
            throw new IllegalStateException("ADB 未连接");
        }
        return manager.openStream(service);
    }

    /** 重置密钥：清掉本地证书，下次必须重新配对。 */
    public void resetKeys() {
        disconnect();
        XprosuAdbKeyManager.resetKeys(mContext);
    }
}

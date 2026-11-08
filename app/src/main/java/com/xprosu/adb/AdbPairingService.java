package com.xprosu.adb;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.RemoteInput;
import android.app.Service;
import android.content.Intent;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;

import androidx.annotation.Nullable;

import com.xprosu.MainActivity;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 无线调试配对服务。移植自 AdbShellTool 的 AdbPairingService.java
 * （MIT, Copyright (c) 2026 Pablo Ajo），流程与 Shizuku 的配对服务一致：
 *
 * 1. 用户点"开始配对"→ 服务进前台，用 NsdManager 监听 _adb-tls-pairing._tcp；
 * 2. 用户在系统设置里点"使用配对码配对设备"，adbd 通过 mDNS 广播配对端口；
 * 3. 本服务解析到端口，把通知更新成带 RemoteInput 输入框的形态；
 * 4. 用户在通知里输入 6 位码（不用离开设置页），PendingIntent 直接回到本服务
 *    onStartCommand，用 android.app.RemoteInput.getResultsFromIntent() 取码；
 * 5. 配对成功后监听 _adb-tls-connect._tcp，拿到会话端口自动连接；
 * 6. 结果写进 AdbSessionBus，UI 订阅即可。
 *
 * 与上游的差异：广播改成 AdbSessionBus（StateFlow），文案改中文；端口校验、
 * RemoteInput 细节保持原样——那些是踩过坑的地方：android.app.RemoteInput 不能
 * 和 androidx.core.app.RemoteInput 混用，通知里的 action 必须来自同一套类。
 */
public class AdbPairingService extends Service {

    private static final String ADB_PAIRING_SERVICE_TYPE = "_adb-tls-pairing._tcp";
    private static final String ADB_CONNECT_SERVICE_TYPE = "_adb-tls-connect._tcp";

    public static final String CHANNEL_ID = "adb_pairing";
    private static final int NOTIF_ID = 1;

    public static final String ACTION_START = "start";
    public static final String ACTION_REPLY = "reply";
    public static final String ACTION_STOP = "stop";
    /** 只连接不配对：密钥已授信时（比如重启后重新打开无线调试）用这条。 */
    public static final String ACTION_CONNECT = "connect";

    /** 与 Shizuku 保持一致（原样保留它的拼写错误 paring_code），同时用作端口 int extra 的 key。 */
    public static final String REMOTE_INPUT_KEY = "paring_code";

    /** 应用内对话框提交配对码时用这个 extra（不走通知 RemoteInput）。 */
    public static final String EXTRA_PAIRING_CODE = "pairing_code";

    private volatile int detectedPairingPort = -1;

    private NsdManager nsdManager;
    private NsdManager.DiscoveryListener pairingDiscoveryListener;
    private NsdManager.DiscoveryListener connectDiscoveryListener;

    private ExecutorService executor;

    /** connect 模式没有配对那样明确的交互，发现不到端口就得自己收场。 */
    private final android.os.Handler handler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable connectTimeout = new Runnable() {
        @Override public void run() {
            if (!AdbBridge.get(getApplicationContext()).isConnected()) {
                AdbSessionBus.error("没发现无线调试端口：确认设置的「无线调试」已打开");
                stopAll();
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        executor = Executors.newSingleThreadExecutor();
        nsdManager = (NsdManager) getSystemService(NSD_SERVICE);
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(@Nullable Intent intent, int flags, int startId) {
        if (intent == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        String action = intent.getAction() == null ? "" : intent.getAction();
        switch (action) {
            case ACTION_START:
                startForeground(NOTIF_ID, buildSearchingNotification());
                AdbSessionBus.scanning();
                startPairingMdnsDiscovery();
                break;

            case ACTION_REPLY: {
                Bundle bundle = RemoteInput.getResultsFromIntent(intent);
                String code = null;
                if (bundle != null) {
                    CharSequence cs = bundle.getCharSequence(REMOTE_INPUT_KEY);
                    if (cs != null) code = cs.toString().trim();
                }
                if (code == null || code.isEmpty()) {
                    String direct = intent.getStringExtra(EXTRA_PAIRING_CODE);
                    if (direct != null) code = direct.trim();
                }
                int portFromIntent = intent.getIntExtra(REMOTE_INPUT_KEY, -1);
                int port = portFromIntent > 0 ? portFromIntent : detectedPairingPort;
                if (code == null || code.isEmpty() || port <= 0) {
                    AdbSessionBus.error("配对码或端口无效");
                    break;
                }
                stopPairingMdnsDiscovery();
                updateNotification(buildPairingInProgressNotification());
                AdbSessionBus.pairing(port);
                final String finalCode = code;
                final int finalPort = port;
                executor.submit(() -> doPairing(finalPort, finalCode));
                break;
            }

            case ACTION_CONNECT:
                startForeground(NOTIF_ID, buildConnectingNotification());
                AdbSessionBus.scanning();
                startConnectMdnsDiscovery();
                handler.removeCallbacks(connectTimeout);
                handler.postDelayed(connectTimeout, 12_000L);
                break;

            case ACTION_STOP:
                handler.removeCallbacks(connectTimeout);
                stopAll();
                AdbSessionBus.reset();
                break;

            default:
                stopSelf();
                return START_NOT_STICKY;
        }
        return START_NOT_STICKY;
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopPairingMdnsDiscovery();
        stopConnectMdnsDiscovery();
        if (executor != null) executor.shutdownNow();
    }

    private void stopAll() {
        stopPairingMdnsDiscovery();
        stopConnectMdnsDiscovery();
        stopForeground(true);
        stopSelf();
    }

    // ---------------------------------------------------------------- mDNS

    private void startPairingMdnsDiscovery() {
        pairingDiscoveryListener = new NsdManager.DiscoveryListener() {
            @Override public void onStartDiscoveryFailed(String type, int errorCode) {}
            @Override public void onStopDiscoveryFailed(String type, int errorCode) {}
            @Override public void onDiscoveryStarted(String type) {}
            @Override public void onDiscoveryStopped(String type) {}
            @Override public void onServiceFound(NsdServiceInfo info) {
                nsdManager.resolveService(info, buildPairingResolveListener());
            }
            @Override public void onServiceLost(NsdServiceInfo info) {}
        };
        nsdManager.discoverServices(ADB_PAIRING_SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD, pairingDiscoveryListener);
    }

    private void stopPairingMdnsDiscovery() {
        if (pairingDiscoveryListener != null) {
            try {
                nsdManager.stopServiceDiscovery(pairingDiscoveryListener);
            } catch (Exception ignored) {
            }
            pairingDiscoveryListener = null;
        }
    }

    private NsdManager.ResolveListener buildPairingResolveListener() {
        return new NsdManager.ResolveListener() {
            @Override public void onResolveFailed(NsdServiceInfo info, int errorCode) {}
            @Override public void onServiceResolved(NsdServiceInfo info) {
                int port = info.getPort();
                // mDNS 会广播同网段所有设备的配对端口；只认本机 adbd 占用的那个
                if (!isPortOccupiedLocally(port)) return;
                detectedPairingPort = port;
                updateNotification(buildCodeInputNotification(port));
                AdbSessionBus.codeRequired(port);
            }
        };
    }

    private void startConnectMdnsDiscovery() {
        connectDiscoveryListener = new NsdManager.DiscoveryListener() {
            @Override public void onStartDiscoveryFailed(String type, int errorCode) {}
            @Override public void onStopDiscoveryFailed(String type, int errorCode) {}
            @Override public void onDiscoveryStarted(String type) {}
            @Override public void onDiscoveryStopped(String type) {}
            @Override public void onServiceFound(NsdServiceInfo info) {
                nsdManager.resolveService(info, buildConnectResolveListener());
            }
            @Override public void onServiceLost(NsdServiceInfo info) {}
        };
        nsdManager.discoverServices(ADB_CONNECT_SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD, connectDiscoveryListener);
    }

    private void stopConnectMdnsDiscovery() {
        if (connectDiscoveryListener != null) {
            try {
                nsdManager.stopServiceDiscovery(connectDiscoveryListener);
            } catch (Exception ignored) {
            }
            connectDiscoveryListener = null;
        }
    }

    private NsdManager.ResolveListener buildConnectResolveListener() {
        return new NsdManager.ResolveListener() {
            @Override public void onResolveFailed(NsdServiceInfo info, int errorCode) {}
            @Override public void onServiceResolved(NsdServiceInfo info) {
                int port = info.getPort();
                if (!isPortOccupiedLocally(port)) return;
                stopConnectMdnsDiscovery();
                AdbSessionBus.connecting(port);
                executor.submit(() -> doConnect(port));
            }
        };
    }

    // ------------------------------------------------------------ pairing

    private void doPairing(int port, String code) {
        try {
            AdbBridge.get(this).pair(port, code);
            updateNotification(buildResultNotification(true, null));
            stopForeground(false);
            AdbSessionBus.paired();
            startConnectMdnsDiscovery();
        } catch (Exception e) {
            String message = String.valueOf(e.getMessage());
            updateNotification(buildResultNotification(false, message));
            stopForeground(false);
            AdbSessionBus.error("配对失败：" + message);
            stopSelf();
        }
    }

    private void doConnect(int port) {
        handler.removeCallbacks(connectTimeout);
        try {
            AdbBridge.get(this).connect(port);
            updateNotification(buildConnectedNotification(port));
            stopForeground(false);
            AdbSessionBus.connected(port);
            rememberPort(port);
            stopSelf();
        } catch (Exception e) {
            String message = String.valueOf(e.getMessage());
            if (message.toLowerCase().contains("pairing")) {
                // 密钥还没被 adbd 授信：直接把配对发现开起来，等用户去设置里
                // 点「使用配对码配对设备」，配对码照样在通知栏输入。
                AdbSessionBus.needsPairing("设备还没信任本机密钥，需要配对一次");
                updateNotification(buildNeedPairingNotification());
                startPairingMdnsDiscovery();
                return;
            }
            updateNotification(buildResultNotification(false, "连接失败：" + message));
            stopForeground(false);
            AdbSessionBus.error("连接失败：" + message);
            stopSelf();
        }
    }

    private void rememberPort(int port) {
        getSharedPreferences("adb_prefs", MODE_PRIVATE)
                .edit().putInt("connection_port", port).apply();
    }

    /**
     * 判断端口是否被本机进程占用：能 bind 说明空闲，bind 失败说明 adbd 在监听。
     * 与 Shizuku 的实现一致。
     */
    private boolean isPortOccupiedLocally(int port) {
        try (ServerSocket socket = new ServerSocket()) {
            socket.bind(new InetSocketAddress("127.0.0.1", port), 1);
            return false;
        } catch (Exception e) {
            return true;
        }
    }

    // -------------------------------------------------------- notification

    private Notification buildNeedPairingNotification() {
        Intent open = new Intent(android.provider.Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
        open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pending = PendingIntent.getActivity(this, 3, open, flags);

        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_error)
                .setContentTitle("需要配对一次")
                .setContentText("去设置 › 无线调试 › 使用配对码配对设备，再从本通知输入 6 位码")
                .setContentIntent(pending)
                .addAction(buildStopAction())
                .setOngoing(true)
                .build();
    }

    private Notification buildConnectingNotification() {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("正在连接")
                .setContentText("查找本机无线调试的会话端口…")
                .addAction(buildStopAction())
                .setOngoing(true)
                .build();
    }

    private Notification buildSearchingNotification() {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("等待配对")
                .setContentText("去 设置 › 开发者选项 › 无线调试 › 使用配对码配对设备")
                .addAction(buildStopAction())
                .setOngoing(true)
                .build();
    }

    private Notification buildCodeInputNotification(int port) {
        RemoteInput remoteInput = new RemoteInput.Builder(REMOTE_INPUT_KEY)
                .setLabel("6 位配对码")
                .build();

        Intent replyIntent = new Intent(this, AdbPairingService.class);
        replyIntent.setAction(ACTION_REPLY);
        replyIntent.putExtra(REMOTE_INPUT_KEY, port);

        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) flags |= PendingIntent.FLAG_MUTABLE;
        PendingIntent replyPending = PendingIntent.getForegroundService(this, 1, replyIntent, flags);

        Notification.Action replyAction = new Notification.Action.Builder(
                null, "输入配对码", replyPending)
                .addRemoteInput(remoteInput)
                .build();

        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("已发现配对端口 " + port)
                .setContentText("下拉通知栏，点「输入配对码」填入设置里显示的 6 位数字")
                .setContentIntent(openAppPending())
                .addAction(replyAction)
                .addAction(buildStopAction())
                .setOngoing(true)
                .build();
    }

    private Notification buildPairingInProgressNotification() {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("正在配对")
                .setContentText("配对进行中…")
                .setOngoing(true)
                .build();
    }

    private Notification buildResultNotification(boolean success, @Nullable String error) {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(success
                        ? android.R.drawable.stat_notify_sync_noanim
                        : android.R.drawable.stat_notify_error)
                .setContentTitle(success ? "配对成功" : "配对失败")
                .setContentText(success
                        ? "正等待会话端口…"
                        : (error == null ? "未知错误" : error))
                .setContentIntent(openAppPending())
                .setAutoCancel(!success)
                .build();
    }

    private Notification buildConnectedNotification(int port) {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
                .setContentTitle("ADB 已连接")
                .setContentText("会话端口 " + port + "，点按回到应用")
                .setContentIntent(openAppPending())
                .setAutoCancel(true)
                .build();
    }

    private PendingIntent openAppPending() {
        Intent openApp = new Intent(this, MainActivity.class);
        openApp.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags |= PendingIntent.FLAG_IMMUTABLE;
        return PendingIntent.getActivity(this, 0, openApp, flags);
    }

    private Notification.Action buildStopAction() {
        Intent stopIntent = new Intent(this, AdbPairingService.class);
        stopIntent.setAction(ACTION_STOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent stopPending = PendingIntent.getService(this, 2, stopIntent, flags);
        return new Notification.Action.Builder(null, "取消", stopPending).build();
    }

    private void updateNotification(Notification notification) {
        getSystemService(NotificationManager.class).notify(NOTIF_ID, notification);
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "ADB 配对", NotificationManager.IMPORTANCE_HIGH);
        channel.setSound(null, null);
        channel.enableVibration(false);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }
}

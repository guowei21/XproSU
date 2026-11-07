// AIDL for the Shizuku user service.  The service runs in a process owned by
// the Shizuku server (uid 2000 shell when Shizuku was started through adb), so
// everything here executes with the identity the exploit chain was validated
// for.  The app only relays bytes and log text.
package com.xprosu;

interface IIcService {
    // uid / pid / SELinux context of the service process, for the status line.
    String identity();

    // Run a short read-only command and return its combined output.
    String runCmd(String cmd);

    // File relay into /data/local/tmp (the service owns it; the app does not).
    void truncate(String path);
    void put(String path, int offset, in byte[] data);
    void makeExec(String path);
    int length(String path);
    byte[] read(String path, int offset, int max);

    // Start `sh <script>` with IC_BIN/ATTEMPTS/PAYLOAD_CMD plus any
    // newline-separated K=V pairs in extraEnv, appending stdout+stderr to
    // <log>.
    String start(String script, String bin, String log, int attempts,
                 String payloadCmd, String extraEnv);
}

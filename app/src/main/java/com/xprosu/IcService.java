package com.xprosu;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Runs in a process started by the Shizuku server, so its uid and SELinux
 * domain are the server's (uid 2000 / u:r:shell:s0 when Shizuku was started
 * over adb) -- exactly the identity the timer chain was validated with.
 *
 * The app cannot touch /data/local/tmp itself, so all file work happens here,
 * and the exploit is started as a child of this service.
 */
public class IcService extends IIcService.Stub {
    private static final String TMP = "/data/local/tmp/";
    private static final String SHELL = "/system/bin/sh";
    private static final String PATH = "/sbin:/system/bin:/system/xbin";
    /* One open fd per log path.  Opening a RandomAccessFile on every app
     * poll (1 Hz) allocates a struct file, i.e. an order-1 slab, exactly the
     * run17 thief that can steal the freed timer-slab page.  The reader is
     * opened before the exploit starts and reused for every read. */
    private final Map<String, RandomAccessFile> readers = new HashMap<>();

    public IcService() { }

    // Shizuku v13 prefers a Context constructor when one exists.
    public IcService(Context context) { }

    private static void check(String path) {
        if (path == null || !path.startsWith(TMP) || path.contains(".."))
            throw new IllegalArgumentException("path outside " + TMP);
    }

    @Override
    public String identity() {
        String ctx = "?";
        try (RandomAccessFile f = new RandomAccessFile("/proc/self/attr/current", "r")) {
            byte[] b = new byte[128];
            int n = f.read(b);
            if (n > 0)
                ctx = new String(b, 0, n, StandardCharsets.UTF_8).trim();
        } catch (IOException ignored) { }
        int nl = ctx.indexOf('\0');
        if (nl >= 0)
            ctx = ctx.substring(0, nl);
        return "uid=" + android.os.Process.myUid()
             + " pid=" + android.os.Process.myPid()
             + " ctx=" + ctx;
    }

    @Override
    public String runCmd(String cmd) {
        try {
            Process p = new ProcessBuilder(SHELL, "-c", cmd)
                    .redirectErrorStream(true)
                    .start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while (out.size() < 65536 && (n = p.getInputStream().read(buf)) > 0)
                out.write(buf, 0, n);
            p.waitFor();
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "error " + t;
        }
    }

    @Override
    public void truncate(String path) {
        check(path);
        try (FileOutputStream fo = new FileOutputStream(path, false)) {
            // truncate only
        } catch (IOException e) {
            throw new IllegalStateException("truncate " + path + ": " + e);
        }
    }

    @Override
    public void put(String path, int offset, byte[] data) {
        check(path);
        try (RandomAccessFile f = new RandomAccessFile(path, "rw")) {
            f.seek(offset);
            f.write(data);
        } catch (IOException e) {
            throw new IllegalStateException("write " + path + ": " + e);
        }
    }

    @Override
    public void makeExec(String path) {
        check(path);
        if (!new File(path).setExecutable(true, false))
            throw new IllegalStateException("chmod +x failed: " + path);
    }

    @Override
    public int length(String path) {
        check(path);
        long len = new File(path).length();
        return (int) Math.min(len, Integer.MAX_VALUE);
    }

    @Override
    public byte[] read(String path, int offset, int max) {
        check(path);
        RandomAccessFile f;
        synchronized (readers) {
            f = readers.get(path);
            if (f == null) {
                try {
                    f = new RandomAccessFile(path, "r");
                    readers.put(path, f);
                } catch (IOException e) {
                    return new byte[0];
                }
            }
        }
        try {
            synchronized (f) {
                long len = f.length();
                if (offset < 0 || offset >= len || max <= 0)
                    return new byte[0];
                f.seek(offset);
                int n = (int) Math.min(max, len - offset);
                byte[] b = new byte[n];
                int got = f.read(b);
                if (got <= 0)
                    return new byte[0];
                if (got == n)
                    return b;
                byte[] t = new byte[got];
                System.arraycopy(b, 0, t, 0, got);
                return t;
            }
        } catch (IOException e) {
            return new byte[0];
        }
    }

    @Override
    public String start(String script, String bin, String log, int attempts,
                        String payloadCmd, String extraEnv) {
        check(script);
        check(bin);
        check(log);
        /* Open the log reader before the exploit starts; the filp page is
         * then allocated up front instead of once per app poll. */
        try {
            synchronized (readers) {
                if (!readers.containsKey(log))
                    readers.put(log, new RandomAccessFile(log, "r"));
            }
        } catch (IOException ignored) { }
        try {
            Map<String, String> env = new HashMap<>();
            env.put("PATH", PATH);
            env.put("IC_BIN", bin);
            env.put("ATTEMPTS", Integer.toString(attempts));
            /* The launcher tees every zero attempt into this file too, so
             * the slide, zero-funcs, zero-selinux and chain output all end
             * up in the one log the UI follows. */
            env.put("IC_APP_LOG", log);
            if (payloadCmd != null && !payloadCmd.isEmpty())
                env.put("PAYLOAD_CMD", payloadCmd);
            /* extraEnv is newline-separated K=V; keep it tiny and reject
             * anything that is not a plain assignment. */
            if (extraEnv != null) {
                for (String line : extraEnv.split("\n")) {
                    int eq = line.indexOf('=');
                    if (eq > 0 && eq < 64)
                        env.put(line.substring(0, eq),
                                line.substring(eq + 1));
                }
            }
            /* setsid gives the whole plan its own session: turning off USB
             * debugging stops adbd and can kill the Shizuku service process
             * group, but the exploit (and the attempts it parks) must keep
             * running.  Fall back to a plain shell if toybox lacks setsid. */
            Process p = startDetached(script, env);
            pumpLog(p, log);
            return "启动 " + script + " (attempts=" + attempts + ")  " + identity();
        } catch (IOException e) {
            return "启动失败: " + e;
        }
    }

    private static Process startDetached(String script, Map<String, String> env)
            throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/system/bin/setsid", SHELL, script);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
        try {
            return pb.start();
        } catch (IOException e) {
            pb = new ProcessBuilder(SHELL, script);
            pb.environment().putAll(env);
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
            return pb.start();
        }
    }

    /* Stream the child's output into the /data/local/tmp log the app polls.
     * Nothing is mirrored to shared storage; the log is removed by the app's
     * post-run cleanup. */
    private static void pumpLog(Process p, String log) {
        final FileOutputStream app;

        try {
            app = new FileOutputStream(log, true);
        } catch (IOException e) {
            return;
        }
        new Thread(() -> {
            byte[] buf = new byte[8192];
            InputStream in = p.getInputStream();
            int n;

            try {
                while ((n = in.read(buf)) > 0) {
                    app.write(buf, 0, n);
                    app.flush();
                }
            } catch (IOException ignored) {
            } finally {
                try {
                    app.close();
                } catch (IOException ignored) { }
            }
        }, "ic-logpump").start();
    }
}

package com.xprosu.adb;

import android.content.Context;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import android.sun.security.x509.AlgorithmId;
import android.sun.security.x509.CertificateAlgorithmId;
import android.sun.security.x509.CertificateExtensions;
import android.sun.security.x509.CertificateIssuerName;
import android.sun.security.x509.CertificateSerialNumber;
import android.sun.security.x509.CertificateSubjectName;
import android.sun.security.x509.CertificateValidity;
import android.sun.security.x509.CertificateVersion;
import android.sun.security.x509.CertificateX509Key;
import android.sun.security.x509.KeyIdentifier;
import android.sun.security.x509.PrivateKeyUsageExtension;
import android.sun.security.x509.SubjectKeyIdentifierExtension;
import android.sun.security.x509.X500Name;
import android.sun.security.x509.X509CertImpl;
import android.sun.security.x509.X509CertInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import io.github.muntashirakon.adb.AbsAdbConnectionManager;

/**
 * ADB 客户端密钥/证书管理。移植自 AdbShellTool 的 MyAdbConnectionManager.java
 * （MIT, Copyright (c) 2026 Pablo Ajo），改动见下。
 *
 * adbd 用 RSA 公钥认证客户端：配对时把公钥写进 /data/misc/adb/adb_keys，
 * 之后每次连接用它签名认证挑战，不再需要 6 位码。
 *
 * 与上游的差异：
 * - 设备名与证书主体改成 XproSU；
 * - 证书有效期 10 年（上游 24 小时；adbd 只保存公钥，但短有效期会让长期安装的
 *   PEM 看起来"过期"，用长期限省掉一类困惑）；
 * - getPrivateKey() 每次从 PKCS#8 字节重新解析。因为 AbsAdbConnectionManager.close()
 *   会调用 getPrivateKey().destroy()，若缓存 PrivateKey 对象，断开一次后重连就可能
 *   拿到已销毁的 key；
 * - 增加 resetKeys()，供"重置 ADB 密钥"按钮使用。
 */
public final class XprosuAdbKeyManager extends AbsAdbConnectionManager {

    private static final String KEY_FILE = "adb_private.der";
    private static final String CERT_FILE = "adb_cert.der";
    private static final String DEVICE_NAME = "XproSU";
    private static final long VALIDITY_MS = 10L * 365 * 24 * 3600 * 1000;

    @Nullable
    private static volatile XprosuAdbKeyManager sInstance;

    private final Context mContext;
    private volatile byte[] mPrivateKeyDer;
    private volatile Certificate mCertificate;

    public static synchronized XprosuAdbKeyManager getInstance(@NonNull Context context) throws Exception {
        if (sInstance == null) {
            sInstance = new XprosuAdbKeyManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private XprosuAdbKeyManager(@NonNull Context context) throws Exception {
        mContext = context;
        setApi(Build.VERSION.SDK_INT);
        // 默认是 Long.MAX_VALUE，连接失败时会永久挂住
        setTimeout(15, TimeUnit.SECONDS);
        loadOrGenerate();
    }

    private synchronized void loadOrGenerate() throws Exception {
        byte[] keyDer = readBytes(new File(mContext.getFilesDir(), KEY_FILE));
        Certificate cert = readCertificate(new File(mContext.getFilesDir(), CERT_FILE));
        if (keyDer != null && cert != null) {
            mPrivateKeyDer = keyDer;
            mCertificate = cert;
            return;
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstance("SHA1PRNG"));
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String subject = "CN=" + DEVICE_NAME;
        String algorithm = "SHA512withRSA";
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + VALIDITY_MS);

        CertificateExtensions extensions = new CertificateExtensions();
        extensions.set("SubjectKeyIdentifier",
                new SubjectKeyIdentifierExtension(new KeyIdentifier(publicKey).getIdentifier()));
        extensions.set("PrivateKeyUsage", new PrivateKeyUsageExtension(notBefore, notAfter));

        X500Name x500Name = new X500Name(subject);
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set("version", new CertificateVersion(2));
        certInfo.set("serialNumber",
                new CertificateSerialNumber(new Random().nextInt() & Integer.MAX_VALUE));
        certInfo.set("algorithmID", new CertificateAlgorithmId(AlgorithmId.get(algorithm)));
        certInfo.set("subject", new CertificateSubjectName(x500Name));
        certInfo.set("key", new CertificateX509Key(publicKey));
        certInfo.set("validity", new CertificateValidity(notBefore, notAfter));
        certInfo.set("issuer", new CertificateIssuerName(x500Name));
        certInfo.set("extensions", extensions);

        X509CertImpl certImpl = new X509CertImpl(certInfo);
        certImpl.sign(keyPair.getPrivate(), algorithm);

        byte[] privateDer = keyPair.getPrivate().getEncoded();
        writeBytes(new File(mContext.getFilesDir(), KEY_FILE), privateDer);
        writeBytes(new File(mContext.getFilesDir(), CERT_FILE), certImpl.getEncoded());

        mPrivateKeyDer = privateDer;
        mCertificate = certImpl;
    }

    /** 删除本地密钥与证书；下次连接前需要重新配对。 */
    public static synchronized void resetKeys(@NonNull Context context) {
        File dir = context.getFilesDir();
        //noinspection ResultOfMethodCallIgnored
        new File(dir, KEY_FILE).delete();
        //noinspection ResultOfMethodCallIgnored
        new File(dir, CERT_FILE).delete();
        sInstance = null;
    }

    @NonNull
    @Override
    protected PrivateKey getPrivateKey() {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(mPrivateKeyDer);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("ADB 私钥损坏，请重置 ADB 密钥后重新配对", e);
        }
    }

    @NonNull
    @Override
    protected Certificate getCertificate() {
        return mCertificate;
    }

    @NonNull
    @Override
    protected String getDeviceName() {
        return DEVICE_NAME;
    }

    @Nullable
    private static byte[] readBytes(File file) {
        if (!file.exists()) return null;
        byte[] data = new byte[(int) file.length()];
        try (InputStream is = new FileInputStream(file)) {
            int offset = 0;
            while (offset < data.length) {
                int read = is.read(data, offset, data.length - offset);
                if (read < 0) break;
                offset += read;
            }
        } catch (IOException e) {
            return null;
        }
        return data;
    }

    @Nullable
    private static Certificate readCertificate(File file) {
        if (!file.exists()) return null;
        try (InputStream is = new FileInputStream(file)) {
            return CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (IOException | CertificateException e) {
            return null;
        }
    }

    private static void writeBytes(File file, byte[] data)
            throws IOException, CertificateEncodingException {
        try (OutputStream os = new FileOutputStream(file)) {
            os.write(data);
        }
    }
}

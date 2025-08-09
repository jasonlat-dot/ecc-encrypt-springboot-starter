package io.github.jasonlat.middleware.util;

import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.model.entity.ServerPublicKeyData;
import io.github.jasonlat.middleware.domain.model.entity.TempPublicKey;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/**
 * @author jasonlat
 */
@Component
public final class ECCCryptoUtil {

    private static final Logger logger = LoggerFactory.getLogger(ECCCryptoUtil.class);

    private static final String CURVE_NAME = "secp256k1";
    private static final String ECDH_ALGORITHM = "ECDH";
    private static final String ECDSA_ALGORITHM = "ECDSA";
    private static final int AES_KEY_SIZE = 32;
    private static final int GCM_IV_SIZE = 12;
    private static final int MAC_SIZE = 128;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final EccAutoConfigProperties eccAutoConfigProperties;

    public ECCCryptoUtil(EccAutoConfigProperties eccAutoConfigProperties) {
        this.eccAutoConfigProperties = eccAutoConfigProperties;
    }

    // ==================== 密钥生成 ====================

    /**
     * @return 密钥对
     * @throws Exception 异常
     */
    public KeyPair generateKeyPair() throws Exception {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
            keyGen.initialize(ecSpec, new SecureRandom());
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed to generate key pairs", e);
            throw new Exception("Failed to generate key pairs: " + e.getMessage(), e);
        }
    }

    /**
     *
     * @param privateKeyHex 私钥十六进制字符
     * @return 私钥
     * @throws Exception 异常
     */
    public PrivateKey buildPrivateKey(String privateKeyHex) throws Exception {
        try {
            if (privateKeyHex == null || privateKeyHex.trim().isEmpty()) {
                throw new IllegalArgumentException("Private keys cannot be empty");
            }

            if (privateKeyHex.startsWith("0x")) {
                privateKeyHex = privateKeyHex.substring(2);
            }

            BigInteger privateKeyValue = new BigInteger(privateKeyHex, 16);
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);

            org.bouncycastle.jce.spec.ECPrivateKeySpec privateKeySpec =
                    new org.bouncycastle.jce.spec.ECPrivateKeySpec(privateKeyValue, ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            logger.error("Failed to build the private key: {}", privateKeyHex, e);
            throw new Exception("Failed to build the private key: " + e.getMessage(), e);
        }
    }


    /**
     * 从坐标构建公钥
     * @param xHex x坐标
     * @param yHex y坐标
     * @return 公钥
     * @throws Exception 异常
     */
    public PublicKey buildPublicKey(String xHex, String yHex) throws Exception {
        try {
            if (xHex == null || yHex == null || xHex.trim().isEmpty() || yHex.trim().isEmpty()) {
                throw new IllegalArgumentException("The coordinates of the public key cannot be empty");
            }

            if (xHex.startsWith("0x")) xHex = xHex.substring(2);
            if (yHex.startsWith("0x")) yHex = yHex.substring(2);

            BigInteger x = new BigInteger(xHex, 16);
            BigInteger y = new BigInteger(yHex, 16);

            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
            ECPoint point = ecSpec.getCurve().createPoint(x, y, false);

            org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec =
                    new org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            logger.error("Failed to build the public key: x={}, y={}", xHex, yHex, e);
            throw new Exception("Failed to build the public key: " + e.getMessage(), e);
        }
    }

    // ==================== ECDSA数字签名 ====================
    /**
     * 签名
     * @param message 数据
     * @param privateKey 私钥
     * @return 签名
     * @throws Exception 异常
     */
    public String sign(String message, PrivateKey privateKey) throws Exception {
        try {
            if (message == null || message.isEmpty()) {
                throw new IllegalArgumentException("The message to be signed cannot be empty");
            }
            if (privateKey == null) {
                throw new IllegalArgumentException("Private keys cannot be empty");
            }

            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initSign(privateKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = signature.sign();
            return bytesToHex(signatureBytes);
        } catch (Exception e) {
            logger.error("ECDSA Signature failed", e);
            throw new Exception("ECDSA Signature failed: " + e.getMessage(), e);
        }
    }

    /**
     *  ECDSA 签名
     * @param message 数据
     * @return 签名
     * @throws Exception 异常
     */
    public String sign(String message) throws Exception {
        return sign(message, buildPrivateKey(eccAutoConfigProperties.getPrivateKey()));
    }

    /**
     * ECDSA 验签
     * @param message 数据
     * @param signatureHex 签名
     * @param publicKey 发送方公钥
     * @return 结果
     * @throws Exception 异常
     */
    public boolean verify(String message, String signatureHex, PublicKey publicKey) throws Exception {
        try {
            if (message == null || message.isEmpty()) {
                throw new IllegalArgumentException("The pending validation message cannot be empty");
            }
            if (signatureHex == null || signatureHex.trim().isEmpty()) {
                throw new IllegalArgumentException("The signature cannot be empty");
            }
            if (publicKey == null) {
                throw new IllegalArgumentException("The public key cannot be empty");
            }

            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initVerify(publicKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = hexToBytes(signatureHex);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            logger.error("ECDSA Failed to verify the visa", e);
            throw new Exception("ECDSA Failed to verify the visa: " + e.getMessage(), e);
        }
    }


    // ==================== ECIES加密解密 ====================

    /**
     * @return ECIES 加密 用户公钥 + 临时私钥 加密
     * @param plaintext 需要加密的数据
     * @param recipientPublicKey 用户公钥
     * @throws Exception 异常
     */
    public EccSecurityData encrypt(String plaintext, PublicKey recipientPublicKey) throws Exception {
        try {
            if (plaintext == null || plaintext.isEmpty()) {
                throw new IllegalArgumentException("Plain text cannot be empty");
            }
            if (recipientPublicKey == null) {
                throw new IllegalArgumentException("The receiver's public key cannot be empty");
            }

            // 1. 生成临时密钥对
            KeyPair ephemeralKeyPair = generateKeyPair();

            // 2. 执行ECDH密钥交换
            byte[] sharedSecret = performECDH(ephemeralKeyPair.getPrivate(), recipientPublicKey);

            // 3. 派生AES密钥
            byte[] aesKey = deriveAESKey(sharedSecret);

            // 4. 生成随机IV
            byte[] iv = generateRandomIV();

            // 5. AES-GCM加密
            String ciphertext = encryptAESGCM(plaintext, aesKey, iv);

            // 6. 获取临时公钥坐标
            org.bouncycastle.jce.interfaces.ECPublicKey bcPublicKey =
                    (org.bouncycastle.jce.interfaces.ECPublicKey) ephemeralKeyPair.getPublic();
            ECPoint point = bcPublicKey.getQ();

            // 使用String.format确保64位长度
            String ephemeralPublicKeyX = String.format("%064x", point.getX().toBigInteger());
            String ephemeralPublicKeyY = String.format("%064x", point.getY().toBigInteger());
            // 签名
            String serverSign = this.sign(ciphertext);
            // 7. 返回加密结果
            return new EccSecurityData(ciphertext, bytesToHex(iv), serverSign, new TempPublicKey(ephemeralPublicKeyX, ephemeralPublicKeyY));

        } catch (Exception e) {
            logger.error("ECIES Encryption failed", e);
            throw new Exception("ECIES Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * ECIES 加密
     * @param plaintext 明文
     * @param publicKeyX 公钥x坐标
     * @param publicKeyY 公钥y坐标
     * @return 密文
     * @throws Exception 异常
     */
    public EccSecurityData encrypt(String plaintext, String publicKeyX, String publicKeyY) throws Exception {
        return encrypt(plaintext, buildPublicKey(publicKeyX, publicKeyY));
    }


    /**
     *  ECIES 解密 服务器私钥 + 临时公钥
     * @param eccSecurityData 需要解密的数据
     * @param recipientPrivateKey 服务器私钥
     * @return 解密的数据
     * @throws Exception 异常
     */
    public String decrypt(EccSecurityData eccSecurityData, PrivateKey recipientPrivateKey) throws Exception {
        try {
            validParams(eccSecurityData, recipientPrivateKey);

            // 1. 重建临时公钥
            PublicKey ephemeralPublicKey = buildPublicKey(
                    eccSecurityData.getTempPublicKey().getX(),
                    eccSecurityData.getTempPublicKey().getY()
            );

            // 2. 执行ECDH密钥交换
            byte[] sharedSecret = performECDH(recipientPrivateKey, ephemeralPublicKey);

            // 3. 派生AES密钥
            byte[] aesKey = deriveAESKey(sharedSecret);

            // 4. AES-GCM解密
            return decryptAESGCM(eccSecurityData.getCiphertext(), aesKey, eccSecurityData.getIv());
        } catch (Exception e) {
            logger.error("ECIES Decryption failed", e);
            throw new Exception("ECIES Decryption failed: " + e.getMessage(), e);
        }
    }

    private void validParams(EccSecurityData eccSecurityData, PrivateKey recipientPrivateKey) {
        if (eccSecurityData == null) {
            throw new IllegalArgumentException("Encrypted data cannot be empty");
        }
        if (recipientPrivateKey == null) {
            throw new IllegalArgumentException("The private key of the receiver cannot be empty");
        }
        if (!StringUtils.hasLength(eccSecurityData.getSignature())) {
            throw new IllegalArgumentException("The signature is empty");
        }
        if (!StringUtils.hasLength(eccSecurityData.getCiphertext())) {
            throw new IllegalArgumentException("The ciphertext is empty");
        }
        if (eccSecurityData.getTempPublicKey() == null || !StringUtils.hasLength(eccSecurityData.getTempPublicKey().getX())
                || !StringUtils.hasLength(eccSecurityData.getTempPublicKey().getY())) {
            throw new IllegalArgumentException("There is an error in the temporary public key");
        }

    }

    /**
     * ECIES 解密
     * @param eccSecurityData 需要解密的数据
     * @return 解密的数据
     * @throws Exception 异常
     */
    public String decrypt(EccSecurityData eccSecurityData) throws Exception {
        return decrypt(eccSecurityData, eccAutoConfigProperties.getPrivateKey());
    }


    /**
     * ECIES 解密
     * @param eccSecurityData 需要解密的数据
     * @param recipientPrivateKey 临时私钥
     * @return 明文
     * @throws Exception 异常
     */
    public String decrypt(EccSecurityData eccSecurityData, String recipientPrivateKey) throws Exception {
        return decrypt(eccSecurityData, buildPrivateKey(recipientPrivateKey));
    }

    // ==================== 私有辅助方法 ====================

    /**
     * @return 执行ECDH密钥交换
     */
    private byte[] performECDH(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ECDH_ALGORITHM, "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    /**
     * @return 从共享密钥派生AES密钥
     */
    private byte[] deriveAESKey(byte[] sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(sharedSecret);
        return Arrays.copyOf(hash, AES_KEY_SIZE);
    }

    /**
     * @return 生成随机IV
     */
    private byte[] generateRandomIV() {
        byte[] iv = new byte[GCM_IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * @return AES-GCM加密
     */
    private String encryptAESGCM(String plaintext, byte[] key, byte[] iv) throws Exception {
        try {
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters = new AEADParameters(
                    new KeyParameter(key),
                    MAC_SIZE,
                    iv,
                    null
            );

            cipher.init(true, parameters); // true = 加密模式

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = new byte[cipher.getOutputSize(plaintextBytes.length)];

            int len = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, encryptedBytes, 0);
            len += cipher.doFinal(encryptedBytes, len);

            byte[] result = new byte[len];
            System.arraycopy(encryptedBytes, 0, result, 0, len);

            return bytesToHex(result);
        } catch (Exception e) {
            throw new Exception("AES-GCM Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * @return AES-GCM解密
     */
    private String decryptAESGCM(String ciphertextHex, byte[] key, String ivHex) throws Exception {
        try {
            if (ciphertextHex == null || ciphertextHex.isEmpty()) {
                throw new IllegalArgumentException("Ciphertext cannot be empty");
            }
            if (key == null || key.length != AES_KEY_SIZE) {
                throw new IllegalArgumentException("The key must be 32 bytes");
            }
            if (ivHex == null || ivHex.isEmpty()) {
                throw new IllegalArgumentException("IV cannot be empty");
            }

            byte[] ciphertext = hexToBytes(ciphertextHex);
            byte[] iv = hexToBytes(ivHex);

            if (iv.length != GCM_IV_SIZE) {
                throw new IllegalArgumentException("IV must be 12 bytes long");
            }

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters = new AEADParameters(
                    new KeyParameter(key),
                    MAC_SIZE,
                    iv,
                    null
            );

            cipher.init(false, parameters); // false = 解密模式

            byte[] decryptedBytes = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.processBytes(ciphertext, 0, ciphertext.length, decryptedBytes, 0);
            len += cipher.doFinal(decryptedBytes, len);

            byte[] result = new byte[len];
            System.arraycopy(decryptedBytes, 0, result, 0, len);

            return new String(result, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new Exception("AES-GCM Decryption failed: " + e.getMessage(), e);
        }
    }


    // ==================== 工具方法 ====================

    public ServerPublicKeyData getServerPublicData() {
        return new ServerPublicKeyData(eccAutoConfigProperties);
    }

    /**
     * @return 字节数组转十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * @return 十六进制字符串转字节数组
     */
    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }


    /**
     *
     * @param publicKey 公钥
     * @return 获取公钥的十六进制表示
     */
    public String getPublicKeyHex(PublicKey publicKey) {
        org.bouncycastle.jce.interfaces.ECPublicKey bcPublicKey =
                (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
        ECPoint point = bcPublicKey.getQ();

        String x = point.getX().toBigInteger().toString(16);
        String y = point.getY().toBigInteger().toString(16);

        return "04" + String.format("%064s", x).replace(' ', '0') +
                String.format("%064s", y).replace(' ', '0');
    }


    /**
     *
     * @param privateKey 私钥
     * @return 获取私钥的十六进制表示
     */
    public String getPrivateKeyHex(PrivateKey privateKey) {
        try {
            if (privateKey == null) {
                throw new IllegalArgumentException("Private keys cannot be empty");
            }

            org.bouncycastle.jce.interfaces.ECPrivateKey bcPrivateKey =
                    (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;

            BigInteger d = bcPrivateKey.getD();

            // 格式化为64位十六进制字符串
            return String.format("%064s", d.toString(16)).replace(' ', '0');

        } catch (ClassCastException e) {
            throw new IllegalArgumentException("The private key provided is not an ECC private key", e);
        } catch (Exception e) {
            throw new RuntimeException("Getting the private key hexadecimal indicates a failure: " + e.getMessage(), e);
        }
    }
}
/**
 * ECC解密业务服务
 */
package io.github.jasonlat.middleware.domain.service;

import com.alibaba.fastjson2.JSON;
import io.github.jasonlat.middleware.context.EccContextHolder;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.model.entity.ServerPublicKeyData;
import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import io.github.jasonlat.middleware.util.ECCCryptoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.PublicKey;


/**
 * @author jasonlat
 */
@Service
public final class ECCSecurityService {
    
    private static final Logger logger = LoggerFactory.getLogger(ECCSecurityService.class);

    private final ECCCryptoUtil eccCryptoUtil;

    public ECCSecurityService(ECCCryptoUtil eccCryptoUtil) {
        this.eccCryptoUtil = eccCryptoUtil;
    }

    /**
     * 解密服务方法
     * @param eccSecurityData 密文
     * @return 明文
     */
    public String decrypt(EccSecurityData eccSecurityData)  {
        // 验证输入参数
        validateInput(eccSecurityData);
        try {
            // 执行解密
            String decrypt = eccCryptoUtil.decrypt(eccSecurityData);

            logger.info("ECIES Decryption was successful: {}，Message length: {} characters", decrypt, decrypt.length());
            return decrypt;

        } catch (Exception e) {
            logger.error("ECIES Decryption failed: {}", e.getMessage(), e);
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 解密服务方法
     * @param encryptedData 密文
     * @return 明文
     */
    public String decrypt(String encryptedData)  {
        return decrypt(JSON.parseObject(encryptedData, EccSecurityData.class));
    }
    
    /**
     *
     * @param eccSecurityData 验证输入参数
     */
    private void validateInput(EccSecurityData eccSecurityData) {

        if (eccSecurityData == null) {
            throw new IllegalArgumentException("Encrypted data cannot be empty");
        }

        if (!StringUtils.hasLength(eccSecurityData.getCiphertext())) {
            throw new IllegalArgumentException("Ciphertext cannot be empty");
        }

        if (eccSecurityData.getIv() == null ) {
            throw new IllegalArgumentException("IV cannot be empty");
        }

        if (!StringUtils.hasLength(eccSecurityData.getTempPublicKey().getX()) || !StringUtils.hasLength(eccSecurityData.getTempPublicKey().getY())) {
            throw new IllegalArgumentException("Temporary public key coordinates cannot be empty");
        }
        

    }


    /**
     * 加密
     * @param message 信息
     * @param publicKeyX x坐标
     * @param publicKeyY y坐标
     * @return 密文
     * @throws Exception 异常
     */
    public EccSecurityData encrypt(String message, String publicKeyX, String publicKeyY) throws Exception {
        return eccCryptoUtil.encrypt(message, publicKeyX, publicKeyY);
    }


    public boolean verify(String message, String signatureHex, String publicKeyX, String publicKeyY) throws Exception {
        PublicKey usePpublicKey = eccCryptoUtil.buildPublicKey(publicKeyX, publicKeyY);
        return eccCryptoUtil.verify(message, signatureHex, usePpublicKey);
    }

    public ServerPublicKeyData getServerPublicData() {
        return eccCryptoUtil.getServerPublicData();
    }


}
package io.github.jasonlat.middleware.domain.service.engine.impl;

import com.alibaba.fastjson2.JSONObject;
import io.github.jasonlat.middleware.annotations.decrypt.RequestDecryption;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.service.ECCSecurityService;
import io.github.jasonlat.middleware.domain.service.engine.HandelDecryptEngine;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service("registerDecrypt")
public final class RegisterDecryptEngine implements HandelDecryptEngine {

    private final ECCSecurityService eccSecurityService;

    public RegisterDecryptEngine(ECCSecurityService eccSecurityService) {
        this.eccSecurityService = eccSecurityService;
    }

    @Override
    public String handelDecrypt(EccSecurityData eccSecurityData, RequestDecryption annotation) throws Exception {
        // 注册接口，先解密
        String decryptedData = eccSecurityService.decrypt(eccSecurityData);
        // 获取发送来的公钥字段
        JSONObject jsonObject = JSONObject.parseObject(decryptedData);
        String userPublicX = jsonObject.getString(annotation.registerPublicXKey());
        String userPublicY = jsonObject.getString(annotation.registerPublicYKey());
        if (!StringUtils.hasLength(userPublicX) || !StringUtils.hasLength(userPublicY)) {
            throw new ReplayProtectionException("userPublicX or userPublicY is empty, please specify a public, SuchAs: \n" +
                    "{\n" +
                    "  \"userPublicX\": \"xValue\",\n" +
                    "  \"userPublicY\": \"yValue\",\n" +
                    "  \"data\": {\n" +
                    "    \"key\": \"value\"\n" +
                    "  }\n" +
                    "}");
        }
        // 解密
        boolean verify = eccSecurityService.verify(eccSecurityData.getCiphertext(), eccSecurityData.getSignature(), userPublicX, userPublicY);
        if (!verify) {
            throw new ReplayProtectionException("signature verification failed");
        }
        return decryptedData;
    }
}

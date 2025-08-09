package io.github.jasonlat.middleware.domain.service.engine.impl;

import com.alibaba.fastjson2.JSONObject;
import io.github.jasonlat.middleware.annotations.decrypt.RequestDecryption;
import io.github.jasonlat.middleware.context.EccContextHolder;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import io.github.jasonlat.middleware.domain.service.ECCSecurityService;
import io.github.jasonlat.middleware.domain.service.EccUserDataService;
import io.github.jasonlat.middleware.domain.service.engine.HandelDecryptEngine;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service("notIdentificationDecrypt")
public final class NotIdentificationDecryptEngine implements HandelDecryptEngine {

    private final ECCSecurityService eccSecurityService;
    private final EccContextHolder contextHolder;
    public NotIdentificationDecryptEngine(ECCSecurityService eccSecurityService, EccContextHolder contextHolder) {
        this.eccSecurityService = eccSecurityService;
        this.contextHolder = contextHolder;
    }

    @Override
    public String handelDecrypt(EccSecurityData eccSecurityData, RequestDecryption annotation) throws Exception {
        // 表示未鉴权的接口，比如登录, 先解密, 如果没有报错，就解密成功
        String decryptedData = eccSecurityService.decrypt(eccSecurityData);
        // 获取 username 字段
        JSONObject jsonObject = JSONObject.parseObject(decryptedData);
        String username = jsonObject.getString(annotation.notIdentUniqueUserKey());
        if (!StringUtils.hasLength(username)) {
            // 请将用户名添加到明文json中加密
            throw new ReplayProtectionException(
                    "username is empty, please specify a username, SuchAs: \n" +
                            "{\n" +
                            "  \"username\": \"username\",\n" +
                            "  \"data\": {\n" +
                            "    \"key\": \"value\"\n" +
                            "  }\n" +
                            "}"
            );
        }
        // 获取用户名成功，获取用户公钥
        UserPublicData userData = contextHolder.getAuthenticationUserPublicData(username);
        // 解密
        boolean verify = eccSecurityService.verify(eccSecurityData.getCiphertext(), eccSecurityData.getSignature(), userData.getX(), userData.getY());
        if (!verify) {
            throw new ReplayProtectionException("signature verification failed");
        }
        return decryptedData;
    }
}

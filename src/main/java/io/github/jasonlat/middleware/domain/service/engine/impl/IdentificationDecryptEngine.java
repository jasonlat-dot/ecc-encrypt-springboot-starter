package io.github.jasonlat.middleware.domain.service.engine.impl;

import io.github.jasonlat.middleware.annotations.decrypt.RequestDecryption;
import io.github.jasonlat.middleware.context.EccContextHolder;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import io.github.jasonlat.middleware.domain.service.ECCSecurityService;
import io.github.jasonlat.middleware.domain.service.engine.HandelDecryptEngine;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
import org.springframework.stereotype.Service;

@Service("identificationDecrypt")
public final class IdentificationDecryptEngine implements HandelDecryptEngine {

    private final ECCSecurityService eccSecurityService;
    private final EccContextHolder contextHolder;

    public IdentificationDecryptEngine(ECCSecurityService eccSecurityService, EccContextHolder contextHolder) {
        this.eccSecurityService = eccSecurityService;
        this.contextHolder = contextHolder;
    }

    @Override
    public String handelDecrypt(EccSecurityData eccSecurityData, RequestDecryption annotation) throws Exception {
        // 正常的认证请求
        // 0. Verify signatures
        UserPublicData currentUserPublicData = contextHolder.getAuthenticationUserPublicData();
        assert currentUserPublicData != null;

        // 验签
        boolean verify = eccSecurityService.verify(eccSecurityData.getCiphertext(), eccSecurityData.getSignature(), currentUserPublicData.getX(), currentUserPublicData.getY());
        if (!verify) {
            throw new ReplayProtectionException("signature verification failed");
        }
        // 解密
        return eccSecurityService.decrypt(eccSecurityData);
    }
}

package io.github.jasonlat.middleware.domain.service.engine;

import io.github.jasonlat.middleware.annotations.decrypt.RequestDecryption;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;

public interface HandelDecryptEngine {
    String handelDecrypt( EccSecurityData eccSecurityData, RequestDecryption annotation) throws Exception;
}

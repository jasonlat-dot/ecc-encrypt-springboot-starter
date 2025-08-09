package io.github.jasonlat.middleware.domain.service.engine.factory;

import io.github.jasonlat.middleware.domain.model.valobj.EccDecryptType;
import io.github.jasonlat.middleware.domain.service.engine.HandelDecryptEngine;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.util.Map;


@Getter
@Component
public class DefaultHandelEncryptFactory {

    private final Map<String, HandelDecryptEngine> handelDecryptMap;

    public DefaultHandelEncryptFactory(Map<String, HandelDecryptEngine> handelDecryptMap) {
        this.handelDecryptMap = handelDecryptMap;
    }

    /**
     * 获取解密实例
     * @param encryptKey key
     * @return 解密的实例
     */
    private HandelDecryptEngine getHandelDecrypt(String encryptKey) {
        return handelDecryptMap.get(encryptKey);
    }

    /**
     * 获取解密实例
     * @param eccDecryptType 解密类型
     * @return 解密实例
     */
    public HandelDecryptEngine getHandelDecrypt(EccDecryptType eccDecryptType) {
        switch (eccDecryptType) {
            case NOT_IDENTIFICATION:
                return getHandelDecrypt(HandelDecryptType.NOT_IDENTIFICATION.key);
            case REGISTER:
                return getHandelDecrypt(HandelDecryptType.REGISTER.key);

            default:
                return getHandelDecrypt(HandelDecryptType.IDENTIFICATION.key);
        }
    }



    @Getter
    @AllArgsConstructor
    private enum HandelDecryptType {
        NOT_IDENTIFICATION("notIdentificationDecrypt"),
        REGISTER("registerDecrypt"),
        IDENTIFICATION("identificationDecrypt"),
        ;

        private final String key;
    }

}

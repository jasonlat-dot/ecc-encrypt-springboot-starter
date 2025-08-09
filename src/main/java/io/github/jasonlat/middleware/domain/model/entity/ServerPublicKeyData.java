package io.github.jasonlat.middleware.domain.model.entity;

import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

/**
 * 服务器公钥数据单例类
 * 使用饿汉式单例模式，线程安全且性能优秀
 *
 * @author jasonlat
 */
@AllArgsConstructor
@Builder
@Data
public final class ServerPublicKeyData implements Serializable {

    private final PublicKey publicKey;
    private final Long timestamp;

    public ServerPublicKeyData(EccAutoConfigProperties eccAutoConfigProperties) {
        this.publicKey = PublicKey.getInstance(eccAutoConfigProperties);
        this.timestamp = System.currentTimeMillis();
    }


}
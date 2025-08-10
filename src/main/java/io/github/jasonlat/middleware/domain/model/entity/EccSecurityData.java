package io.github.jasonlat.middleware.domain.model.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

/**
 * @author jasonlat
 */
@AllArgsConstructor
@Builder
@Data
public final class EccSecurityData {

    /** 加密后的数据 */
    @JsonProperty("ciphertext")
    private final String ciphertext;

    /** 初始化向量 */
    @JsonProperty("iv")
    private final String iv;


    /** 对原始消息的数字签名 */
    @JsonProperty("signature")
    private final String signature;

    @JsonProperty("tempPublicKey")
    private final TempPublicKey tempPublicKey;



}
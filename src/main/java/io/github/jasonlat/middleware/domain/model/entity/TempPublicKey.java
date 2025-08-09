package io.github.jasonlat.middleware.domain.model.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Builder
@Data
 public  class TempPublicKey {
        /** 临时公钥X坐标 */
        @JsonProperty("x")
        private final String x;

        /** 临时公钥Y坐标 */
        @JsonProperty("y")
        private final String y;
    }
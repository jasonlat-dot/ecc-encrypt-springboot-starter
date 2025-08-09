package io.github.jasonlat.middleware.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * @author jasonlat
 */
@AllArgsConstructor
@Builder
@Data
@Slf4j
public final class UserPublicData {
    private String x;
    private String y;

    /**
     * 清理公钥数据中的敏感信息
     */
    public void clearSensitiveData() {
        // 清理公钥字符串
        this.x = null;
        this.y = null;
        log.debug("已清理UserPublicData敏感数据");
    }
}

package io.github.jasonlat.middleware.context;

import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author jasonlat
 */
@Data
@Slf4j
public final class EccContext {

    private UserPublicData userPublicData;
    private String user;
    private String sessionId;
    private LocalDateTime loadTime;
    private ConcurrentHashMap<String, Object> attributes;
    
    public static EccContext of(String user, UserPublicData userData) {
        EccContext context = new EccContext();
        context.setUser(user);
        context.setUserPublicData(userData);
        context.setLoadTime(LocalDateTime.now());
        context.setAttributes(new ConcurrentHashMap<>());
        return context;
    }

    /**
     * 清理敏感数据
     * 在缓存驱逐时调用，确保敏感信息不会在内存中残留
     */
    public void clearSensitiveData() {
        // 清理用户公钥数据
        if (this.userPublicData != null) {
            this.userPublicData.clearSensitiveData();
            this.userPublicData = null;
        }

        // 清理会话ID（可能包含敏感信息）
        if (this.sessionId != null) {
            // 用零填充字符串内存（安全清理）
            char[] sessionChars = this.sessionId.toCharArray();
            Arrays.fill(sessionChars, '\0');
            this.sessionId = null;
        }

        // 清理属性中的敏感数据
        if (this.attributes != null) {
            // 清理可能包含敏感信息的属性
            this.attributes.entrySet().removeIf(entry -> {
                String key = entry.getKey();
                return key.contains("password") ||
                        key.contains("secret") ||
                        key.contains("token") ||
                        key.contains("key");
            });

            // 如果属性为空，释放Map
            if (this.attributes.isEmpty()) {
                this.attributes = null;
            }
        }

        // 记录清理日志
        log.debug("已清理用户{}的ECC上下文敏感数据", this.user);
    }

    /**
     * @return 检查上下文是否已被清理
     */
    public boolean isCleared() {
        return this.userPublicData == null &&
                this.sessionId == null &&
                (this.attributes == null || this.attributes.isEmpty());
    }

}
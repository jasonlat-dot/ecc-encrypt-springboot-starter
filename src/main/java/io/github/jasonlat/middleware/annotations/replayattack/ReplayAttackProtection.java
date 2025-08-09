package io.github.jasonlat.middleware.annotations.replayattack;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 重放攻击保护注解
 * 用于标记需要进行重放攻击防护的方法或类
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ReplayAttackProtection {

    /**
     * @return 时间戳在前端请求头的Key
     */
    String requestHeaderKey() default "X-Timestamp";

    /**
     * @return 时间窗口（毫秒），默认5分钟
     * 超过此时间的请求将被视为过期
     */
    long timeWindow() default 5 * 60 * 1000L; // 5分钟
    
    /**
     * @return 缓存键前缀，用于区分不同业务场景
     */
    String cacheKeyPrefix() default "replay";
    
    /**
     * @return 错误消息
     */
    String message() default "检测到重放攻击";
    
    /**
     * @return 是否记录日志
     */
    boolean enableLog() default true;
    
    /**
     * @return 是否检查未来时间戳
     */
    boolean checkFutureTime() default true;
    
    /**
     * @return 未来时间容忍度（秒），默认60秒
     */
    long futureTimeTolerance() default 60L;
}
package io.github.jasonlat.middleware.annotations.uniquerequest;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 唯一请求保护注解
 * 用于标记需要进行唯一请求检测的方法或类
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface UniqueRequestProtection {

    /**
     * @return 时间戳在前端请求头的Key
     */
    String requestHeaderKey() default "X-Request-ID";
    
    /**
     * @return 错误消息
     */
    String message() default "检测到重复请求";
    
    /**
     * @return 是否记录日志
     */
    boolean enableLog() default true;
    
    /**
     * @return 是否启用严格模式
     * 严格模式下，即使是不同IP的相同RequestID也会被拒绝
     */
    boolean strictMode() default true;
}
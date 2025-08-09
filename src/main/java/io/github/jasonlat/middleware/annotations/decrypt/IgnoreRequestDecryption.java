package io.github.jasonlat.middleware.annotations.decrypt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 忽略请求解密注解
 * 用于在类级别启用请求解密时，忽略特定方法的解密处理
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface IgnoreRequestDecryption {
    
    /**
     * @return 忽略原因说明
     */
    String reason() default "业务需要忽略请求解密处理";
}
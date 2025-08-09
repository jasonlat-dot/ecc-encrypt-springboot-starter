package io.github.jasonlat.middleware.annotations.uniquerequest;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 忽略唯一请求保护注解
 * 用于在类级别启用唯一请求保护时，忽略特定方法的唯一请求检测
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface IgnoreUniqueRequest {
    
    /**
     * @return 忽略原因说明
     */
    String reason() default "业务需要忽略唯一请求检测";
}
package io.github.jasonlat.middleware.annotations.replayattack;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 忽略重放攻击保护注解
 * 用于在类级别启用重放攻击保护时，忽略特定方法的重放攻击检测
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface IgnoreReplayAttack {
    
    /**
     * @return 忽略原因说明
     */
    String reason() default "业务需要忽略重放攻击检测";
}
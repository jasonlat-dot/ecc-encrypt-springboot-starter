package io.github.jasonlat.middleware.annotations.encrypt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 请求加密注解
 * 用于标记需要对请求体进行加密处理的方法或类
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequestEncryption {

    /**
     *
     */

    /**
     * @return 是否启用压缩
     * 在加密前对数据进行压缩
     */
    boolean enableCompression() default false;
    
    /**
     * @return 压缩算法
     */
    String compressionAlgorithm() default "GZIP";
    
    /**
     * @return 错误消息
     */
    String message() default "请求加密处理失败";
    
    /**
     * @return 是否记录日志
     */
    boolean enableLog() default true;

    /**
     * @return 是否已经加密
     */
    String encryptStatusHeaderKey() default "encryptStatusHeader";

    /**
     * @return 是否已经加密
     */
    String encryptStatusHeaderValue() default "encrypt-complete";
}
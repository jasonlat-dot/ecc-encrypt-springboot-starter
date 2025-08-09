package io.github.jasonlat.middleware.annotations.decrypt;

import io.github.jasonlat.middleware.domain.model.valobj.EccDecryptType;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 请求解密注解
 * 用于标记需要对请求体进行解密处理的方法或类
 *
 * @author jasonlat
 * @since 1.0.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequestDecryption {

    /**
     * @return 是否启用解压缩
     * 在解密后对数据进行解压缩
     */
    boolean enableDecompression() default false;

    /**
     * @return 解压缩算法
     */
    String decompressionAlgorithm() default "GZIP";

    /**
     * @return 错误消息
     */
    String message() default "请求解密处理失败";

    /**
     * @return 是否记录日志
     */
    boolean enableLog() default true;

    /**
     * @return 解密后的数据类型
     * JSON: JSON字符串
     * OBJECT: Java对象
     * STRING: 普通字符串
     * BINARY: 二进制数据
     */
    String resultType() default "JSON";

    /**
     * @return 是否自动转换数据类型
     */
    boolean autoConvert() default true;

    /**
     * @return 解密类型
     * IDENTIFICATION 表示经过jwt认证的
     * NOT_IDENTIFICATION 没有经过认证的
     * REGISTER 注册请求
     */
    EccDecryptType requestType() default EccDecryptType.IDENTIFICATION;

    /**
     * 当 requestType 是 NOT_IDENTIFICATION 时，需要加密解密需要提供一个用户唯一标识
     * @return 户唯一标识在 json 中的key
     */
    String notIdentUniqueUserKey() default "username";

    /**
     *
     * @return 注册时，发送过来的用户公钥X在 json 中的key
     */
    String registerPublicXKey() default "userPublicX";

    /**
     *
     * @return 注册时，发送过来的用户公钥X在 json 中的key
     */
    String registerPublicYKey() default "userPublicY";
}
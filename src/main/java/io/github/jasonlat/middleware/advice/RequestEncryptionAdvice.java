package io.github.jasonlat.middleware.advice;

import com.alibaba.fastjson2.JSON;
import io.github.jasonlat.middleware.annotations.encrypt.IgnoreRequestEncryption;
import io.github.jasonlat.middleware.annotations.encrypt.RequestEncryption;
import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import io.github.jasonlat.middleware.context.EccContextHolder;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.model.entity.Response;
import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import io.github.jasonlat.middleware.domain.service.ECCSecurityService;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
//import io.github.jasonlat.middleware.domain.service.EccUserDataService;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;


import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

/**
 * 请求加密处理切面
 * 专门处理请求体加密逻辑
 * 
 * @author jasonlat
 */
@RestControllerAdvice
public final class RequestEncryptionAdvice implements ResponseBodyAdvice<Object> {

    private static final Logger logger = LoggerFactory.getLogger(RequestEncryptionAdvice.class);

    private final ECCSecurityService eccSecurityService;
    private final EccContextHolder contextHolder;
    private final EccAutoConfigProperties configProperties;
    private final HttpServletRequest request;
    public RequestEncryptionAdvice(ECCSecurityService eccSecurityService, EccContextHolder contextHolder, EccAutoConfigProperties configProperties, HttpServletRequest request) {
        this.eccSecurityService = eccSecurityService;
        this.contextHolder = contextHolder;
        this.configProperties = configProperties;
        this.request = request;
    }



    @Override
    public boolean supports(@NonNull MethodParameter returnType, @NonNull Class converterType) {

        if (!configProperties.isEnabled()) {
            logger.info("RequestDecryptionAdvice is disabled, please enable config.");
            return false;
        }

        Method method = returnType.getMethod();
        if (method == null) {
            return false;
        }
        // 获取请求方法类型
        String httpMethod = request.getMethod();

        // 排除 OPTIONS 请求
        if ("OPTIONS".equalsIgnoreCase(httpMethod)) {
            logger.debug("Skipping OPTIONS request");
            return false;
        }

        // Check if the method ignores annotations
        IgnoreRequestEncryption ignoreAnnotation = getIgnoreAnnotation(method);
        if (ignoreAnnotation != null) {
            logger.info("RequestDecryptionAdvice is ignored by @IgnoreRequestEncryption annotation. reason: {}", ignoreAnnotation.reason());
            return false;
        }

        // Check if a method or class has a request encryption annotation
        RequestEncryption annotation = getAnnotation(method);
        if (annotation == null) {
            return false;
        }
        if (annotation.notCertified() && !StringUtils.hasLength(annotation.user())) {
            logger.warn("not certified request encryption, need designate user().");
            return false;
        }

        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, @NonNull MethodParameter returnType, @NonNull MediaType selectedContentType, @NonNull Class selectedConverterType, @NonNull ServerHttpRequest request, @NonNull ServerHttpResponse response) {
        if (null == body) return null;
        Method method = returnType.getMethod();
        RequestEncryption annotation = getAnnotation(method);

        try {
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            // Encrypt the requesting body
            EccSecurityData encryptResponse = processEncryption(body, method);

            if (body instanceof Response) {
                // Provides some flexibility and does not package if the body is already packaged
                return body;
            }
            if (body instanceof String) {
                //解决返回值为字符串时，不能正常包装
                return JSON.toJSONString(Response.<EccSecurityData>builder()
                        .code("200")
                        .info("Success")
                        .data(encryptResponse)
                        .build());
            }

            return Response.<EccSecurityData>builder()
                    .code("200")
                    .info("Success")
                    .data(encryptResponse)
                    .build();
        } finally {
            response.getHeaders().set("Access-Control-Expose-Headers", annotation.encryptStatusHeaderKey());
            response.getHeaders().set(annotation.encryptStatusHeaderKey(), annotation.encryptStatusHeaderValue());

        }

    }

    /**
     * 获取注解配置（优先方法级别，其次类级别）
     * 
     * @param method 方法
     * @return 注解配置
     */
    private RequestEncryption getAnnotation(Method method) {
        // Get method-level annotations
        RequestEncryption methodAnnotation = AnnotationUtils.findAnnotation(method, RequestEncryption.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        
        // Get class-level annotations
        return AnnotationUtils.findAnnotation(method.getDeclaringClass(), RequestEncryption.class);
    }
    private IgnoreRequestEncryption getIgnoreAnnotation(Method method) {
        // Priority acquisition of method-level ignore annotations
        return AnnotationUtils.findAnnotation(method, IgnoreRequestEncryption.class);
    }
    
    /**
     * 处理加密逻辑
     * 
     * @param body 原始请求体
     * @param method 方法
     * @return 加密后的请求体
     */
    private EccSecurityData processEncryption(Object body, Method method) {
        RequestEncryption annotation = getAnnotation(method);

        try {
            // Convert the request body to a string
            String bodyString = convertToString(body);
            // Compression treatment
            if (annotation.enableCompression()) {
                bodyString = compressData(bodyString, annotation.compressionAlgorithm());
                if (annotation.enableLog()) {
                    logger.debug("the_request_body_is_compressed - Algorithm: {}", annotation.compressionAlgorithm());
                }
            }
            // Encrypted processing
            EccSecurityData securityData = encryptData(bodyString, annotation);
            if (annotation.enableLog()) {
                logger.info("the_requesting_body_encryption_is_complete - Method: {}", method.getName());
            }
            
            return securityData;
            
        } catch (Exception e) {
            logger.error("Request body encryption failed - Method: {}, Error: {}", method.getName(), e.getMessage(), e);
            throw new ReplayProtectionException (
                annotation.message() + ": " + e.getMessage(),
                "ENCRYPTION_FAILED",
                null,
                null
            );
        }
    }
    
    /**
     * 将对象转换为字符串
     * 
     * @param body 请求体对象
     * @return 字符串表示
     */
    private String convertToString(Object body) {
        if (body == null) {
            return "";
        }
        
        if (body instanceof String) {
            return (String) body;
        }
        
        if (body instanceof byte[]) {
            return new String((byte[]) body, StandardCharsets.UTF_8);
        }
        
        return JSON.toJSONString(body);
    }
    
    /**
     * 压缩数据
     * 
     * @param data 原始数据
     * @param algorithm 压缩算法
     * @return 压缩后的数据（Base64编码）
     */
    private String compressData(String data, String algorithm) throws Exception {
        if ("GZIP".equalsIgnoreCase(algorithm)) {
            ByteArrayOutputStream bass = new ByteArrayOutputStream();
            try (GZIPOutputStream gzipOut = new GZIPOutputStream(bass)) {
                gzipOut.write(data.getBytes(StandardCharsets.UTF_8));
            }
            return Base64.getEncoder().encodeToString(bass.toByteArray());
        }
        
        logger.warn("Unsupported compression algorithms: {}, Skip compression", algorithm);
        return data;
    }
    
    /**
     * 加密数据
     * 
     * @param data 原始数据
     * @param annotation 加密配置
     * @return 加密后的数据
     */
    private EccSecurityData encryptData(String data, RequestEncryption annotation) {
        if (annotation.enableLog()) {
            logger.info("data encrypt begin ...... ");
        }
        return encryptWithECC(data, annotation);
    }
    
    /**
     * ECC加密
     * 
     * @param data 原始数据
     * @return 加密后的数据
     */
    private EccSecurityData encryptWithECC(String data, RequestEncryption annotation)  {
        try {
            UserPublicData currentUserPublicData;
            if (annotation.notCertified()) {
                currentUserPublicData = contextHolder.getAuthenticationUserPublicData(annotation.user());
            } else {
                // 有jwt，无需指定 user()
                currentUserPublicData = contextHolder.getAuthenticationUserPublicData();
            }

            if (currentUserPublicData == null) {
                throw new ReplayProtectionException("用户密钥查询失败，无法进行数据加密");
            }
            // encryption
            return eccSecurityService.encrypt(data, currentUserPublicData.getX(), currentUserPublicData.getY());
        } catch (Exception e) {
            logger.error("Ecc Encryption failed: {}", e.getMessage(), e);
            throw new ReplayProtectionException(
                "ECC Encryption failed: " + e.getMessage(),
                "ECC_ENCRYPTION_FAILED",
                null, null
            );
        }
    }


}
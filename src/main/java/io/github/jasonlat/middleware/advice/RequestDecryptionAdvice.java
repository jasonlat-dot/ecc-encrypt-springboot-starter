package io.github.jasonlat.middleware.advice;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.TypeReference;
import io.github.jasonlat.middleware.annotations.decrypt.IgnoreRequestDecryption;
import io.github.jasonlat.middleware.annotations.decrypt.RequestDecryption;
import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import io.github.jasonlat.middleware.domain.model.entity.DecryptHttpInputMessage;
import io.github.jasonlat.middleware.domain.model.entity.EccSecurityData;
import io.github.jasonlat.middleware.domain.service.engine.HandelDecryptEngine;
import io.github.jasonlat.middleware.domain.service.engine.factory.DefaultHandelEncryptFactory;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
import lombok.NonNull;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

/**
 * 请求解密处理切面
 * 专门处理请求体解密逻辑
 * 
 * @author jasonlat
 */
@ControllerAdvice
public final class RequestDecryptionAdvice implements RequestBodyAdvice {
    
    private static final Logger logger = LoggerFactory.getLogger(RequestDecryptionAdvice.class);

    private final EccAutoConfigProperties configProperties;
    private final HttpServletRequest request;
    private final DefaultHandelEncryptFactory handelEncryptFactory;
    public RequestDecryptionAdvice(EccAutoConfigProperties configProperties, HttpServletRequest request, DefaultHandelEncryptFactory handelEncryptFactory) {
        this.configProperties = configProperties;
        this.request = request;
        this.handelEncryptFactory = handelEncryptFactory;
    }

    @Override
    public boolean supports(@NonNull MethodParameter methodParameter, @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        if (!configProperties.isEnabled()) {
            logger.info("RequestDecryptionAdvice is disabled, please enable config.");
            return false;
        }
        
        Method method = methodParameter.getMethod();
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
        
        // 检查方法是否有忽略注解
        IgnoreRequestDecryption ignoreAnnotation = getIgnoreAnnotation(method);
        if (ignoreAnnotation != null) {
            logger.debug("Method {} is marked to ignore request decryption processing, reason: {}", method.getName(), ignoreAnnotation.reason());
            return false;
        }
        
        // 检查方法或类是否有请求解密注解
        RequestDecryption annotation = getAnnotation(method);
        boolean hasAnnotation = annotation != null;
        
        if (hasAnnotation) {
            logger.debug("Method {} requires decryption request", method.getName());
        }

        return hasAnnotation;
    }
    
    @Override
    @NonNull
    public HttpInputMessage beforeBodyRead(@NonNull HttpInputMessage inputMessage, MethodParameter parameter,
                                           @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        // 指定字符编码, 将请求体的内容读取为字符串
        String bodyString = IOUtils.toString(inputMessage.getBody(), StandardCharsets.UTF_8);

        Method method = parameter.getMethod();
        if (method != null) {
            // Preprocess before reading the request body
            RequestDecryption annotation = getAnnotation(method);
            if (annotation != null && annotation.enableLog()) {
                logger.info("begin_processing_the_request_decryption - Method: {},", method.getName());
                String decryptBody = processDecryption(bodyString, method);
                InputStream inputStream = IOUtils.toInputStream(decryptBody, StandardCharsets.UTF_8);
                // 返回解密后的数据
                logger.info("end_processing_the_request_decryption - Method: {},", method.getName());
                return new DecryptHttpInputMessage(inputStream, inputMessage.getHeaders());
            }
        }

        return inputMessage;
    }
    
    @Override
    @NonNull
    public Object afterBodyRead(@NonNull Object body, @NonNull HttpInputMessage inputMessage, MethodParameter parameter,
                                @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {

        return body;
    }
    
    @Override
    public Object handleEmptyBody(Object body, @NonNull HttpInputMessage inputMessage, MethodParameter parameter,
                                  @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        
        Method method = parameter.getMethod();
        if (method != null) {
            RequestDecryption annotation = getAnnotation(method);
            if (annotation != null && annotation.enableLog()) {
                logger.debug("处理空请求体解密 - Method: {}", method.getName());
            }
        }
        
        return body;
    }
    
    /**
     * 获取注解配置（优先方法级别，其次类级别）
     * 
     * @param method 方法
     * @return 注解配置
     */
    private RequestDecryption getAnnotation(Method method) {
        // Priority acquisition of method-level annotations
        RequestDecryption methodAnnotation = AnnotationUtils.findAnnotation(method, RequestDecryption.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        
        // Get class-level annotations
        return AnnotationUtils.findAnnotation(method.getDeclaringClass(), RequestDecryption.class);
    }

    private IgnoreRequestDecryption getIgnoreAnnotation(Method method) {
        // Priority acquisition of method-level ignore annotations
        return AnnotationUtils.findAnnotation(method, IgnoreRequestDecryption.class);
    }
    
    /**
     * 处理解密逻辑
     * 
     * @param body 加密的请求体
     * @param method 方法
     * @return 解密后的请求体
     */
    private String processDecryption(String body, Method method) {
        
        RequestDecryption annotation = getAnnotation(method);
        if (annotation == null) {
            return body;
        }
        
        try {
            if (!StringUtils.hasText(body)) {
                logger.warn("The request body is empty, and the decryption process is skipped");
                return body;
            }

            // 转换对象
            EccSecurityData eccSecurityData = JSON.parseObject(body, EccSecurityData.class);
            // 解密
            HandelDecryptEngine handelDecryptEngine = handelEncryptFactory.getHandelDecrypt(annotation.requestType());
            String decryptedData = handelDecryptEngine.handelDecrypt(eccSecurityData, annotation);

            // Unzip the process
            if (annotation.enableDecompression()) {
                decryptedData = decompressData(decryptedData, annotation.decompressionAlgorithm());
                if (annotation.enableLog()) {
                    logger.debug("The request body is decompressed - Algorithm: {}", annotation.decompressionAlgorithm());
                }
            }

            if (annotation.enableLog()) {
                logger.info("The requesting body is decrypted - Method: {}, ResultType: {}", method.getName(),  annotation.resultType());
            }
            
            return decryptedData;
            
        } catch (Exception e) {
            logger.error("Request body decryption failed - Method: {}, Error: {}", method.getName(), e.getMessage(), e);
            throw new ReplayProtectionException(
                annotation.message() + ": " + e.getMessage(),
                "DECRYPTION_FAILED",
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
     * 解压缩数据
     * 
     * @param data 压缩数据（Base64编码）
     * @param algorithm 解压缩算法
     * @return 解压缩后的数据
     */
    private String decompressData(String data, String algorithm) throws Exception {
        if ("GZIP".equalsIgnoreCase(algorithm)) {
            byte[] compressedData = Base64.getDecoder().decode(data);
            ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            
            try (GZIPInputStream gzipIn = new GZIPInputStream(bais)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = gzipIn.read(buffer)) != -1) {
                    baos.write(buffer, 0, len);
                }
            }
            
            return new String(baos.toByteArray(), StandardCharsets.UTF_8);
        }
        
        // Other decompression algorithms can be added here
        logger.warn("Unsupported decompression algorithms: {}, skip decompression", algorithm);
        return data;
    }
    
    /**
     * 转换为目标类型
     * 
     * @param decryptedData 解密后的数据
     * @param annotation 注解配置
     * @param targetType 目标类型
     * @return 转换后的对象
     */
    private Object convertToTargetType(String decryptedData, RequestDecryption annotation, Type targetType) {
        
        String resultType = annotation.resultType();
        boolean autoConvert = annotation.autoConvert();
        
        // If you don't enable automatic conversion, return the string directly
        if (!autoConvert) {
            return decryptedData;
        }
        
        switch (resultType.toUpperCase()) {
            case "JSON":
                // Try to parse to JSON objects
                if (targetType == String.class) {
                    return decryptedData;
                }
                return JSON.parseObject(decryptedData, new TypeReference<Object>(targetType) {});
            case "OBJECT":
                // Resolves to Java objects
                return JSON.parseObject(decryptedData, new TypeReference<Object>(targetType) {});
            case "STRING":
                // Return a string
                return decryptedData;
                
            case "BINARY":
                // Returns binary data
                return decryptedData.getBytes(StandardCharsets.UTF_8);
            default:
                logger.warn("Unsupported result type: {}, returns a string", resultType);
                return decryptedData;
        }
    }
    
}
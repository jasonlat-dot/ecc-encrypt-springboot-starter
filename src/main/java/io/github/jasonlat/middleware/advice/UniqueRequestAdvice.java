package io.github.jasonlat.middleware.advice;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.github.jasonlat.middleware.annotations.uniquerequest.IgnoreUniqueRequest;
import io.github.jasonlat.middleware.annotations.uniquerequest.UniqueRequestProtection;
import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import io.github.jasonlat.middleware.domain.model.entity.RequestInfo;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.concurrent.TimeUnit;

/**
 * 唯一请求保护切面
 * 专门处理唯一请求检测逻辑
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@ControllerAdvice
public final class UniqueRequestAdvice implements RequestBodyAdvice {
    
    private static final Logger logger = LoggerFactory.getLogger(UniqueRequestAdvice.class);

    private final EccAutoConfigProperties configProperties;
    private final Cache<String, RequestInfo> requestCache;
    private final HttpServletRequest request;
    public UniqueRequestAdvice(EccAutoConfigProperties configProperties, HttpServletRequest request) {
        this.configProperties = configProperties;

        /**
         * 使用Guava缓存，带有时效性的请求缓存，用于唯一请求检测
         */
        requestCache = CacheBuilder.newBuilder()
                .maximumSize(configProperties.getUniqueRequestMaximumSize())  // Maximum number of cached entries
                .expireAfterWrite(configProperties.getUniqueRequestExpireMinutes(), TimeUnit.MINUTES)  // Expired 60 minutes after writing
                .recordStats()  // Enable the statistics feature
                .build();

        this.request = request;
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

        // Check if the method ignores annotations
        IgnoreUniqueRequest ignoreAnnotation = getIgnoreAnnotation(method);
        if (ignoreAnnotation != null) {
            logger.debug("Method {} is marked as ignoring unique request protection, reason: {}", method.getName(), ignoreAnnotation.reason());
            return false;
        }
        
        // 检查方法或类是否有唯一请求保护注解
        UniqueRequestProtection annotation = getAnnotation(method);
        boolean hasAnnotation = annotation != null;
        
        if (hasAnnotation) {
            logger.debug("Method {} requires a unique request protection detection", method.getName());
        }
        
        return hasAnnotation;
    }
    
    @Override
    @NonNull
    public HttpInputMessage beforeBodyRead(@NonNull HttpInputMessage inputMessage, MethodParameter parameter,
                                           @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        
        Method method = parameter.getMethod();
        if (method != null) {
            // Perform unique request detection
            performUniqueRequestCheck(method);
        }
        
        return inputMessage;
    }
    
    @Override
    @NonNull
    public Object afterBodyRead(@NonNull Object body, @NonNull HttpInputMessage inputMessage, @NonNull MethodParameter parameter,
                                @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }
    
    @Override
    public Object handleEmptyBody(Object body, @NonNull HttpInputMessage inputMessage, @NonNull MethodParameter parameter,
                                  @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }
    
    /**
     * 获取注解配置（优先方法级别，其次类级别）
     * 
     * @param method 方法
     * @return 注解配置
     */
    private UniqueRequestProtection getAnnotation(Method method) {
        // 优先获取方法级别的注解
        UniqueRequestProtection methodAnnotation = AnnotationUtils.findAnnotation(method, UniqueRequestProtection.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        
        // 获取类级别的注解
        return AnnotationUtils.findAnnotation(method.getDeclaringClass(), UniqueRequestProtection.class);
    }
    private IgnoreUniqueRequest getIgnoreAnnotation(Method method) {
        // Priority acquisition of method-level ignore annotations
        return AnnotationUtils.findAnnotation(method, IgnoreUniqueRequest.class);
    }
    
    /**
     * 获取当前HTTP请求
     * 
     * @return HTTP请求对象
     */
    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
    
    /**
     * 执行唯一请求检测
     * 
     * @param method 方法
     */
    private void performUniqueRequestCheck(Method method) {
        
        // Get the annotation configuration
        UniqueRequestProtection annotation = getAnnotation(method);
        if (annotation == null) {
            return;
        }
        
        // Get HTTP requests
        HttpServletRequest request = getCurrentRequest();
        if (request == null) {
            logger.warn("The HTTP request object cannot be obtained, and the unique request detection is skipped");
            return;
        }
        
        // Extract the request ID
        String requestId = request.getHeader(annotation.requestHeaderKey());
        if (!StringUtils.hasText(requestId)) {
            throw new ReplayProtectionException (
                "Missing request ID request header: " + annotation.requestHeaderKey(),
                "MISSING_REQUEST_ID"
            );
        }
        
        // 创建请求信息
        RequestInfo requestInfo = createRequestInfo(request, requestId);
        
        // 验证唯一请求
        validateUniqueRequest(requestInfo, annotation);
        
        // 记录日志
        if (annotation.enableLog()) {
            logger.info("The only request detection passes - Method: {}, RequestID: {}, IP: {}",
                       method.getName(), requestId, requestInfo.getClientIp());
        }
    }
    
    /**
     * 创建请求信息对象
     * 
     * @param request HTTP请求
     * @param requestId 请求ID
     * @return 请求信息
     */
    private RequestInfo createRequestInfo(HttpServletRequest request, String requestId) {
        RequestInfo requestInfo = new RequestInfo(requestId, null);
        requestInfo.setMethod(request.getMethod());
        requestInfo.setUri(request.getRequestURI());
        requestInfo.setClientIp(getClientIpAddress(request));
        requestInfo.setUserAgent(request.getHeader("User-Agent"));
        return requestInfo;
    }
    
    /**
     * 验证唯一请求
     * 
     * @param requestInfo 请求信息
     * @param annotation 注解配置
     */
    private void validateUniqueRequest(RequestInfo requestInfo, UniqueRequestProtection annotation) {
        String requestId = requestInfo.getRequestId();
        
        // 检查请求是否已存在
        RequestInfo existingRequest = requestCache.getIfPresent(requestId);
        if (existingRequest != null) {
            // 严格模式下，不同IP的相同RequestID也会被拒绝
            if (annotation.strictMode() || 
                existingRequest.getClientIp().equals(requestInfo.getClientIp())) {
                
                throw new ReplayProtectionException(
                    String.format("%s - RequestID: %s, Original time: %s, originalIP: %s",
                                 annotation.message(),
                                 requestId, 
                                 existingRequest.getServerReceiveTime(),
                                 existingRequest.getClientIp()),
                    "DUPLICATE_REQUEST",
                    requestId,
                    null
                );
            }
        }
        
        // 缓存请求信息
        requestCache.put(requestId, requestInfo);
    }
    
    /**
     * @return 获取缓存统计信息
     */
    public String getCacheStats() {
        return String.format("缓存统计 - 大小: %d, 命中率: %.2f%%", 
                requestCache.size(), 
                requestCache.stats().hitRate() * 100);
    }
    
    /**
     * 获取客户端真实IP地址
     * 
     * @param request HTTP请求
     * @return 客户端IP地址
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headerNames = {
            "X-Forwarded-For",
            "X-Real-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
        };
        
        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
                // 取第一个IP（可能有多个IP用逗号分隔）
                return ip.split(",")[0].trim();
            }
        }
        
        return request.getRemoteAddr();
    }
    
    /**
     * 获取当前缓存的请求数量
     * 
     * @return 缓存中的请求数量
     */
    public long getCacheSize() {
        return requestCache.size();
    }
    
    /**
     * 清空所有缓存
     */
    public void clearAll() {
        long size = requestCache.size();
        requestCache.invalidateAll();
        logger.info("已清空所有唯一请求缓存 - 清理数量: {}", size);
    }
}
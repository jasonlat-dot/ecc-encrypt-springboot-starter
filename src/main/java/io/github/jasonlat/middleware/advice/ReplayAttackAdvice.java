package io.github.jasonlat.middleware.advice;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.github.jasonlat.middleware.annotations.replayattack.IgnoreReplayAttack;
import io.github.jasonlat.middleware.annotations.replayattack.ReplayAttackProtection;
import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

/**
 * 重放攻击保护切面
 * 专门处理重放攻击检测逻辑
 *
 * @author jasonlat
 */
@ControllerAdvice
public final class ReplayAttackAdvice implements RequestBodyAdvice {

    private static final Logger logger = LoggerFactory.getLogger(ReplayAttackAdvice.class);

    private static final String COMMA = ",";

    private final EccAutoConfigProperties configProperties;
    private final Cache<String, Long> timestampCache;
    private final HttpServletRequest request;
    public ReplayAttackAdvice(EccAutoConfigProperties configProperties, HttpServletRequest request) {
        this.configProperties = configProperties;

        timestampCache = CacheBuilder.newBuilder()
                .maximumSize(configProperties.getReplayAttackCacheMaxSize())  // 最大缓存条目数
                .expireAfterWrite(configProperties.getReplayAttackCacheExpireMinutes(), TimeUnit.MINUTES)  // 写入后 x 分钟过期
                .recordStats()  // 启用统计功能
                .build();
        this.request = request;
    }

    /**
     * 时间戳缓存，用于防止重放攻击
     * Key: timestamp + clientIp, Value: 处理时间
     * 使用Guava缓存，带有时效性
     */



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
        IgnoreReplayAttack ignoreAnnotation = getIgnoreAnnotation(method);
        if (ignoreAnnotation != null) {
            logger.debug("Method {} is marked as ignoring replay attack protection, reason: {}", method.getName(), ignoreAnnotation.reason());
            return false;
        }

        // 检查方法或类是否有重放攻击保护注解
        ReplayAttackProtection annotation = getAnnotation(method);
        boolean hasAnnotation = annotation != null;

        if (hasAnnotation) {
            logger.debug("Method {} requires replay attack protection detection", method.getName());
        }

        return hasAnnotation;
    }

    @Override
    @NonNull
    public HttpInputMessage beforeBodyRead(@NonNull HttpInputMessage inputMessage, MethodParameter parameter,
                                           @NonNull Type targetType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {

        Method method = parameter.getMethod();
        if (method != null) {
            // Perform replay attack detection
            performReplayAttackCheck(method);
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
    private ReplayAttackProtection getAnnotation(Method method) {
        // Priority acquisition of method-level annotations
        ReplayAttackProtection methodAnnotation = AnnotationUtils.findAnnotation(method, ReplayAttackProtection.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }

        // Get class-level annotations
        return AnnotationUtils.findAnnotation(method.getDeclaringClass(), ReplayAttackProtection.class);
    }

    private IgnoreReplayAttack getIgnoreAnnotation(Method method) {
        // Priority acquisition of method-level ignore annotations
        return AnnotationUtils.findAnnotation(method, IgnoreReplayAttack.class);
    }
    /**
     * @return 获取缓存统计信息
     */
    public String getCacheStats() {
        return String.format("Replay Attack Cache Stats - Size: %d, Hit Rate: %.2f%%, Number of Expulsions: %d",
                timestampCache.size(),
                timestampCache.stats().hitRate() * 100,
                timestampCache.stats().evictionCount());
    }

    /**
     * 获取缓存大小
     * @return 获取缓存大小
     */
    public long getCacheSize() {
        return timestampCache.size();
    }

    /**
     * 清空所有缓存
     */
    public void clearAll() {
        long size = timestampCache.size();
        timestampCache.invalidateAll();
        logger.info("Cleared all replay attack caches - Cleaned quantity: {}", size);
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
     * 执行重放攻击检测
     *
     * @param method 方法
     */
    private void performReplayAttackCheck(Method method) {

        // Get the annotation configuration
        ReplayAttackProtection annotation = getAnnotation(method);
        if (annotation == null) {
            return;
        }

        // Get HTTP requests
        HttpServletRequest request = getCurrentRequest();
        if (request == null) {
            logger.warn("The HTTP request object cannot be obtained, and the replay attack detection is skipped");
            return;
        }

        // Extract timestamps
        String timestamp = request.getHeader(annotation.requestHeaderKey());
        if (!StringUtils.hasText(timestamp)) {
            throw new ReplayProtectionException(
                    "The timestamp request header is missing: " + annotation.requestHeaderKey(),
                    "MISSING_TIMESTAMP"
            );
        }

        // Validate timestamps
        validateTimestamp(timestamp, annotation, request);

        // Log logs
        if (annotation.enableLog()) {
            logger.info("The replay attack detection passes - Method: {}, Timestamp: {}, IP: {}",
                    method.getName(), timestamp, getClientIpAddress(request));
        }
    }

    /**
     * 验证时间戳（重放攻击检测）
     *
     * @param timestamp 客户端时间戳
     * @param annotation 注解配置
     * @param request HTTP请求
     */
    private void validateTimestamp(String timestamp, ReplayAttackProtection annotation, HttpServletRequest request) {
        try {
            // Parse timestamps in ISO 8601 format
            Instant clientTime = Instant.parse(timestamp);
            Instant serverTime = Instant.now();

            // Calculate the time difference
            long timeDiff = Math.abs(ChronoUnit.MILLIS.between(clientTime, serverTime));

            // Check the time window
            if (timeDiff > annotation.timeWindow()) {
                throw new ReplayProtectionException(
                        String.format("%s - TimeDifference： %d ms， AllowWindow： %d ms",
                                annotation.message(), timeDiff, annotation.timeWindow()),
                        "TIMESTAMP_EXPIRED",
                        null,
                        timestamp
                );
            }

            // Check future time (to prevent clock deviation attacks)
            if (annotation.checkFutureTime() &&
                    clientTime.isAfter(serverTime.plus(annotation.futureTimeTolerance(), ChronoUnit.SECONDS))) {
                throw new ReplayProtectionException(
                        "The request timestamp cannot be in the future",
                        "FUTURE_TIMESTAMP",
                        null,
                        timestamp
                );
            }

            // Check if the timestamp has been used (simple replay detection)
            String clientIp = getClientIpAddress(request);
            String cacheKey = annotation.cacheKeyPrefix() + ":" + timestamp + ":" + clientIp;

            Long existingTime = timestampCache.getIfPresent(cacheKey);
            if (existingTime != null) {
                throw new ReplayProtectionException(
                        "Replay attack detected - the same timestamp has been used",
                        "REPLAY_ATTACK_DETECTED",
                        null,
                        timestamp
                );
            }

            // Add the timestamp to the cache
            timestampCache.put(cacheKey, System.currentTimeMillis());

        } catch (Exception e) {
            if (e instanceof ReplayProtectionException) {
                throw e;
            }
            throw new ReplayProtectionException(
                    "Invalid timestamp formatting: " + timestamp,
                    "INVALID_TIMESTAMP_FORMAT",
                    null,
                    timestamp
            );
        }
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
                // Take the first IP (there may be multiple IPs separated by a comma)
                return ip.split(COMMA)[0].trim();
            }
        }

        return request.getRemoteAddr();
    }
}
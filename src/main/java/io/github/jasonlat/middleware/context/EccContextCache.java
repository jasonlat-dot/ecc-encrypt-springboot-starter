package io.github.jasonlat.middleware.context;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * @author jasonlat
 */
@Slf4j
@Component
public final class EccContextCache {

    private final Cache<String, EccContext> cache;
    
    public EccContextCache(EccAutoConfigProperties properties) {
        this.cache = Caffeine.newBuilder()
            .maximumSize(properties.getUserContextCacheMaxSize())
            .expireAfterWrite(properties.getUserContextCacheExpireMinutes(), TimeUnit.MINUTES)
            .recordStats()
                // 移除监听
            .removalListener(this::onRemoval)  // 🔥 关键配置
            .build();
    }
    
    public EccContext get(String userId) {
        return cache.getIfPresent(userId);
    }
    
    public void put(String userId, EccContext context) {
        cache.put(userId, context);
    }
    
    public void evict(String userId) {
        cache.invalidate(userId);
    }
    
    public void clear() {
        cache.invalidateAll();
    }

    /**
     * 缓存条目被移除时的回调
     */
    private void onRemoval(String userId, EccContext context, RemovalCause cause) {
        switch (cause) {
            case SIZE:
                log.info("用户{}的ECC上下文因缓存容量限制被驱逐", userId);
                break;
            case EXPIRED:
                log.info("用户{}的ECC上下文因过期被驱逐", userId);
                break;
            case EXPLICIT:
                log.debug("用户{}的ECC上下文被手动移除", userId);
                break;
            default:
                log.info("用户{}的ECC上下文被移除，原因：{}", userId, cause);
        }

        // 清理敏感数据
        if (context != null) {
            context.clearSensitiveData();
        }
    }

    /**
     * @return 获取缓存统计信息
     */
    public CacheStats getStats() {
        return cache.stats();
    }

    /**
     * @return 获取当前缓存大小
     */
    public long size() {
        return cache.estimatedSize();
    }

    /**
     * 手动触发缓存清理
     */
    public void cleanUp() {
        cache.cleanUp();
    }
}
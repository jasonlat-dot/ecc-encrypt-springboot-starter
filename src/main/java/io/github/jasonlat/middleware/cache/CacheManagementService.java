package io.github.jasonlat.middleware.cache;


import io.github.jasonlat.middleware.advice.ReplayAttackAdvice;
import io.github.jasonlat.middleware.advice.UniqueRequestAdvice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 缓存管理控制器
 * 用于监控和管理Guava缓存的状态
 * 
 * @author jasonlat
 * @since 1.0.0
 */
@Service
public final class CacheManagementService {
    
    private static final Logger logger = LoggerFactory.getLogger(CacheManagementService.class);
    
    private final ReplayAttackAdvice replayAttackAdvice;
    
    private final UniqueRequestAdvice uniqueRequestAdvice;

    public CacheManagementService(ReplayAttackAdvice replayAttackAdvice, UniqueRequestAdvice uniqueRequestAdvice) {
        this.replayAttackAdvice = replayAttackAdvice;
        this.uniqueRequestAdvice = uniqueRequestAdvice;
    }

    /**
     *  @return 获取所有缓存统计信息
     */
    public Map<String, Object> getAllCacheStats() {
        logger.info("Get all cache statistics");
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("timestamp", LocalDateTime.now());
        
        Map<String, Object> cacheStats = new HashMap<>();
        
        // 重放攻击缓存统计
        Map<String, Object> replayStats = new HashMap<>();
        replayStats.put("description", "重放攻击防护缓存");
        replayStats.put("size", replayAttackAdvice.getCacheSize());
        replayStats.put("details", replayAttackAdvice.getCacheStats());
        replayStats.put("purpose", "存储已使用的时间戳，防止重放攻击");
        replayStats.put("expireTime", "30分钟");
        replayStats.put("maxSize", 10000);
        cacheStats.put("replayAttackCache", replayStats);
        
        // 唯一请求缓存统计
        Map<String, Object> uniqueStats = new HashMap<>();
        uniqueStats.put("description", "唯一请求保护缓存");
        uniqueStats.put("size", uniqueRequestAdvice.getCacheSize());
        uniqueStats.put("details", uniqueRequestAdvice.getCacheStats());
        uniqueStats.put("purpose", "存储已处理的请求ID，防止重复请求");
        uniqueStats.put("expireTime", "60分钟");
        uniqueStats.put("maxSize", 50000);
        cacheStats.put("uniqueRequestCache", uniqueStats);
        
        response.put("cacheStats", cacheStats);
        
        // 总体统计
        Map<String, Object> summary = new HashMap<>();
        summary.put("totalCaches", 2);
        summary.put("totalSize", replayAttackAdvice.getCacheSize() + uniqueRequestAdvice.getCacheSize());
        summary.put("cacheProvider", "Google Guava Cache");
        summary.put("features", new String[]{"时效性过期", "大小限制", "统计监控", "线程安全"});
        response.put("summary", summary);
        
        return response;
    }
    
    /**
     *  @return 获取重放攻击缓存统计
     */
    public Map<String, Object> getReplayAttackCacheStats() {
        logger.info("获取重放攻击缓存统计");
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("timestamp", LocalDateTime.now());
        response.put("cacheType", "重放攻击防护缓存");
        response.put("stats", replayAttackAdvice.getCacheStats());
        response.put("size", replayAttackAdvice.getCacheSize());


        // 使用HashMap和Collections.unmodifiableMap
        Map<String, Object> config = new HashMap<>();
        config.put("maxSize", 10000);
        config.put("recordStats", true);
        config.put("expireAfterWrite", "30分钟");
        config.put("keyFormat", "timestamp:clientIp");


        response.put("config", Collections.unmodifiableMap(config));
        
        return response;
    }
    
    /**
     *  @return 获取唯一请求缓存统计
     */
    public Map<String, Object> getUniqueRequestCacheStats() {
        logger.info("获取唯一请求缓存统计");
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("timestamp", LocalDateTime.now());
        response.put("cacheType", "唯一请求保护缓存");
        response.put("size", uniqueRequestAdvice.getCacheSize());
        response.put("stats", uniqueRequestAdvice.getCacheStats());

        // 使用HashMap和Collections.unmodifiableMap
        Map<String, Object> config = new HashMap<>();
        config.put("maxSize", 10000);
        config.put("expireAfterWrite", "30分钟");
        config.put("recordStats", true);
        config.put("keyFormat", "timestamp:clientIp");

        response.put("config", Collections.unmodifiableMap(config));
        return response;
    }
    
    /**
     *  @return 清空重放攻击缓存
     */
    public Map<String, Object> clearReplayAttackCache() {
        logger.warn("手动清空重放攻击缓存");
        
        long sizeBefore = replayAttackAdvice.getCacheSize();
        replayAttackAdvice.clearAll();
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "重放攻击缓存已清空");
        response.put("timestamp", LocalDateTime.now());
        response.put("clearedCount", sizeBefore);
        response.put("currentSize", replayAttackAdvice.getCacheSize());
        
        return response;
    }
    
    /**
     *  @return 清空唯一请求缓存
     */
    public Map<String, Object> clearUniqueRequestCache() {
        logger.warn("手动清空唯一请求缓存");
        
        long sizeBefore = uniqueRequestAdvice.getCacheSize();
        uniqueRequestAdvice.clearAll();
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "唯一请求缓存已清空");
        response.put("timestamp", LocalDateTime.now());
        response.put("clearedCount", sizeBefore);
        response.put("currentSize", uniqueRequestAdvice.getCacheSize());
        
        return response;
    }
    
    /**
     *  @return 清空所有缓存
     */
    public Map<String, Object> clearAllCaches() {
        logger.warn("手动清空所有缓存");
        
        long replaySizeBefore = replayAttackAdvice.getCacheSize();
        long uniqueSizeBefore = uniqueRequestAdvice.getCacheSize();
        
        replayAttackAdvice.clearAll();
        uniqueRequestAdvice.clearAll();
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "所有缓存已清空");
        response.put("timestamp", LocalDateTime.now());
        
        Map<String, Object> clearedStats = new HashMap<>();
        clearedStats.put("replayAttackCache", replaySizeBefore);
        clearedStats.put("uniqueRequestCache", uniqueSizeBefore);
        clearedStats.put("total", replaySizeBefore + uniqueSizeBefore);
        response.put("clearedStats", clearedStats);
        
        Map<String, Object> currentStats = new HashMap<>();
        currentStats.put("replayAttackCache", replayAttackAdvice.getCacheSize());
        currentStats.put("uniqueRequestCache", uniqueRequestAdvice.getCacheSize());
        currentStats.put("total", replayAttackAdvice.getCacheSize() + uniqueRequestAdvice.getCacheSize());
        response.put("currentStats", currentStats);
        
        return response;
    }
    
    /**
     *  @return 获取缓存配置信息
     */
    public Map<String, Object> getCacheConfig() {
        logger.info("获取缓存配置信息");
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("timestamp", LocalDateTime.now());
        
        Map<String, Object> config = new HashMap<>();
        config.put("cacheProvider", "Google Guava Cache");
        config.put("version", "Latest");
        
        Map<String, Object> replayConfig = new HashMap<>();
        replayConfig.put("maxSize", 10000);
        replayConfig.put("expireAfterWrite", "30分钟");
        replayConfig.put("recordStats", true);
        replayConfig.put("concurrencyLevel", "自动");
        replayConfig.put("keyType", "String (timestamp:clientIp)");
        replayConfig.put("valueType", "Long (处理时间)");
        config.put("replayAttackCache", replayConfig);
        
        Map<String, Object> uniqueConfig = new HashMap<>();
        uniqueConfig.put("maxSize", 50000);
        uniqueConfig.put("expireAfterWrite", "60分钟");
        uniqueConfig.put("recordStats", true);
        uniqueConfig.put("concurrencyLevel", "自动");
        uniqueConfig.put("keyType", "String (requestId)");
        uniqueConfig.put("valueType", "RequestInfo (请求信息对象)");
        config.put("uniqueRequestCache", uniqueConfig);
        
        response.put("config", config);
        
        Map<String, Object> features = new HashMap<>();
        features.put("timeBasedExpiration", "支持写入后过期");
        features.put("sizeBasedEviction", "支持基于大小的驱逐");
        features.put("statistics", "支持命中率、驱逐数等统计");
        features.put("threadSafety", "完全线程安全");
        features.put("memoryEfficient", "内存高效，自动垃圾回收");
        features.put("performance", "高性能，接近ConcurrentHashMap");
        response.put("features", features);
        
        return response;
    }
    
    /**
     * @return 缓存健康检查
     */
    public Map<String, Object> cacheHealthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("timestamp", LocalDateTime.now());
        
        // 检查缓存是否正常工作
        boolean replayCacheHealthy = replayAttackAdvice.getCacheSize() >= 0;
        boolean uniqueCacheHealthy = uniqueRequestAdvice.getCacheSize() >= 0;
        
        Map<String, Object> healthStatus = new HashMap<>();
        healthStatus.put("replayAttackCache", replayCacheHealthy ? "healthy" : "error");
        healthStatus.put("uniqueRequestCache", uniqueCacheHealthy ? "healthy" : "error");
        healthStatus.put("overall", (replayCacheHealthy && uniqueCacheHealthy) ? "healthy" : "degraded");
        response.put("healthStatus", healthStatus);
        
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("totalCacheSize", replayAttackAdvice.getCacheSize() + uniqueRequestAdvice.getCacheSize());
        metrics.put("cacheProvider", "Guava");
        metrics.put("uptime", "运行中");
        response.put("metrics", metrics);
        
        return response;
    }
}
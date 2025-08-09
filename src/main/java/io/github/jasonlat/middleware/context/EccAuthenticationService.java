package io.github.jasonlat.middleware.context;

import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
//import io.github.jasonlat.middleware.domain.service.EccUserDataService;
import io.github.jasonlat.middleware.domain.service.EccUserDataService;
import io.github.jasonlat.middleware.exception.ReplayProtectionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

import static io.github.jasonlat.middleware.domain.model.valobj.EccConstants.ANONYMOUS_USER_ID;


/**
 * @author jasonlat
 */
@Service
public final class EccAuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(EccAuthenticationService.class);
    private final EccUserDataService userDataService;
    
    private final EccContextCache contextCache;

    private final EccAutoConfigProperties eccAutoConfigProperties;

    public EccAuthenticationService(EccUserDataService userDataService, EccContextCache contextCache, EccAutoConfigProperties eccAutoConfigProperties) {
        this.userDataService = userDataService;
        this.contextCache = contextCache;
        this.eccAutoConfigProperties = eccAutoConfigProperties;
    }

    /**
     * 认证用户并设置上下文
     * @param username 用户id
     */
    public void authenticate(String username) {
        // 0. 判断 userId
        if (!StringUtils.hasLength(username)) {
            log.warn("userId is empty, skip authenticate");
            return;
        }
        // 1. 先从缓存获取
        EccContext cachedContext = contextCache.get(username);
        if (cachedContext != null && cachedContext.getUserPublicData() != null && !isExpired(cachedContext)) {
            EccContextHolder.setContext(cachedContext);
            EccContext context = EccContextHolder.getContext();
            System.out.println(context
            );
            return;
        }
        
        // 2. 从用户服务获取数据
        UserPublicData userData = userDataService.loadUserPublicData(username);

        // 匿名用户，不用设置上下文
        if (userData != null && !ANONYMOUS_USER_ID.VALUE().contains(username)) {
            // 3. 创建新的上下文
            EccContext context = EccContext.of(username, userData);

            // 4. 缓存上下文
            contextCache.put(username, context);

            // 5. 设置到当前线程
            EccContextHolder.setContext(context);
        }

    }

    /**
     * 认证用户并设置上下文
     */
    public void authenticate() {
        String currentUserId = userDataService.getCurrentUserId();
        if (!StringUtils.hasLength(currentUserId)) {
            throw new ReplayProtectionException("userDataService.getCurrentUserId() return userId is empty, can't authenticate");
        }
        authenticate(currentUserId);
    }
    
    /**
     * 刷新用户上下文
     * @param userId 用户id
     */
    public void refreshContext(String userId) {
        contextCache.evict(userId);
        authenticate(userId);
    }

    /**
     * 时间过期检查
     * @param context 上下文
     * @return 结果
     */
    private boolean isExpired(EccContext context) {
        if (context == null) {
            return true;
        }

        // 检查基本时间过期
        return isTimeExpired(context);
    }


    /**
     * 时间过期检查
     * @param context 上下文
     * @return 结果
     */
    private boolean isTimeExpired(EccContext context) {
        if (context.getLoadTime() == null) {
            return true;
        }

        LocalDateTime loadTime = context.getLoadTime();
        LocalDateTime now = LocalDateTime.now();
        long expireMinutes = eccAutoConfigProperties.getUserContextCacheExpireMinutes();

        return loadTime.plusMinutes(expireMinutes).isBefore(now);
    }



}
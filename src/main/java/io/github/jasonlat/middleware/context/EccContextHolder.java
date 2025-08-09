package io.github.jasonlat.middleware.context;

import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.UUID;

/**
 * @author jasonlat
 */
@Component
public final class EccContextHolder {
    
    private static final ThreadLocal<EccContext> contextHolder = new ThreadLocal<>();

    private final EccAuthenticationService authenticationService;

    public EccContextHolder(EccAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    // ========================= 静态方法区 ==============================
    /**
     * @return 获取当前线程的ECC上下文
     */
    public static EccContext getContext() {
        return contextHolder.get();
    }
    

    /**
     * 设置当前线程的ECC上下文
     * @param context 上下文
     */
    public static void setContext(EccContext context) {
        contextHolder.set(context);
    }
    
    /**
     * 清除当前线程的ECC上下文
     */
    public static void clearContext() {
        contextHolder.remove();
    }
    
    /**
     * @return 获取当前用户的公钥数据
     */
    private static UserPublicData getCurrentUserPublicData() {
        EccContext context = getContext();
        validateContext(context);
        return context.getUserPublicData();
    }

    /**
     * @return 获取当前用户的公钥数据(自动设置上下文)
     */
    public UserPublicData getAuthenticationUserPublicData() {
        // 手动设置上下文
        authenticationService.authenticate();
        return getCurrentUserPublicData();
    }

    /**
     * @return 获取当前用户的公钥数据(自动设置上下文)
     */
    public UserPublicData getAuthenticationUserPublicData(String username) {
        // 手动设置上下文
        authenticationService.authenticate(username);
        return getCurrentUserPublicData();
    }



    /**
     * 验证上下文
     */
    private static void validateContext(EccContext context) {
        if (context == null) {
            throw new IllegalArgumentException("ECC上下文为空");
        }
        UserPublicData userPublicData = context.getUserPublicData();
        if (userPublicData == null || !StringUtils.hasLength(userPublicData.getX()) || !StringUtils.hasLength(userPublicData.getY())) {
            throw new IllegalArgumentException("ECC上下文的用户公钥数据不能为空");
        }
    }

    /**
     * @return 生成会话ID
     */
    private static String generateSessionId() {
        return UUID.randomUUID().toString().replace("-", "") + System.currentTimeMillis();
    }

}
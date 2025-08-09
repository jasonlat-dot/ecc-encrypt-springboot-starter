package io.github.jasonlat.middleware.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;

/**
 * ECC自动配置属性
 * @author jasonlat
 */
@Setter
@Getter
@ConfigurationProperties(prefix = "jasonlat.ecc", ignoreInvalidFields = true)
public final class EccAutoConfigProperties {

    /**
     * 是否启用ECC功能
     */
    private boolean enabled = true;

    /**
     * ECC私钥
     */
    private String privateKey = null;

    /**
     * ECC公钥X坐标
     */
    private String publicKeyX = null;

    /**
     * ECC公钥Y坐标
     */
    private String publicKeyY = null;

    /**
     * 用户上下文缓存配置
     */
    private UserContextCache userContextCache = new UserContextCache();

    /**
     * 重放攻击防护配置
     */
    private ReplayAttack replayAttack = new ReplayAttack();

    /**
     * 唯一请求防护配置
     */
    private UniqueRequest uniqueRequest = new UniqueRequest();

    /**
     * 用户上下文缓存配置类
     */
    @Setter
    @Getter
    public static class UserContextCache {

        /**
         * 缓存最大大小
         */
        private long cacheMaxSize = 5000L;

        /**
         * 缓存过期时间（分钟）
         */
        private long cacheExpireMinutes = 120L;
    }

    /**
     * 重放攻击防护配置类
     */
    @Setter
    @Getter
    public static class ReplayAttack {

        /**
         * 缓存配置
         */
        private Cache cache = new Cache();

        /**
         * 缓存配置类
         */
        @Setter
        @Getter
        public static class Cache {

            /**
             * 缓存最大大小
             */
            private long cacheMaxSize = 1000L;

            /**
             * 缓存过期时间（分钟）
             */
            private long cacheExpireMinutes = 30L;
        }
    }

    /**
     * 唯一请求防护配置类
     */
    @Setter
    @Getter
    public static class UniqueRequest {

        /**
         * 缓存配置
         */
        private Cache cache = new Cache();

        /**
         * 缓存配置类
         */
        @Setter
        @Getter
        public static class Cache {

            /**
             * 缓存最大大小
             */
            private long maximumSize = 10000L;

            /**
             * 写入后过期时间（分钟）
             */
            private long expireMinutesAfterWrite = 60L;
        }
    }

    // ========== 便捷方法 ==========

    /**
     * @return 获取用户上下文缓存最大大小
     */
    public long getUserContextCacheMaxSize() {
        return userContextCache.getCacheMaxSize();
    }

    /**
     * @return 获取用户上下文缓存过期时间
     */
    public long getUserContextCacheExpireMinutes() {
        return userContextCache.getCacheExpireMinutes();
    }

    /**
     * @return 获取重放攻击缓存最大大小
     */
    public long getReplayAttackCacheMaxSize() {
        return replayAttack.getCache().getCacheMaxSize();
    }

    /**
     * @return 获取重放攻击缓存过期时间
     */
    public long getReplayAttackCacheExpireMinutes() {
        return replayAttack.getCache().getCacheExpireMinutes();
    }

    /**
     * @return 获取唯一请求缓存最大大小
     */
    public long getUniqueRequestMaximumSize() {
        return uniqueRequest.getCache().getMaximumSize();
    }

    /**
     * @return 获取唯一请求缓存过期时间
     */
    public long getUniqueRequestExpireMinutes() {
        return uniqueRequest.getCache().getExpireMinutesAfterWrite();
    }

    /**
     * 验证配置的有效性
     */
    @PostConstruct
    public void validateConfiguration() {
        if (enabled) {
            // 验证密钥配置
            if (!StringUtils.hasLength(privateKey)) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("ECC private keys cannot be empty");
            }

            if (!StringUtils.hasLength(publicKeyX) || !StringUtils.hasLength(publicKeyY)) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("ECC public key coordinates cannot be empty");
            }

            // 验证缓存配置
            if (getUserContextCacheMaxSize() <= 0) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("The user context cache size must be greater than 0");
            }

            if (getUserContextCacheExpireMinutes() <= 0) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("The user context cache expiration time must be greater than 0");
            }

            if (getReplayAttackCacheMaxSize() <= 0) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("The size of the replay attack cache must be greater than 0");
            }

            if (getUniqueRequestMaximumSize() <= 0) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("The unique request cache size must be greater than 0");
            }

            if (getReplayAttackCacheExpireMinutes() <= 0) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("The replay attack cache expiration time must be greater than 0");
            }

            if (getUniqueRequestExpireMinutes() <= 0) {
                System.out.println(generateCompleteDocumentation());
                throw new IllegalArgumentException("The unique request cache expiration time must be greater than 0");
            }
        }
        this.getConfigSummary();
    }

    /**
     * @return 获取配置摘要信息
     */
    public String getConfigSummary() {
        if (!enabled) {
            return "The ECC feature is disabled";
        }

        return String.format(
                "ECC Configuration Summary: User Context Cache [Size: %d, Expiration: %d minutes], Replay Attack Cache [Size: %d, Expiration: %d Minutes], Unique Request Cache [Size: %d, Expiration: %d minutes]",
                getUserContextCacheMaxSize(),
                getUserContextCacheExpireMinutes(),
                getReplayAttackCacheMaxSize(),
                getReplayAttackCacheExpireMinutes(),
                getUniqueRequestMaximumSize(),
                getUniqueRequestExpireMinutes()
        );
    }

    /**
     * @return 生成完整的配置文档
     */
    public static String generateCompleteDocumentation() {

        return generateConfigurationGuide() +
                "\n" +
                "┌─────────────────────────────────────────────────────────────┐\n" +
                "│                Properties 格式配置                          │\n" +
                "└─────────────────────────────────────────────────────────────┘\n" +
                generatePropertiesConfiguration() +
                generateValidationTips();
    }

    /**
     * 打印配置指南到控制台
     */
    public static void printConfigurationGuide() {
        System.out.println(generateConfigurationGuide());
    }

    /**
     * 打印Properties配置到控制台
     */
    public static void printPropertiesConfiguration() {
        System.out.println(generatePropertiesConfiguration());
    }

    /**
     * 生成ECC配置提示信息
     *
     * @return 格式化的配置提示字符串
     */
    public static String generateConfigurationGuide() {
        return "\n" +
                "═══════════════════════════════════════════════════════════════\n" +
                "                    ECC 配置指南                              \n" +
                "═══════════════════════════════════════════════════════════════\n" +
                "\n" +
                "请在您的 application.yml 或 application.properties 文件中添加以下配置：\n" +
                "\n" +
                "┌─────────────────────────────────────────────────────────────┐\n" +
                "│                    YAML 配置示例                            │\n" +
                "└─────────────────────────────────────────────────────────────┘\n" +
                "\n" +

                // YAML配置内容
                generateYamlConfiguration() +
                "\n" +
                "┌─────────────────────────────────────────────────────────────┐\n" +
                "│                  配置项说明                                 │\n" +
                "└─────────────────────────────────────────────────────────────┘\n" +
                "\n" +

                // 配置说明
                generateConfigurationDescription() +
                "\n" +
                "═══════════════════════════════════════════════════════════════\n" +
                "\n";
    }

    /**
     * @return 生成YAML配置内容
     */
    private static String generateYamlConfiguration() {

        String yaml = "jasonlat:\n" +
                "  ecc:\n" +
                "    # 是否启用ECC功能\n" +
                "    enabled: true\n" +
                "    \n" +
                "    # ECC密钥配置（请替换为您的实际密钥）\n" +
                "    privateKey: be38fba57a90bcdbd59cdba9df58e511d0105f4e400bec872448be3202e7eaf8\n" +
                "    publicKeyX: d13d9de5d2cf7578aa427a73eca23aa6335baa2f218c433a972501f42a760e1a\n" +
                "    publicKeyY: cae8c8fc121bf4f7a4310a7273364b15af5bff70dd1bf603124f8f8f25207c84\n" +
                "    \n" +
                "    # 用户上下文缓存配置\n" +
                "    user-context-cache:\n" +
                "      cache-max-size: 5000        # 最大缓存用户数量\n" +
                "      cache-expire-minutes: 120   # 缓存过期时间（分钟）\n" +
                "    \n" +
                "    # 重放攻击防护缓存配置\n" +
                "    replay-attack:\n" +
                "      cache:\n" +
                "        cache-max-size: 1000      # 最大缓存请求数量\n" +
                "        cache-expire-minutes: 30  # 缓存过期时间（分钟）\n" +
                "    \n" +
                "    # 唯一请求防护缓存配置\n" +
                "    unique-request:\n" +
                "      cache:\n" +
                "        maximum-size: 10000             # 最大缓存请求数量\n" +
                "        expire-minutes-after-write: 60  # 写入后过期时间（分钟）\n";

        return yaml;
    }

    /**
     * @return 生成配置项说明
     */
    private static String generateConfigurationDescription() {

        String desc = "📋 配置项详细说明：\n" +
                "\n" +
                "🔧 基础配置\n" +
                "  • enabled: 是否启用ECC功能（true/false）\n" +
                "  • privateKey: ECC私钥（64位十六进制字符串）\n" +
                "  • publicKeyX: ECC公钥X坐标（64位十六进制字符串）\n" +
                "  • publicKeyY: ECC公钥Y坐标（64位十六进制字符串）\n" +
                "\n" +
                "👤 用户上下文缓存\n" +
                "  • cache-max-size: 最大缓存的用户上下文数量\n" +
                "  • cache-expire-minutes: 用户上下文缓存过期时间（分钟）\n" +
                "\n" +
                "🛡️ 重放攻击防护\n" +
                "  • cache-max-size: 最大缓存的请求数量\n" +
                "  • cache-expire-minutes: 请求缓存过期时间（分钟）\n" +
                "\n" +
                "🔒 唯一请求防护\n" +
                "  • maximum-size: 最大缓存的唯一请求数量\n" +
                "  • expire-minutes-after-write: 写入后过期时间（分钟）\n" +
                "\n" +
                "💡 推荐配置值：\n" +
                "  • 用户上下文缓存: 5000个用户，120分钟过期\n" +
                "  • 重放攻击防护: 1000个请求，30分钟过期\n" +
                "  • 唯一请求防护: 10000个请求，60分钟过期\n";

        return desc;
    }

    /**
     * @return 生成Properties格式配置
     */
    public static String generatePropertiesConfiguration() {

        return "\n" +
                "# ═══════════════════════════════════════════════════════════════\n" +
                "#                    ECC 配置 (Properties格式)                  \n" +
                "# ═══════════════════════════════════════════════════════════════\n" +
                "\n" +
                "# 基础配置\n" +
                "jasonlat.ecc.enabled=true\n" +
                "\n" +
                "# ECC密钥配置\n" +
                "jasonlat.ecc.privateKey=be38fba57a90bcdbd59cdba9df58e511d0105f4e400bec872448be3202e7eaf8\n" +
                "jasonlat.ecc.publicKeyX=d13d9de5d2cf7578aa427a73eca23aa6335baa2f218c433a972501f42a760e1a\n" +
                "jasonlat.ecc.publicKeyY=cae8c8fc121bf4f7a4310a7273364b15af5bff70dd1bf603124f8f8f25207c84\n" +
                "\n" +
                "# 用户上下文缓存配置\n" +
                "jasonlat.ecc.user-context-cache.cache-max-size=5000\n" +
                "jasonlat.ecc.user-context-cache.cache-expire-minutes=120\n" +
                "\n" +
                "# 重放攻击防护缓存配置\n" +
                "jasonlat.ecc.replay-attack.cache.cache-max-size=1000\n" +
                "jasonlat.ecc.replay-attack.cache.cache-expire-minutes=30\n" +
                "\n" +
                "# 唯一请求防护缓存配置\n" +
                "jasonlat.ecc.unique-request.cache.maximum-size=10000\n" +
                "jasonlat.ecc.unique-request.cache.expire-minutes-after-write=60\n" +
                "\n";
    }



    /**
     * @return 生成配置验证提示
     */
    public static String generateValidationTips() {

        return "\n" +
                "🔍 配置验证提示：\n" +
                "\n" +
                "✅ 必需配置项检查：\n" +
                "  1. enabled 必须设置为 true\n" +
                "  2. privateKey 不能为空，必须是64位十六进制字符串\n" +
                "  3. publicKeyX 和 publicKeyY 不能为空\n" +
                "\n" +
                "⚠️ 缓存配置建议：\n" +
                "  1. 缓存大小应根据实际用户量调整\n" +
                "  2. 过期时间应平衡安全性和性能\n" +
                "  3. 生产环境建议启用缓存统计监控\n" +
                "\n" +
                "🔐 安全提示：\n" +
                "  1. 私钥应妥善保管，不要提交到版本控制\n" +
                "  2. 建议使用环境变量或配置中心管理敏感信息\n" +
                "  3. 定期轮换密钥以提高安全性\n" +
                "\n";
    }


}

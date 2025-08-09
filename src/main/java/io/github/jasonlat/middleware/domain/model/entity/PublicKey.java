package io.github.jasonlat.middleware.domain.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.github.jasonlat.middleware.config.EccAutoConfigProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;


/**
 * @author jasonlat
 */
@AllArgsConstructor
@Builder
@Data
public final class PublicKey implements Serializable {

    private final String x;
    private final String y;

    // 静态实例变量（饿汉式）
    private static volatile PublicKey instance;

    // 私有构造函数，从配置创建
    private PublicKey(EccAutoConfigProperties eccAutoConfigProperties) {
        this.x = eccAutoConfigProperties.getPublicKeyX();
        this.y = eccAutoConfigProperties.getPublicKeyY();
    }

    /**
     * 获取单例实例（懒汉式 + 双重检查锁定）
     * @param x 公钥X坐标
     * @param y 公钥Y坐标
     * @return ServerPublicData单例实例
     */
    public static PublicKey getInstance(String x, String y) {
        if (instance == null) {
            synchronized (PublicKey.class) {
                if (instance == null) {
                    instance = new PublicKey(x, y);
                }
            }
        }
        return instance;
    }

    /**
     * 获取单例实例（从配置创建）
     * @param eccAutoConfigProperties 自动配置属性
     * @return ServerPublicData单例实例
     */
    public static PublicKey getInstance(EccAutoConfigProperties eccAutoConfigProperties) {
        if (instance == null) {
            synchronized (ServerPublicKeyData.class) {
                if (instance == null) {
                    instance = new PublicKey(eccAutoConfigProperties);
                }
            }
        }
        return instance;
    }

    /**
     * 获取已存在的单例实例
     * @return ServerPublicData单例实例，如果未初始化则抛出异常
     * @throws IllegalStateException 如果单例未初始化
     */
    public static PublicKey getInstance() {
        if (instance == null) {
            throw new IllegalStateException("ServerPublicData单例未初始化，请先调用getInstance(String, String)或getInstance(AutoConfigProperties)");
        }
        return instance;
    }

    /**
     * @param x 新的公钥X坐标
     * @param y 新的公钥Y坐标
     */
    public static synchronized void resetInstance(String x, String y) {
        instance = new PublicKey(x, y);
    }

    /**
     * 重置单例实例（从配置）
     * @param eccAutoConfigProperties 新的自动配置属性
     */
    public static synchronized void resetInstance(EccAutoConfigProperties eccAutoConfigProperties) {
        instance = new PublicKey(eccAutoConfigProperties);
    }

    /**
     * 清除单例实例（主要用于测试）
     */
    public static synchronized void clearInstance() {
        instance = null;
    }

    /**
     * 检查单例是否已初始化
     * @return true如果已初始化，false否则
     */
    public static boolean isInitialized() {
        return instance != null;
    }


    /**
     * 获取公钥的完整信息
     * @return 包含x和y坐标的字符串表示
     */
    @JsonIgnore
    public String getPublicKeyInfo() {
        return String.format("PublicKey{x='%s', y='%s'}", x, y);
    }

    /**
     * 验证公钥数据是否有效
     * @return true如果公钥数据有效，false否则
     */
    @JsonIgnore
    public boolean isValid() {
        return x != null && !x.trim().isEmpty() &&
                y != null && !y.trim().isEmpty();
    }

    @Override
    @JsonIgnore
    public String toString() {
        return getPublicKeyInfo();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        PublicKey that = (PublicKey) obj;
        return x.equals(that.x) && y.equals(that.y);
    }

    @Override
    public int hashCode() {
        return x.hashCode() * 31 + y.hashCode();
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("单例对象不支持克隆");
    }
}

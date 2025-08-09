package io.github.jasonlat.middleware.config;


import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;
import io.github.jasonlat.middleware.domain.service.EccUserDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;



/**
 * 自动装配类
 * @author jasonlat
 */
@Configuration
@EnableConfigurationProperties(EccAutoConfigProperties.class) // 启用EncryptProperties类的配置属性。
public class EccAutoConfigure {

    @Autowired
    private ApplicationContext context;

     // Jar 包提供的默认实现
    @Bean
    @ConditionalOnMissingBean // 关键：当用户未自定义时才生效
    public EccUserDataService eccUserDataService() {
        // 检查容器中是否已存在EccUserDataService类型的Bean
        boolean exists = context.containsBeanDefinition("eccUserDataService");
        System.out.println("容器中是否已存在eccUserDataService Bean：" + exists);

        return new EccUserDataService() {
            @Override
            public UserPublicData loadUserPublicData(String userId) {
                //  Jar 包的默认逻辑（可能抛出未实现异常，提示用户自定义）
                throw new UnsupportedOperationException("请自定义 EccUserDataService 实现 loadUserPublicData() 方法");
            }

            @Override
            public String getCurrentUserId() {
                // 默认逻辑（例如返回匿名用户）
                throw new UnsupportedOperationException("请自定义 EccUserDataService 实现 getCurrentUserId() 方法");
            }
        };
    }

}
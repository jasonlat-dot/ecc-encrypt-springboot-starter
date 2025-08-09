# ECC Encrypt SpringBoot Starter

一个基于椭圆曲线加密（ECC）的SpringBoot自动配置启动器，提供请求加密解密、重放攻击防护、唯一请求防护等安全功能。

## 功能特性

- 🔐 **ECC加密解密**：基于椭圆曲线加密算法的请求体加密解密
- 🛡️ **重放攻击防护**：防止恶意重放请求攻击
- 🔒 **唯一请求防护**：防止重复请求处理
- 📦 **自动配置**：SpringBoot自动配置，开箱即用
- 🚀 **高性能缓存**：基于Guava和Caffeine的高性能缓存
- 📝 **注解驱动**：简单易用的注解配置

## 快速开始

### 1. 添加依赖

在您的 `pom.xml` 文件中添加以下依赖：

```xml
<dependency>
    <groupId>io.github.jasonlat-dot</groupId>
    <artifactId>ecc-encrypt-springboot-starter</artifactId>
    <version>1.0</version>
</dependency>
```

### 2. YML配置

在 `application.yml` 文件中添加以下配置：

```yaml
jasonlat:
  ecc:
    # 是否启用ECC功能
    enabled: true

    # ECC密钥配置（请替换为您的实际密钥）
    privateKey: 
    publicKeyX: 
    publicKeyY: 

    # 用户上下文缓存配置
    user-context-cache:
      cache-max-size: 5000        # 最大缓存用户数量
      cache-expire-minutes: 120   # 缓存过期时间（分钟）

    # 重放攻击防护缓存配置
    replay-attack:
      cache:
        cache-max-size: 1000      # 最大缓存请求数量
        cache-expire-minutes: 30  # 缓存过期时间（分钟）

    # 唯一请求防护缓存配置
    unique-request:
      cache:
        maximum-size: 10000             # 最大缓存请求数量
        expire-minutes-after-write: 60  # 写入后过期时间（分钟）
```

#### Properties格式配置

如果您使用 `application.properties` 文件，可以使用以下配置：

```properties
# 基础配置
jasonlat.ecc.enabled=true

# ECC密钥配置
jasonlat.ecc.privateKey=
jasonlat.ecc.publicKeyX=
jasonlat.ecc.publicKeyY=

# 用户上下文缓存配置
jasonlat.ecc.user-context-cache.cache-max-size=5000
jasonlat.ecc.user-context-cache.cache-expire-minutes=120

# 重放攻击防护缓存配置
jasonlat.ecc.replay-attack.cache.cache-max-size=1000
jasonlat.ecc.replay-attack.cache.cache-expire-minutes=30

# 唯一请求防护缓存配置
jasonlat.ecc.unique-request.cache.maximum-size=10000
jasonlat.ecc.unique-request.cache.expire-minutes-after-write=60
```

### 3. 实现Bean

您需要实现 `EccUserDataService` 接口来提供用户数据服务：

```java
/**
 * 自定义用户数据服务实现
 * @author jasonlat
 */
@Service
public class CustomEccUserDataService implements EccUserDataService {

    /**
     * 加载用户公钥数据
     * @param userId 用户ID
     * @return 用户公钥数据
     */
    @Override
    public UserPublicData loadUserPublicData(String userId) {
        // 从数据库或其他存储中加载用户公钥数据
        // 这里是示例实现，请根据实际情况修改
        return UserPublicData.builder()
                .userId(userId)
                .publicKeyX("用户的公钥X坐标")
                .publicKeyY("用户的公钥Y坐标")
                .build();
    }

    /**
     * 获取当前用户ID
     * @return 当前用户ID
     */
    @Override
    public String getCurrentUserId() {
        // 从JWT token、Session或其他方式获取当前用户ID
        // 这里是示例实现，请根据实际情况修改
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
```

**注意**：如果您不提供自定义实现，系统会使用默认实现，但会抛出 `UnsupportedOperationException` 异常提示您实现相关方法。

### 4. 注解使用

#### 4.1 请求加密注解 `@RequestEncryption`

用于标记需要对响应进行加密的方法或类：

```java
/**
 * 用户控制器
 * @author jasonlat
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    /**
     * 获取用户信息（响应加密）
     * @param userId 用户ID
     * @return 加密后的用户信息
     */
    @GetMapping("/{userId}")
    @RequestEncryption(
        enableCompression = true,      // 启用压缩
        compressionAlgorithm = "GZIP", // 压缩算法
        enableLog = true               // 启用日志
    )
    public ResponseEntity<UserInfo> getUserInfo(@PathVariable String userId) {
        UserInfo userInfo = userService.getUserInfo(userId);
        return ResponseEntity.ok(userInfo);
    }
}
```

#### 4.2 请求解密注解 `@RequestDecryption`

用于标记需要对请求体进行解密的方法或类：

```java
/**
 * 用户控制器
 * @author jasonlat
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    /**
     * 更新用户信息（请求解密）
     * @param request 加密的用户信息请求
     * @return 更新结果
     */
    @PostMapping("/update")
    @RequestDecryption(
        enableDecompression = true,                    // 启用解压缩
        decompressionAlgorithm = "GZIP",              // 解压缩算法
        resultType = "JSON",                          // 解密后数据类型
        requestType = EccDecryptType.IDENTIFICATION,   // 已认证用户请求
        enableLog = true                               // 启用日志
    )
    public ResponseEntity<String> updateUserInfo(@RequestBody UserUpdateRequest request) {
        userService.updateUserInfo(request);
        return ResponseEntity.ok("更新成功");
    }

    /**
     * 用户注册（注册请求解密）
     * @param request 注册请求
     * @return 注册结果
     */
    @PostMapping("/register")
    @RequestDecryption(
        requestType = EccDecryptType.REGISTER,     // 注册请求类型
        registerPublicXKey = "userPublicX",       // 用户公钥X在明文JSON中的key
        registerPublicYKey = "userPublicY",       // 用户公钥Y在明文JSON中的key
        enableLog = true
    )
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        userService.register(request);
        return ResponseEntity.ok("注册成功");
    }

    /**
     * 未认证用户请求（需要提供用户标识）
     * @param request 请求数据
     * @return 处理结果
     */
    @PostMapping("/public-action")
    @RequestDecryption(
        requestType = EccDecryptType.NOT_IDENTIFICATION, // 未认证请求
        notIdentUniqueUserKey = "username",             // 用户唯一标识在明文JSON中的key
        enableLog = true
    )
    public ResponseEntity<String> publicAction(@RequestBody PublicActionRequest request) {
        // 处理未认证用户的请求
        return ResponseEntity.ok("处理成功");
    }
}
```

#### 4.3 重放攻击防护注解 `@ReplayAttackProtection`

用于防止重放攻击：

```java
/**
 * 支付控制器
 * @author jasonlat
 */
@RestController
@RequestMapping("/api/payment")
public class PaymentController {

    /**
     * 创建支付订单（防重放攻击）
     * @param request 支付请求
     * @return 支付结果
     */
    @PostMapping("/create")
    @ReplayAttackProtection(
        requestHeaderKey = "X-Timestamp",    // 时间戳请求头key
        timeWindow = 300000L,                // 时间窗口5分钟
        cacheKeyPrefix = "payment",          // 缓存key前缀
        checkFutureTime = true,              // 检查未来时间戳
        futureTimeTolerance = 60L,           // 未来时间容忍度60秒
        enableLog = true                     // 启用日志
    )
    public ResponseEntity<PaymentResult> createPayment(@RequestBody PaymentRequest request) {
        PaymentResult result = paymentService.createPayment(request);
        return ResponseEntity.ok(result);
    }
}
```

#### 4.4 唯一请求防护注解 `@UniqueRequestProtection`

用于防止重复请求：

```java
/**
 * 订单控制器
 * @author jasonlat
 */
@RestController
@RequestMapping("/api/order")
public class OrderController {

    /**
     * 创建订单（防重复请求）
     * @param request 订单请求
     * @return 订单结果
     */
    @PostMapping("/create")
    @UniqueRequestProtection(
        requestHeaderKey = "X-Request-ID",   // 请求ID请求头key
        strictMode = true,                   // 严格模式
        enableLog = true                     // 启用日志
    )
    public ResponseEntity<OrderResult> createOrder(@RequestBody OrderRequest request) {
        OrderResult result = orderService.createOrder(request);
        return ResponseEntity.ok(result);
    }
}
```

#### 4.5 忽略注解

如果某些方法不需要应用相应的功能，可以使用忽略注解：

```java
/**
 * 公共控制器
 * @author jasonlat
 */
@RestController
@RequestMapping("/api/public")
@RequestEncryption  // 类级别启用加密
public class PublicController {

    /**
     * 健康检查（忽略加密）
     * @return 健康状态
     */
    @GetMapping("/health")
    @IgnoreRequestEncryption  // 忽略请求加密
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }

    /**
     * 公开信息（忽略解密）
     * @param request 请求
     * @return 响应
     */
    @PostMapping("/info")
    @IgnoreRequestDecryption  // 忽略请求解密
    public ResponseEntity<String> getPublicInfo(@RequestBody InfoRequest request) {
        return ResponseEntity.ok("公开信息");
    }

    /**
     * 公开接口（忽略重放攻击防护）
     * @return 响应
     */
    @GetMapping("/open")
    @IgnoreReplayAttack  // 忽略重放攻击防护
    public ResponseEntity<String> openApi() {
        return ResponseEntity.ok("开放接口");
    }

    /**
     * 批量操作（忽略唯一请求防护）
     * @param request 批量请求
     * @return 响应
     */
    @PostMapping("/batch")
    @IgnoreUniqueRequest  // 忽略唯一请求防护
    public ResponseEntity<String> batchOperation(@RequestBody BatchRequest request) {
        return ResponseEntity.ok("批量操作完成");
    }
}
```

## 配置说明

### 配置项详细说明

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `jasonlat.ecc.enabled` | boolean | true | 是否启用ECC功能 |
| `jasonlat.ecc.privateKey` | String | - | ECC私钥（64位十六进制字符串） |
| `jasonlat.ecc.publicKeyX` | String | - | ECC公钥X坐标（64位十六进制字符串） |
| `jasonlat.ecc.publicKeyY` | String | - | ECC公钥Y坐标（64位十六进制字符串） |
| `jasonlat.ecc.user-context-cache.cache-max-size` | long | 5000 | 用户上下文缓存最大数量 |
| `jasonlat.ecc.user-context-cache.cache-expire-minutes` | long | 120 | 用户上下文缓存过期时间（分钟） |
| `jasonlat.ecc.replay-attack.cache.cache-max-size` | long | 1000 | 重放攻击防护缓存最大数量 |
| `jasonlat.ecc.replay-attack.cache.cache-expire-minutes` | long | 30 | 重放攻击防护缓存过期时间（分钟） |
| `jasonlat.ecc.unique-request.cache.maximum-size` | long | 10000 | 唯一请求防护缓存最大数量 |
| `jasonlat.ecc.unique-request.cache.expire-minutes-after-write` | long | 60 | 唯一请求防护缓存写入后过期时间（分钟） |

### 安全建议

1. **密钥管理**：
   - 私钥应妥善保管，不要提交到版本控制系统
   - 建议使用环境变量或配置中心管理敏感信息
   - 定期轮换密钥以提高安全性

2. **缓存配置**：
   - 缓存大小应根据实际用户量和请求量调整
   - 过期时间应平衡安全性和性能需求
   - 生产环境建议启用缓存统计监控

3. **性能优化**：
   - 根据业务场景调整缓存参数
   - 监控缓存命中率和内存使用情况
   - 合理设置时间窗口和容忍度

## 依赖说明

本starter依赖以下主要组件：

- **Spring Boot 2.7.12**：基础框架
- **BouncyCastle**：ECC加密算法实现
- **Guava**：高性能缓存
- **Caffeine**：高性能缓存
- **FastJSON**：JSON序列化
- **Lombok**：代码简化

## 许可证

本项目采用 [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.txt) 许可证。

## 作者

- **作者**：jasonlat
- **邮箱**：lijiaqiang1024@163.com
- **GitHub**：[https://github.com/jasonlat-dot](https://github.com/jasonlat-dot)

## 贡献

欢迎提交Issue和Pull Request来帮助改进这个项目！

## 更新日志

### v1.0
- 初始版本发布
- 支持ECC加密解密
- 支持重放攻击防护
- 支持唯一请求防护
- 提供SpringBoot自动配置
package io.github.jasonlat.middleware.exception;

import lombok.Getter;
import lombok.Setter;


/**
 * 重放保护异常
 * 当检测到重放攻击或重复请求时抛出
 *
 * @author jasonlat
 */
@Setter
@Getter
public class ReplayProtectionException extends RuntimeException {

    // Getters and Setters
    /**
     * 错误代码
     */
    private String errorCode;

    /**
     * 请求ID
     */
    private String requestId;

    /**
     * 时间戳
     */
    private String timestamp;
    
    public ReplayProtectionException(String message) {
        super(message);
    }
    
    public ReplayProtectionException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public ReplayProtectionException(String message, String errorCode, String requestId, String timestamp) {
        super(message);
        this.errorCode = errorCode;
        this.requestId = requestId;
        this.timestamp = timestamp;
    }
    
    public ReplayProtectionException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public ReplayProtectionException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    @Override
    public String toString() {
        return "ReplayProtectionException{" +
                "errorCode='" + errorCode + '\'' +
                ", requestId='" + requestId + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", message='" + getMessage() + '\'' +
                '}';
    }
}
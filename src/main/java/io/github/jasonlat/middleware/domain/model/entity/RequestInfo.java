package io.github.jasonlat.middleware.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * @author jasonlat
 */
@AllArgsConstructor
@Builder
@Data
public final class RequestInfo {
    
    /**
     * 请求ID
     */
    private String requestId;
    
    /**
     * 客户端时间戳
     */
    private String clientTimestamp;
    
    /**
     * 服务器接收时间
     */
    private LocalDateTime serverReceiveTime;
    
    /**
     * 请求方法
     */
    private String method;
    
    /**
     * 请求URI
     */
    private String uri;
    
    /**
     * 客户端IP
     */
    private String clientIp;
    
    /**
     * 用户代理
     */
    private String userAgent;

    public RequestInfo() {
        this.serverReceiveTime = LocalDateTime.now();
    }

    public RequestInfo(String requestId, String clientTimestamp) {
        this();
        this.requestId = requestId;
        this.clientTimestamp = clientTimestamp;
    }


    public long getServerReceiveTimeAsMillis() {
        return serverReceiveTime.toInstant(ZoneOffset.UTC).toEpochMilli();
    }
    

}
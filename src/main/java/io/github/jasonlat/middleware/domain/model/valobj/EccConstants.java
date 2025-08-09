package io.github.jasonlat.middleware.domain.model.valobj;

import lombok.AllArgsConstructor;

/**
 * @author jasonlat
 */
@AllArgsConstructor
public enum EccConstants {

    USER_PUBLIC_X_KEY_HEADER("X-Public-X", "默认用户x密钥存储的请求头 key"),
    USER_PUBLIC_Y_KEY_HEADER("X-Public-Y", "默认用户y密钥存储的请求头 key"),
    ANONYMOUS_USER_ID("anonymous_user_id_get_key_from_request_header", "匿名用户，未配置获取用户id方法时，默认使用这种方式")
    ;

    private final String VALUE;

    private final String DESC;

    public String VALUE() {
        return VALUE;
    }

    public String DESC() {
        return DESC;
    }
}

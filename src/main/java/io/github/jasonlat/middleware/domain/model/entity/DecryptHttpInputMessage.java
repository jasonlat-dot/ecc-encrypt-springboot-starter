package io.github.jasonlat.middleware.domain.model.entity;

import lombok.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;

import java.io.InputStream;

/**
 * 解密信息输入流
 * @author li--jiaqiang
 */
public class DecryptHttpInputMessage implements HttpInputMessage {

    private final InputStream body;

    private final HttpHeaders headers;

    public DecryptHttpInputMessage(InputStream body, HttpHeaders headers) {
        this.body = body;
        this.headers = headers;
    }

    @Override
    @NonNull
    public InputStream getBody() {
        return body;
    }

    @Override
    @NonNull
    public HttpHeaders getHeaders() {
        return headers;
    }
}
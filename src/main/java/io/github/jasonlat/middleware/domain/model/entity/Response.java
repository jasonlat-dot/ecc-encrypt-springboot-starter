package io.github.jasonlat.middleware.domain.model.entity;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

/**
 * @author jasonlat
 */
@Setter
@Getter
public class Response<T> implements Serializable {

    private String code;
    private String info;
    private T data;

    public Response() {

    }

    private Response(Builder<T> builder) {
        this.code = builder.code;
        this.info = builder.info;
        this.data = builder.data;
    }



    // Builder class
    public static class Builder<T> {
        private String code;
        private String info;
        private T data;

        public Builder() {
        }

        public Builder<T> code(String code) {
            this.code = code;
            return this;
        }

        public Builder<T> info(String info) {
            this.info = info;
            return this;
        }

        public Builder<T> encryptMethod(String encryptMethod) {
            return this;
        }

        public Builder<T> data(T data) {
            this.data = data;
            return this;
        }


        public Response<T> build() {
            return new Response<>(this);
        }
    }

    public Response(String code, String info, String encryptMethod, T data) {
        this.code = code;
        this.info = info;
        this.data = data;
    }


    // Static method to create a Builder
    public static <T> Builder<T> builder() {
        return new Builder<>();
    }
}
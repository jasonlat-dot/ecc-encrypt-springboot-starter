package io.github.jasonlat.middleware.domain.service;

import io.github.jasonlat.middleware.domain.model.entity.UserPublicData;

public interface EccUserDataService {


    UserPublicData loadUserPublicData(String userId);

    String getCurrentUser();
}
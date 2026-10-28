package com.innowise.auth_service.mapper;

import com.innowise.auth_service.dto.RegisterRequest;
import com.innowise.auth_service.dto.UserCredentialsResponse;
import com.innowise.auth_service.entity.UserCredentials;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserCredentialsMapper {

    UserCredentialsResponse toResponse(UserCredentials user);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    UserCredentials toEntity(RegisterRequest request);
}

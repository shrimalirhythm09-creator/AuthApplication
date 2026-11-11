package com.auth.auth_app.dto;

import com.auth.auth_app.entity.RefreshToken;

public record RefreshTokenRequest(
        String  refreshToken
) {
}

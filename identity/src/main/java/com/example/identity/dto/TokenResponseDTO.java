package com.example.identity.dto;

public class TokenResponseDTO {

    private String accessToken;
    private String refreshToken;
    private String tokenType;

    public TokenResponseDTO(
            String accessToken,
            String refreshToken,
            String tokenType) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }
}
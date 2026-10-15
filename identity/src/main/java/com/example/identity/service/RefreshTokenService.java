package com.example.identity.service;

import com.example.identity.dto.TokenResponseDTO;
import com.example.identity.entity.RefreshToken;
import com.example.identity.entity.User;
import com.example.identity.Repository.RefreshTokenRepository;
import com.example.identity.Repository.UserRepository;
import com.example.identity.security.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            JwtUtils jwtUtils) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(
                Instant.now().plusMillis(refreshTokenExpiration));

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token does not exist or has already been used"));

        if (!oldToken.getExpiryDate().isAfter(Instant.now())) {
            refreshTokenRepository.delete(oldToken);
            refreshTokenRepository.flush();

            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token expired. Please log in again.");
        }

        User user = oldToken.getUser();

        refreshTokenRepository.delete(oldToken);
        refreshTokenRepository.flush();

        String newAccessToken = jwtUtils.generateAccessToken(user);
        RefreshToken newRefreshToken = createRefreshToken(user.getId());

        return new TokenResponseDTO(
                newAccessToken,
                newRefreshToken.getToken(),
                "Bearer");
    }

    @Transactional
    public RefreshToken verifyAndRotate(String token) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token does not exist or has already been used"));

        if (!oldToken.getExpiryDate().isAfter(Instant.now())) {
            refreshTokenRepository.delete(oldToken);
            refreshTokenRepository.flush();

            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh token expired. Please log in again.");
        }

        User user = oldToken.getUser();

        refreshTokenRepository.delete(oldToken);
        refreshTokenRepository.flush();

        return createRefreshToken(user.getId());
    }
}
package com.example.identity.service;

import com.example.identity.security.JwtUtils;
import io.jsonwebtoken.Claims;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private final JwtUtils jwtUtils;

    public TokenBlacklistService(
            StringRedisTemplate redisTemplate,
            JwtUtils jwtUtils) {
        this.redisTemplate = redisTemplate;
        this.jwtUtils = jwtUtils;
    }

    public void logout(String token) {
        Claims claims = jwtUtils.getClaims(token);

        String jti = claims.getId();
        Date expiration = claims.getExpiration();

        if (jti == null || expiration == null) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid token claims");
        }

        long ttl = expiration.toInstant().getEpochSecond()
                - Instant.now().getEpochSecond();

        if (ttl <= 0) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Access token expired");
        }

        redisTemplate.opsForValue().set(
                "blacklist:" + jti,
                "revoked",
                ttl,
                TimeUnit.SECONDS
        );
    }

    public boolean isBlacklisted(String jti) {
        if (jti == null) {
            return false;
        }

        return Boolean.TRUE.equals(
                redisTemplate.hasKey("blacklist:" + jti)
        );
    }
}
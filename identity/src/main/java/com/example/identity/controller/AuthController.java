package com.example.identity.controller;

import com.example.identity.dto.AuthResponse;
import com.example.identity.dto.LoginRequest;
import com.example.identity.dto.RefreshRequest;
import com.example.identity.dto.RegisterRequest;
import com.example.identity.entity.RefreshToken;
import com.example.identity.entity.User;
import com.example.identity.Repository.UserRepository;
import com.example.identity.security.JwtUtils;
import com.example.identity.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService,
            PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Email already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("ROLE_USER");

        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body("Registration successful");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()));

        User user = (User) authentication.getPrincipal();

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(user.getId());

        return ResponseEntity.ok(
                new AuthResponse(
                        accessToken,
                        refreshToken.getToken(),
                        "Bearer"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @Valid @RequestBody RefreshRequest request) {

        RefreshToken newRefreshToken =
                refreshTokenService.verifyAndRotate(request.getRefreshToken());

        User user = newRefreshToken.getUser();
        String newAccessToken = jwtUtils.generateAccessToken(user);

        return ResponseEntity.ok(
                new AuthResponse(
                        newAccessToken,
                        newRefreshToken.getToken(),
                        "Bearer"));
    }
}
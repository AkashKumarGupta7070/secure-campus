package com.securecampus.ids.controller;

import com.securecampus.ids.dto.LoginRequest;
import com.securecampus.ids.dto.LoginResponse;
import com.securecampus.ids.dto.LogoutRequest;
import com.securecampus.ids.entity.RefreshToken;
import com.securecampus.ids.security.JwtService;
import com.securecampus.ids.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          RefreshTokenService refreshTokenService) {

        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request,
                               BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            FieldError error = bindingResult.getFieldError();
            throw new IllegalArgumentException(error.getDefaultMessage());
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        String accessToken = jwtService.generateToken(request.getUsername());

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(request.getUsername());

        return new LoginResponse(
                accessToken,
                refreshToken.getToken()
        );
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody LogoutRequest request) {

        refreshTokenService.deleteByToken(request.getRefreshToken());

        return ResponseEntity.ok("Logged out successfully");
    }
    @PostMapping("/refresh")
    public LoginResponse refresh(@RequestBody String refreshTokenValue) {

        RefreshToken refreshToken = refreshTokenService
                .findByToken(refreshTokenValue)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshTokenService.isExpired(refreshToken)) {
            refreshTokenService.deleteToken(refreshToken);
            throw new RuntimeException("Refresh token expired");
        }

        String username = refreshToken.getUser().getUsername();

        String newAccessToken = jwtService.generateToken(username);

        // ROTATION: delete old token
        refreshTokenService.deleteToken(refreshToken);

        // create new refresh token
        RefreshToken newRefreshToken =
                refreshTokenService.createRefreshToken(username);

        return new LoginResponse(
                newAccessToken,
                newRefreshToken.getToken()
        );
    }

}

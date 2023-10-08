package com.roomreservation.authservice.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.roomreservation.authservice.config.JwtService;
import com.roomreservation.authservice.token.TokenEntity;
import com.roomreservation.authservice.token.TokenRepository;
import com.roomreservation.authservice.user.Permission;
import com.roomreservation.authservice.user.UserEntity;
import com.roomreservation.authservice.user.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.NoSuchElementException;


@Service
public class AuthService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService tokenProvider;
    private final AuthenticationManager authenticationManager;

    public AuthService(
        UserRepository userRepository,
        TokenRepository tokenRepository,
        JwtService tokenProvider,
        AuthenticationManager authenticationManager
    ) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }

    public JwtAuthenticationResponseDto registerUser(RegisterRequestDto request) {
        var user = UserEntity.builder()
                .roles(request.getRole())
                .password(request.getPassword())
                .email(request.getEmail())
                .build();
        user = userRepository.save(user);
        String accessToken = tokenProvider.generateToken(user);
        String refreshToken = tokenProvider.generateRefreshToken(user);
        saveUserToken(user, accessToken);
        return new JwtAuthenticationResponseDto(accessToken, refreshToken);
    }

    public JwtAuthenticationResponseDto login(LoginRequestDto loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication); //  poinformowaliśmy Spring Security, kto jest obecnie zalogowanym użytkownikiem w bieżącym wątku.

        var user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(); // TODO - trzeba zmapować na 404; nie ma takiego użytkownika

        String accessToken = tokenProvider.generateToken(user);
        String refreshToken = tokenProvider.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        return new JwtAuthenticationResponseDto(accessToken, refreshToken);
    }

    public void verify(JwtAuthenticationResponseDto tokenRequest) {
        tokenRepository.findByToken(tokenRequest.getAccessToken())
                .ifPresentOrElse(
                        token -> {
                            if(token.isExpired() || token.isRevoked())
                                throw new IllegalArgumentException("Invalid JWT token");
                            },
                        () -> {
                            throw new NoSuchElementException(); // TODO: trzeba zmapować na 404; nie ma takiego użytkownika
                        });
    }

    public void verifyAccess(JwtAuthenticationResponseDto tokenRequest, Permission permission) {
        tokenRepository.findByToken(tokenRequest.getAccessToken())
                .ifPresentOrElse(
                        token -> {
                            if(token.isExpired() || token.isRevoked())
                                throw new IllegalArgumentException("Invalid JWT token");
                            else
                                tokenRepository.
                        },
                        () -> {
                            throw new NoSuchElementException(); // TODO: trzeba zmapować na 404; nie ma takiego użytkownika
                        });
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = tokenProvider.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = userRepository.findByEmail(userEmail)
                    .orElseThrow();
            if (tokenProvider.isTokenValid(refreshToken, user)) {
                var accessToken = tokenProvider.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = JwtAuthenticationResponseDto.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private void revokeAllUserTokens(UserEntity user) {
        var validTokenList = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validTokenList.isEmpty()) return;
        validTokenList.forEach(tokenRepository::delete);
    }

    private void saveUserToken(UserEntity user, String accessToken) {
        tokenRepository.save(
                TokenEntity.builder()
                        .user(user)
                        .token(accessToken)
                        .expired(false)
                        .revoked(false)
                        .build());
    }
}

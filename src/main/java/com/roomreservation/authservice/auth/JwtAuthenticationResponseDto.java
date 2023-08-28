package com.roomreservation.authservice.auth;

import lombok.*;

@Data
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtAuthenticationResponseDto {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";

    JwtAuthenticationResponseDto(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

}

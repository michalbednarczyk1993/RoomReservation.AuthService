package com.roomreservation.authservice.auth;

import com.roomreservation.authservice.user.Permission;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register-user")
    @ApiOperation(value = "Rejestruje nowego użytkownika, oraz generuje token JWT")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Poprawnie zarejestrowano, zalogowano i wygenerowano token JWT"),
            @ApiResponse(code = 400, message = "Błędne dane logowania"),
            @ApiResponse(code = 500, message = "Błąd serwera")
    })
    public ResponseEntity<JwtAuthenticationResponseDto> registerUser(RegisterRequestDto registerRequestDto) {
        return ResponseEntity.ok(authService.registerUser(registerRequestDto));
    }

    @PostMapping("/login")
    @ApiOperation(value = "Logowanie użytkownika i zwracanie tokena JWT")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Poprawnie zalogowano i wygenerowano token JWT"),
            @ApiResponse(code = 400, message = "Błędne dane logowania"),
            @ApiResponse(code = 500, message = "Błąd serwera")
    })
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequestDto loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @PostMapping("/verify")
    @ApiOperation(value = "Weryfikacja poprawności tokena JWT")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Token jest poprawny"),
            @ApiResponse(code = 400, message = "Błędny token"),
            @ApiResponse(code = 500, message = "Błąd serwera")
    })
    public ResponseEntity<Void> verify(@RequestBody @Valid JwtAuthenticationResponseDto tokenRequest) {
        authService.verify(tokenRequest);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify-access")
    @ApiOperation(value = "Weryfikacja dostępu do zasobów dla tokena JWT")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Posiada dostęp do zasobów"),
            @ApiResponse(code = 400, message = "Błędne żądanie"),
            @ApiResponse(code = 403, message = "Brak dostępu do zasobów"),
            @ApiResponse(code = 500, message = "Błąd serwera")
    })
    public ResponseEntity<Void> verifyAccess(
            @RequestBody @Valid JwtAuthenticationResponseDto tokenRequest,
            @RequestBody @Valid Permission permission)
    {
        authService.verifyAccess(tokenRequest, permission);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/refresh")
    @ApiOperation(value = "Odświeżenie tokena JWT")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Poprawnie odświeżono token JWT"),
            @ApiResponse(code = 400, message = "Błędny token odświeżający"),
            @ApiResponse(code = 500, message = "Błąd serwera")
    })
    public ResponseEntity<JwtAuthenticationResponseDto> refresh(
            HttpServletRequest request,
            HttpServletResponse response)
            throws IOException
    {
        authService.refreshToken(request, response);
        return ResponseEntity.ok().build();
    }
}

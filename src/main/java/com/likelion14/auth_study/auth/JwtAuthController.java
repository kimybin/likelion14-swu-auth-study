package com.likelion14.auth_study.auth;

import com.likelion14.auth_study.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/jwt")
@RequiredArgsConstructor
public class JwtAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(
                            request.username(), request.password()));

            String role = authentication.getAuthorities().iterator().next().getAuthority();
            String token = jwtTokenProvider.createToken(authentication.getName(), role);

            // 세션에 저장하지 않음! 토큰을 클라이언트에게 넘겨줌
            return ResponseEntity.ok(Map.of("accessToken", token));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "아이디 또는 비밀번호가 틀렸습니다."));
        }
    }

    // 3주차 확인용 임시 엔드포인트 (4주차에 필터로 대체됨)
    @GetMapping("/verify")
    public ResponseEntity<?> verify(@RequestHeader("Authorization") String authorization) {
        String token = authorization.replace("Bearer ", "");

        if (!jwtTokenProvider.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "유효하지 않은 토큰입니다."));
        }

        Claims claims = jwtTokenProvider.parseClaims(token);
        return ResponseEntity.ok(Map.of(
                "subject", claims.getSubject(),
                "role", claims.get("role"),
                "issuedAt", claims.getIssuedAt(),
                "expiration", claims.getExpiration()
        ));
    }
}
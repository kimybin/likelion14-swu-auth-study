package com.likelion14.auth_study.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final long expirationMs;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.expiration-ms}") long expirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    // 토큰 발급
    public String createToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(username)        // sub 클레임
                .claim("role", role)      // 커스텀 클레임
                .issuedAt(now)            // iat 클레임
                .expiration(expiry)       // exp 클레임
                .signWith(key)            // 서명 (여기서 세 번째 조각 생성)
                .compact();               // 문자열로 합치기
    }

    // 토큰 해석 (서명 검증 + 만료 검사가 여기서 함께 일어남)
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("만료된 토큰입니다.");
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("유효하지 않은 토큰입니다: {}", e.getMessage());
        }
        return false;
    }
}
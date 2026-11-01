package com.likelion14.auth_study.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class JwtTokenProvider {

    // 1. 필드
    private final SecretKey key;
    private final long accessExpirationMs;
    private final long refreshExpirationMs;

    // 2. 생성자
    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.access-expiration-ms}") long accessExpirationMs,
                            @Value("${jwt.refresh-expiration-ms}") long refreshExpirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    // 3. 토큰 생성
    // 공통 로직 (private — 외부에서 직접 호출 못 하게)
    public String createToken(String username, String role, String type, long validityMs) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + validityMs);

        return Jwts.builder()
                .subject(username)        // sub 클레임
                .claim("role", role)   // 커스텀 클레임
                .claim("type", type)   // 토큰 종류를 구분하는 클레임
                .issuedAt(now)            // iat 클레임
                .expiration(expiry)       // exp 클레임
                .signWith(key)            // 서명 (여기서 세 번째 조각 생성)
                .compact();               // 문자열로 합치기
    }

    public String createAccessToken(String username, String role) {
        return createToken(username, role, "access", accessExpirationMs);
    }

    public String createRefreshToken(String username) {
        // Refresh는 재발급에만 쓰이므로 권한 정보 불필요
        return createToken(username, null, "refresh", refreshExpirationMs);
    }

    // 4. 토큰 해석 및 검증 (서명 검증 + 만료 검사가 여기서 함께 일어남)
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

    // 토큰에서 인증 정보를 꺼내 Security가 이해하는 객체로 변환
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        String username = claims.getSubject();                // "yubin"
        String role = claims.get("role", String.class);       // "ROLE_USER"

        // 권한 목록 생성 (한 사람이 여러 권한을 가질 수 있어서 List)
        List<GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority(role));

        // 인증 완료된 토큰 객체 (비밀번호 자리는 null — 이미 검증 끝났으니 불필요)
        return UsernamePasswordAuthenticationToken.authenticated(username, null, authorities);
    }

    // 5. 조회용
    public String getUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public String getType(String token) {
        return parseClaims(token).get("type", String.class);
    }
}
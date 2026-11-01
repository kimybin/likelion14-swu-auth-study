package com.likelion14.auth_study.auth;

import com.likelion14.auth_study.jwt.JwtTokenProvider;
import com.likelion14.auth_study.jwt.RefreshToken;
import com.likelion14.auth_study.jwt.RefreshTokenRepository;
import com.likelion14.auth_study.member.Member;
import com.likelion14.auth_study.member.MemberRepository;
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
    private final RefreshTokenRepository refreshTokenRepository;
    private final MemberRepository memberRepository;

    // 로그인: 토큰 두 개 발급
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(
                            request.username(), request.password()));

            String username = authentication.getName();
            String role = authentication.getAuthorities().iterator().next().getAuthority();

            String accessToken = jwtTokenProvider.createAccessToken(username, role);
            String refreshToken = jwtTokenProvider.createRefreshToken(username);

            // Refresh만 서버에 저장 (같은 username이면 덮어쓰기)
            refreshTokenRepository.save(new RefreshToken(username, refreshToken));

            return ResponseEntity.ok(new TokenResponse(accessToken, refreshToken));

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "아이디 또는 비밀번호가 틀렸습니다."));
        }
    }

    // 재발급
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@RequestBody ReissueRequest request) {
        String refreshToken = request.refreshToken();

        // 1단계: 서명과 만료 검증
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "유효하지 않은 Refresh Token입니다."));
        }

        // 2단계: 정말 Refresh Token이 맞는지 (Access를 보내면 거부)
        if (!"refresh".equals(jwtTokenProvider.getType(refreshToken))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Refresh Token이 아닙니다."));
        }

        String username = jwtTokenProvider.getUsername(refreshToken);

        // 3단계: 서버에 저장된 것과 일치하는지 (로그아웃된 토큰 차단)
        RefreshToken saved = refreshTokenRepository.findById(username).orElse(null);
        if (saved == null || !saved.getToken().equals(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "이미 사용되었거나 로그아웃된 토큰입니다."));
        }

        // 4단계: 권한은 DB에서 다시 조회 (그 사이 권한이 바뀌었을 수 있으므로)
        Member member = memberRepository.findByUsername(username).orElseThrow();
        String role = "ROLE_" + member.getRole();

        // 5단계: 새 토큰 발급 + Rotation (Refresh도 새것으로 교체)
        String newAccessToken = jwtTokenProvider.createAccessToken(username, role);
        String newRefreshToken = jwtTokenProvider.createRefreshToken(username);
        saved.updateToken(newRefreshToken);
        refreshTokenRepository.save(saved);

        return ResponseEntity.ok(new TokenResponse(newAccessToken, newRefreshToken));
    }

    // 로그아웃: 저장된 Refresh 삭제
    @PostMapping("/logout")
    public ResponseEntity<?> logout(Authentication authentication) {
        // 필터가 등록해준 인증 정보 → Access Token이 유효해야 호출 가능
        refreshTokenRepository.deleteById(authentication.getName());
        return ResponseEntity.ok(Map.of("message", "로그아웃 완료"));
    }
}
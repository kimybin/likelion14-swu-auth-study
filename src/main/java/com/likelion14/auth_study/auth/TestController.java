package com.likelion14.auth_study.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/jwt/me")
    public ResponseEntity<String> me(Authentication authentication) {
        return ResponseEntity.ok("현재 사용자: " + authentication.getName()
                + " / 권한: " + authentication.getAuthorities());
    }

    @GetMapping("/admin/dashboard")
    public ResponseEntity<String> adminOnly() {
        return ResponseEntity.ok("관리자 전용 페이지");
    }
}
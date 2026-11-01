package com.likelion14.auth_study.jwt;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    @Id
    private String username;   // 사용자당 하나만 저장 → 새 로그인 시 덮어쓰기

    @Column(nullable = false, length = 512)
    private String token;      // JWT는 길어서 길이를 넉넉히

    public RefreshToken(String username, String token) {
        this.username = username;
        this.token = token;
    }

    public void updateToken(String token) {
        this.token = token;    // Rotation 때 사용
    }
}
package com.likelion14.auth_study.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/session")
public class SessionLoginController {
    private static final String LOGIN_USER = "LOGIN_USER";

    // DB 말고 임시 유저 사용
    private final Map<String, String> users = Map.of(
            "yubin", "1234",
            "guest", "0000"
    );

    // 로그인
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request,
                                        HttpServletRequest httpRequest) {
        String savedPassword = users.get(request.username());
        if (savedPassword == null || !savedPassword.equals(request.password())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("아이디 또는 비밀번호가 틀렸습니다.");
        }

        HttpSession session = httpRequest.getSession(true); // 없으면 새로 생성
        session.setAttribute(LOGIN_USER, request.username());
        return ResponseEntity.ok("로그인 성공: " + request.username());
    }

    // 현재 로그인한 사용자 조회
    @GetMapping("/me")
    public ResponseEntity<String> me(HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession(false); // 없으면 null
        if (session == null || session.getAttribute(LOGIN_USER) == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("로그인이 필요합니다.");
        }
        return ResponseEntity.ok("현재 로그인 사용자: " + session.getAttribute(LOGIN_USER));
    }

    // 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            session.invalidate(); // 쿠키를 지우는 게 아니라, 서버 쪽에서 세션 삭제
        }
        return ResponseEntity.ok("로그아웃 완료");
    }


}

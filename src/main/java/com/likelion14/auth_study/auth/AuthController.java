package com.likelion14.auth_study.auth;

import com.likelion14.auth_study.member.Member;
import com.likelion14.auth_study.member.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody AuthRequest request) {
        if (memberRepository.existsByUsername(request.username())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 존재하는 아이디입니다.");
        }
        String encoded = passwordEncoder.encode(request.password());
        memberRepository.save(new Member(request.username(), encoded, "USER"));
        return ResponseEntity.ok("회원가입 완료");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthRequest request,
                                        HttpServletRequest httpRequest,
                                        HttpServletResponse httpResponse) {
        try {
            // 1주차의 "비번 비교"를 Security가 대신 수행
            Authentication authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(
                            request.username(), request.password()));

            // 1주차의 session.setAttribute()에 해당
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, httpRequest, httpResponse);

            return ResponseEntity.ok("로그인 성공: " + authentication.getName());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("아이디 또는 비밀번호가 틀렸습니다.");
        }
    }

    @GetMapping("/me")
    public ResponseEntity<String> me(Authentication authentication) {
        // 여기까지 왔다면 이미 필터가 인증을 확인한 상태
        return ResponseEntity.ok("현재 로그인 사용자: " + authentication.getName());
    }
}
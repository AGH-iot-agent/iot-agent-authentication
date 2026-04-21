package io.agh.iot.authentication.controller;

import io.agh.iot.authentication.model.User;
import io.agh.iot.authentication.service.JwtService;
import io.agh.iot.authentication.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final String TOKEN_COOKIE = "token";
    private static final String USERNAME_FIELD = "username";

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody Map<String, String> req, HttpServletRequest request, HttpServletResponse response) {
        String username = req.get(USERNAME_FIELD);
        String email = req.get("email");
        String password = req.get("password");
        if (username == null || email == null || password == null) {
            return ResponseEntity.badRequest().body("Brak wymaganych pól");
        }
        if (userService.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body("Użytkownik już istnieje");
        }
        User user = userService.register(username, email, password);
        String token = jwtService.generateToken(user.getUsername());
        response.addHeader(HttpHeaders.SET_COOKIE, buildTokenCookie(request, token, Duration.ofDays(1)).toString());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody Map<String, String> req, HttpServletRequest request, HttpServletResponse response) {
        String username = req.get(USERNAME_FIELD);
        String password = req.get("password");
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body("Brak wymaganych pól");
        }
        return userService.findByUsername(username)
            .filter(user -> userService.checkPassword(user, password))
            .<ResponseEntity<Object>>map(user -> {
                String token = jwtService.generateToken(user.getUsername());
                response.addHeader(HttpHeaders.SET_COOKIE, buildTokenCookie(request, token, Duration.ofDays(1)).toString());
                return ResponseEntity.ok().build();
            })
            .orElseGet(() -> ResponseEntity.status(401).body("Błędny login lub hasło"));
    }

    @GetMapping("/me")
    public ResponseEntity<Object> me(HttpServletRequest request) {
        String token = extractTokenFromCookies(request);
        @RestController
        @RequestMapping("/api/auth")
        public class AuthController {
            @GetMapping("/health")
            public ResponseEntity<?> health() {
                return ResponseEntity.ok(Map.of("status", "UP"));
            }
        }
            .maxAge(maxAge);

        String domain = resolveCookieDomain(request);
        if (domain != null) {
            cookieBuilder.domain("." + domain);
        }
        return cookieBuilder.build();
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP"));
    }

    private String resolveCookieDomain(HttpServletRequest request) {
        String host = request.getHeader("X-Forwarded-Host");
        if (host == null || host.isBlank()) {
            host = request.getHeader("Host");
        }
        if (host == null || host.isBlank()) {
            return null;
        }

        String normalizedHost = host.split(",")[0].trim();
        int portSeparatorIndex = normalizedHost.indexOf(':');
        if (portSeparatorIndex >= 0) {
            normalizedHost = normalizedHost.substring(0, portSeparatorIndex);
        }

        if (normalizedHost.equals("localhost") || normalizedHost.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return null;
        }

        String[] parts = normalizedHost.split("\\.");
        if (parts.length < 2) {
            return null;
        }

        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private boolean isSecureRequest(HttpServletRequest request) {
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if (forwardedProto != null && !forwardedProto.isBlank()) {
            return "https".equalsIgnoreCase(forwardedProto);
        }
        return request.isSecure();
    }
}

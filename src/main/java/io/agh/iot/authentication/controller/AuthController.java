package io.agh.iot.authentication.controller;

import io.agh.iot.authentication.model.User;
import io.agh.iot.authentication.service.JwtService;
import io.agh.iot.authentication.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

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
    public ResponseEntity<Object> register(@RequestBody Map<String, String> req, HttpServletResponse response) {
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
        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(TOKEN_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 24); // 1 dzień
        response.addCookie(cookie);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody Map<String, String> req, HttpServletResponse response) {
        String username = req.get(USERNAME_FIELD);
        String password = req.get("password");
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body("Brak wymaganych pól");
        }
        return userService.findByUsername(username)
            .filter(user -> userService.checkPassword(user, password))
            .<ResponseEntity<Object>>map(user -> {
                String token = jwtService.generateToken(user.getUsername());
                jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(TOKEN_COOKIE, token);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(60 * 60 * 24); // 1 dzień
                response.addCookie(cookie);
                return ResponseEntity.ok().build();
            })
            .orElseGet(() -> ResponseEntity.status(401).body("Błędny login lub hasło"));
    }

    @GetMapping("/me")
    public ResponseEntity<Object> me(HttpServletRequest request) {
        String token = extractTokenFromCookies(request);
        if (token == null) {
            return ResponseEntity.status(401).body("Brak tokenu");
        }

        try {
            String username = jwtService.extractUsername(token);
            return ResponseEntity.ok(Map.of(USERNAME_FIELD, username));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Nieprawidłowy token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie(TOKEN_COOKIE, "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/validate")
    public ResponseEntity<Object> validate(@RequestParam String token) {
        try {
            String username = jwtService.extractUsername(token);
            return ResponseEntity.ok(Map.of(USERNAME_FIELD, username));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Nieprawidłowy token");
        }
    }

    private String extractTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (TOKEN_COOKIE.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }
}

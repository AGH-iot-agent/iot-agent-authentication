package io.agh.iot.authentication.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

@RestController
public class JwksController {
    @Value("${jwt.secret}")
    private String jwtSecret;

    // UWAGA: To uproszczony JWKS dla HS256 (symetryczny klucz)
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<?> jwks() {
        // W produkcji: wystawiaj JWKS tylko dla RS256!
        String k = Base64.getUrlEncoder().withoutPadding().encodeToString(jwtSecret.getBytes());
        Map<String, Object> jwk = Map.of(
                "kty", "oct",
                "k", k,
                "alg", "HS256",
                "use", "sig",
                "kid", "main"
        );
        return ResponseEntity.ok(Map.of("keys", new Object[]{jwk}));
    }
}

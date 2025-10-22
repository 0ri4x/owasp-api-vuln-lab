package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.service.PasswordService;
import edu.nu.owaspapivulnlab.web.dto.SignupRequest;
import edu.nu.owaspapivulnlab.web.dto.UserDTO;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordService passwordService;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordService passwordService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordService = passwordService;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        // SECURE: Using BCrypt password verification instead of plaintext comparison
        AppUser user = users.findByUsername(req.username()).orElse(null);
        if (user != null && passwordService.verifyPassword(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        // Check if username already exists
        if (users.findByUsername(req.getUsername()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username already exists");
            return ResponseEntity.status(409).body(error);
        }
        
        // Check if email already exists
        if (users.findByEmail(req.getEmail()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email already exists");
            return ResponseEntity.status(409).body(error);
        }
        
        // Create new user with hashed password
        AppUser newUser = AppUser.builder()
                .username(req.getUsername())
                .password(passwordService.hashPassword(req.getPassword())) // SECURE: Hash password before storing
                .email(req.getEmail())
                .role("USER") // Default role for new users
                .isAdmin(false) // Default to non-admin
                .build();
        
        AppUser savedUser = users.save(newUser);
        
        // Convert to DTO to prevent password exposure
        UserDTO userDTO = UserDTO.builder()
                .id(savedUser.getId())
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .isAdmin(savedUser.isAdmin())
                .build();
        
        return ResponseEntity.status(201).body(userDTO);
    }
}

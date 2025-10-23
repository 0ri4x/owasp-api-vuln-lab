package edu.nu.owaspapivulnlab.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.service.PasswordService;
import edu.nu.owaspapivulnlab.service.RateLimitService;
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
    private final RateLimitService rateLimitService;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordService passwordService, RateLimitService rateLimitService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordService = passwordService;
        this.rateLimitService = rateLimitService;
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
    public ResponseEntity<?> login(@RequestBody LoginReq req, HttpServletRequest request) {
        // SECURITY FIX: Additional rate limiting check with detailed logging
        if (!rateLimitService.isAuthAllowed(request)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many login attempts. Please try again later.");
            error.put("remainingAttempts", rateLimitService.getAuthRemainingTokens(request));
            
            // SECURITY FIX: Log suspicious activity for monitoring
            System.err.println("SECURITY ALERT: Rate limit exceeded for login from IP: " + 
                             request.getRemoteAddr() + " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Enhanced input validation
        if (req.username() == null || req.username().trim().isEmpty() || 
            req.password() == null || req.password().trim().isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username and password are required");
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURE: Using BCrypt password verification instead of plaintext comparison
        AppUser user = users.findByUsername(req.username().trim()).orElse(null);
        if (user != null && passwordService.verifyPassword(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            String token = jwt.issue(user.getUsername(), claims);
            
            // SECURITY FIX: Log successful authentication for monitoring
            System.out.println("INFO: Successful login for user: " + user.getUsername() + 
                             " from IP: " + request.getRemoteAddr());
            
            return ResponseEntity.ok(new TokenRes(token));
        }
        
        // SECURITY FIX: Log failed authentication attempts for monitoring
        System.err.println("SECURITY ALERT: Failed login attempt for username: " + req.username() + 
                         " from IP: " + request.getRemoteAddr() + " at " + java.time.Instant.now());
        
        Map<String, String> error = new HashMap<>();
        error.put("error", "Invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req, HttpServletRequest request) {
        // SECURITY FIX: Additional rate limiting check for signup endpoint
        if (!rateLimitService.isAuthAllowed(request)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many signup attempts. Please try again later.");
            error.put("remainingAttempts", rateLimitService.getAuthRemainingTokens(request));
            
            // SECURITY FIX: Log suspicious signup activity
            System.err.println("SECURITY ALERT: Rate limit exceeded for signup from IP: " + 
                             request.getRemoteAddr() + " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Enhanced input validation and sanitization
        if (req.getUsername() == null || req.getUsername().trim().isEmpty() ||
            req.getEmail() == null || req.getEmail().trim().isEmpty() ||
            req.getPassword() == null || req.getPassword().trim().isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username, email, and password are required");
            return ResponseEntity.status(400).body(error);
        }
        
        String sanitizedUsername = req.getUsername().trim().toLowerCase();
        String sanitizedEmail = req.getEmail().trim().toLowerCase();
        
        // SECURITY FIX: Prevent account enumeration with generic error messages
        boolean usernameExists = users.findByUsername(sanitizedUsername).isPresent();
        boolean emailExists = users.findByEmail(sanitizedEmail).isPresent();
        
        if (usernameExists || emailExists) {
            // SECURITY FIX: Generic error message to prevent enumeration
            Map<String, String> error = new HashMap<>();
            error.put("error", "Registration failed. Please check your information and try again.");
            
            // SECURITY FIX: Log enumeration attempts for monitoring
            System.err.println("SECURITY ALERT: Potential account enumeration attempt from IP: " + 
                             request.getRemoteAddr() + " for username: " + sanitizedUsername + 
                             " email: " + sanitizedEmail + " at " + java.time.Instant.now());
            
            return ResponseEntity.status(409).body(error);
        }
        
        // SECURITY FIX: Password strength validation
        if (req.getPassword().length() < 8) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Password must be at least 8 characters long");
            return ResponseEntity.status(400).body(error);
        }
        
        // Create new user with hashed password
        AppUser newUser = AppUser.builder()
                .username(sanitizedUsername)
                .password(passwordService.hashPassword(req.getPassword())) // SECURE: Hash password before storing
                .email(sanitizedEmail)
                .role("USER") // Default role for new users
                .isAdmin(false) // Default to non-admin
                .build();
        
        AppUser savedUser = users.save(newUser);
        
        // SECURITY FIX: Log successful registration for monitoring
        System.out.println("INFO: New user registered: " + savedUser.getUsername() + 
                         " from IP: " + request.getRemoteAddr());
        
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

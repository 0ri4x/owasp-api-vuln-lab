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
import edu.nu.owaspapivulnlab.service.SessionService;
import edu.nu.owaspapivulnlab.service.SecurityLoggingService;
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
    private final SessionService sessionService;
    private final SecurityLoggingService securityLoggingService;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordService passwordService, 
                         RateLimitService rateLimitService, SessionService sessionService,
                         SecurityLoggingService securityLoggingService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordService = passwordService;
        this.rateLimitService = rateLimitService;
        this.sessionService = sessionService;
        this.securityLoggingService = securityLoggingService;
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
        private String accessToken;
        private String refreshToken;
        private String tokenType;
        private long expiresIn;

        public TokenRes() {}

        public TokenRes(String accessToken, String refreshToken, String tokenType, long expiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.tokenType = tokenType;
            this.expiresIn = expiresIn;
        }

        public String getAccessToken() { return accessToken; }
        public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
        
        public String getRefreshToken() { return refreshToken; }
        public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
        
        public String getTokenType() { return tokenType; }
        public void setTokenType(String tokenType) { this.tokenType = tokenType; }
        
        public long getExpiresIn() { return expiresIn; }
        public void setExpiresIn(long expiresIn) { this.expiresIn = expiresIn; }
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
        
        // SECURITY FIX: Enhanced input validation with comprehensive checks
        if (req.username() == null || req.username().trim().isEmpty() || 
            req.password() == null || req.password().trim().isEmpty()) {
            
            securityLoggingService.logSecurityViolation(
                "INVALID_LOGIN_INPUT",
                req.username(),
                getClientIpAddress(request),
                "Empty username or password provided",
                "MEDIUM"
            );
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username and password are required");
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURITY FIX: Validate username format
        if (!inputValidationService.isValidUsername(req.username())) {
            securityLoggingService.logSecurityViolation(
                "INVALID_USERNAME_FORMAT",
                req.username(),
                getClientIpAddress(request),
                "Invalid username format: " + req.username(),
                "MEDIUM"
            );
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid username format");
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURITY FIX: Validate password length (basic check)
        if (!inputValidationService.isValidStringLength(req.password(), 1, 1000)) {
            securityLoggingService.logSecurityViolation(
                "INVALID_PASSWORD_LENGTH",
                req.username(),
                getClientIpAddress(request),
                "Password length validation failed",
                "MEDIUM"
            );
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid password format");
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURE: Using BCrypt password verification instead of plaintext comparison
        AppUser user = users.findByUsername(req.username().trim()).orElse(null);
        if (user != null && passwordService.verifyPassword(req.password(), user.getPassword())) {
            
            // SECURITY FIX: Create secure session with binding information
            String clientIp = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");
            String sessionId = sessionService.createSession(user.getUsername(), clientIp, userAgent);
            
            // SECURITY FIX: Create JWT claims with security information
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            claims.put("ipAddress", clientIp);
            claims.put("userAgent", userAgent);
            
            // SECURITY FIX: Issue both access and refresh tokens
            String accessToken = jwt.issueAccessToken(user.getUsername(), claims, sessionId);
            String refreshToken = jwt.issueRefreshToken(user.getUsername(), sessionId);
            
            // SECURITY FIX: Log successful authentication using security logging service
            securityLoggingService.logAuthenticationEvent(
                "LOGIN",
                user.getUsername(),
                clientIp,
                userAgent,
                true,
                "SessionID: " + sessionId + " | Role: " + user.getRole()
            );
            
            return ResponseEntity.ok(new TokenRes(accessToken, refreshToken, "Bearer", 900)); // 15 minutes
        }
        
        // SECURITY FIX: Log failed authentication using security logging service
        securityLoggingService.logAuthenticationEvent(
            "LOGIN",
            req.username(),
            getClientIpAddress(request),
            request.getHeader("User-Agent"),
            false,
            "Invalid credentials provided"
        );
        
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

    /**
     * SECURITY FIX: Secure logout endpoint with token revocation
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);
            
            try {
                // SECURITY FIX: Get session ID before revoking token
                String sessionId = jwt.getSessionIdFromToken(token);
                
                // SECURITY FIX: Revoke the access token
                jwt.revokeToken(token);
                
                // SECURITY FIX: Invalidate the session
                if (sessionId != null) {
                    sessionService.invalidateSession(sessionId);
                }
                
                // SECURITY FIX: Log logout for audit
                System.out.println("INFO: User logged out - SessionID: " + sessionId + 
                                 " IP: " + getClientIpAddress(request) + 
                                 " Time: " + java.time.Instant.now());
                
                Map<String, String> response = new HashMap<>();
                response.put("message", "Successfully logged out");
                return ResponseEntity.ok(response);
                
            } catch (Exception e) {
                System.err.println("SECURITY ALERT: Logout failed: " + e.getMessage());
                Map<String, String> error = new HashMap<>();
                error.put("error", "Logout failed");
                return ResponseEntity.status(400).body(error);
            }
        }
        
        Map<String, String> error = new HashMap<>();
        error.put("error", "No valid token provided");
        return ResponseEntity.status(400).body(error);
    }

    /**
     * SECURITY FIX: Token refresh endpoint
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        String refreshToken = request.get("refreshToken");
        
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Refresh token is required");
            return ResponseEntity.status(400).body(error);
        }
        
        try {
            // SECURITY FIX: Validate refresh token
            if (!jwt.isTokenType(refreshToken, "refresh")) {
                throw new RuntimeException("Invalid token type");
            }
            
            io.jsonwebtoken.Claims claims = jwt.validateToken(refreshToken);
            String username = claims.getSubject();
            String sessionId = (String) claims.get("sessionId");
            
            // SECURITY FIX: Validate session is still active
            String clientIp = getClientIpAddress(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");
            
            if (!sessionService.validateSession(sessionId, clientIp, userAgent)) {
                throw new RuntimeException("Session validation failed");
            }
            
            // SECURITY FIX: Get user information for new token
            AppUser user = users.findByUsername(username).orElseThrow(() -> 
                new RuntimeException("User not found"));
            
            // SECURITY FIX: Create new access token
            Map<String, Object> newClaims = new HashMap<>();
            newClaims.put("role", user.getRole());
            newClaims.put("isAdmin", user.isAdmin());
            newClaims.put("ipAddress", clientIp);
            newClaims.put("userAgent", userAgent);
            
            String newAccessToken = jwt.issueAccessToken(username, newClaims, sessionId);
            
            // SECURITY FIX: Log token refresh for audit
            System.out.println("INFO: Token refreshed for user: " + username + 
                             " SessionID: " + sessionId + " IP: " + clientIp);
            
            return ResponseEntity.ok(new TokenRes(newAccessToken, refreshToken, "Bearer", 900));
            
        } catch (Exception e) {
            System.err.println("SECURITY ALERT: Token refresh failed: " + e.getMessage() + 
                             " IP: " + getClientIpAddress(httpRequest));
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "Token refresh failed");
            return ResponseEntity.status(401).body(error);
        }
    }

    /**
     * SECURITY FIX: Extract real client IP address considering proxies
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}

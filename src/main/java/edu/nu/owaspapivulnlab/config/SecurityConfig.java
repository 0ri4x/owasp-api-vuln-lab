package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;
    
    private final RateLimitFilter rateLimitFilter;
    private final MassAssignmentProtectionFilter massAssignmentProtectionFilter;
    private final JwtService jwtService;
    private final SessionService sessionService;

    public SecurityConfig(RateLimitFilter rateLimitFilter, MassAssignmentProtectionFilter massAssignmentProtectionFilter,
                         JwtService jwtService, SessionService sessionService) {
        this.rateLimitFilter = rateLimitFilter;
        this.massAssignmentProtectionFilter = massAssignmentProtectionFilter;
        this.jwtService = jwtService;
        this.sessionService = sessionService;
    }

    // SECURITY FIX: Enhanced SecurityFilterChain with rate limiting protection
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                // SECURE: Only allow public access to authentication endpoints
                .requestMatchers("/api/auth/login", "/api/auth/signup").permitAll()
                .requestMatchers("/h2-console/**").permitAll() // H2 console for development
                // SECURE: Require authentication for all other API endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated() // All other API endpoints require authentication
                .anyRequest().authenticated()
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console

        // SECURITY FIX: Add security filters in proper order for maximum protection
        http.addFilterBefore(rateLimitFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(massAssignmentProtectionFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtFilter(secret, jwtService, sessionService), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // SECURITY FIX: Hardened JWT filter with comprehensive validation
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        private final JwtService jwtService;
        private final SessionService sessionService;
        
        JwtFilter(String secret, JwtService jwtService, SessionService sessionService) { 
            this.secret = secret; 
            this.jwtService = jwtService;
            this.sessionService = sessionService;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    // SECURITY FIX: Use enhanced JWT validation
                    Claims claims = jwtService.validateToken(token);
                    
                    // SECURITY FIX: Validate session binding
                    String sessionId = (String) claims.get("sessionId");
                    String clientIp = getClientIpAddress(request);
                    String userAgent = request.getHeader("User-Agent");
                    
                    if (sessionId != null && !sessionService.validateSession(sessionId, clientIp, userAgent)) {
                        // SECURITY FIX: Log session validation failure
                        System.err.println("SECURITY ALERT: Session validation failed for token - " +
                                         "SessionID: " + sessionId + " IP: " + clientIp + 
                                         " Time: " + java.time.Instant.now());
                        SecurityContextHolder.clearContext();
                        chain.doFilter(request, response);
                        return;
                    }
                    
                    // SECURITY FIX: Validate token type (must be access token)
                    if (!jwtService.isTokenType(token, "access")) {
                        System.err.println("SECURITY ALERT: Invalid token type used for authentication");
                        SecurityContextHolder.clearContext();
                        chain.doFilter(request, response);
                        return;
                    }
                    
                    String user = claims.getSubject();
                    String role = (String) claims.get("role");
                    
                    // SECURITY FIX: Enhanced authentication with additional claims
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                        user, 
                        null,
                        role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList()
                    );
                    
                    // SECURITY FIX: Add additional authentication details
                    authn.setDetails(Map.of(
                        "sessionId", sessionId,
                        "jwtId", claims.getId(),
                        "issuedAt", claims.getIssuedAt(),
                        "expiresAt", claims.getExpiration()
                    ));
                    
                    SecurityContextHolder.getContext().setAuthentication(authn);
                    
                } catch (JwtException e) {
                    // SECURITY FIX: Enhanced error handling with detailed logging
                    SecurityContextHolder.clearContext();
                    System.err.println("SECURITY ALERT: JWT validation failed - " + 
                                     "IP: " + getClientIpAddress(request) + 
                                     " Error: " + e.getMessage() + 
                                     " Time: " + java.time.Instant.now());
                }
            }
            chain.doFilter(request, response);
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
}

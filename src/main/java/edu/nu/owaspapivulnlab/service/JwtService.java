package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SECURITY FIX: Hardened JWT service with strong cryptography and validation
 */
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    @Value("${app.jwt.refresh-ttl-seconds}")
    private long refreshTtlSeconds;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    // SECURITY FIX: Token blacklist for revocation support
    private final ConcurrentHashMap<String, Long> tokenBlacklist = new ConcurrentHashMap<>();
    
    // SECURITY FIX: Secure random for JWT ID generation
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * SECURITY FIX: Generate secure secret key from configured secret
     */
    private SecretKey getSigningKey() {
        // SECURITY FIX: Ensure minimum key length for HS256 (256 bits)
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 256 bits (32 bytes) for HS256");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * SECURITY FIX: Issue secure JWT with all required claims and validation
     */
    public String issueAccessToken(String subject, Map<String, Object> claims, String sessionId) {
        long now = System.currentTimeMillis();
        String jwtId = generateSecureJwtId();
        
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)                                    // SECURITY FIX: Add issuer claim
                .setAudience(audience)                                // SECURITY FIX: Add audience claim
                .setIssuedAt(new Date(now))                          // SECURITY FIX: Issue time
                .setNotBefore(new Date(now))                         // SECURITY FIX: Not valid before now
                .setExpiration(new Date(now + ttlSeconds * 1000))    // SECURITY FIX: Short expiration
                .setId(jwtId)                                        // SECURITY FIX: Unique JWT ID
                .addClaims(claims)                                   // User claims
                .claim("sessionId", sessionId)                       // SECURITY FIX: Session binding
                .claim("tokenType", "access")                        // SECURITY FIX: Token type
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // SECURITY FIX: Strong key
                .compact();
    }

    /**
     * SECURITY FIX: Issue refresh token with longer validity
     */
    public String issueRefreshToken(String subject, String sessionId) {
        long now = System.currentTimeMillis();
        String jwtId = generateSecureJwtId();
        
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)
                .setAudience(audience)
                .setIssuedAt(new Date(now))
                .setNotBefore(new Date(now))
                .setExpiration(new Date(now + refreshTtlSeconds * 1000))
                .setId(jwtId)
                .claim("sessionId", sessionId)
                .claim("tokenType", "refresh")
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * SECURITY FIX: Validate JWT with comprehensive security checks
     */
    public Claims validateToken(String token) throws JwtException {
        try {
            // SECURITY FIX: Parse and validate with strict requirements
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())                  // SECURITY FIX: Verify signature
                    .requireIssuer(issuer)                           // SECURITY FIX: Validate issuer
                    .requireAudience(audience)                       // SECURITY FIX: Validate audience
                    .setAllowedClockSkewSeconds(30)                  // SECURITY FIX: Allow 30s clock skew
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // SECURITY FIX: Check if token is blacklisted
            String jwtId = claims.getId();
            if (jwtId != null && isTokenBlacklisted(jwtId)) {
                throw new JwtException("Token has been revoked");
            }

            // SECURITY FIX: Validate expiration explicitly
            Date expiration = claims.getExpiration();
            if (expiration != null && expiration.before(new Date())) {
                throw new ExpiredJwtException(null, claims, "Token has expired");
            }

            // SECURITY FIX: Validate not-before claim
            Date notBefore = claims.getNotBefore();
            if (notBefore != null && notBefore.after(new Date())) {
                throw new PrematureJwtException(null, claims, "Token not yet valid");
            }

            return claims;
            
        } catch (ExpiredJwtException e) {
            throw new JwtException("Token has expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported JWT token: " + e.getMessage());
        } catch (MalformedJwtException e) {
            throw new JwtException("Malformed JWT token: " + e.getMessage());
        } catch (SignatureException e) {
            throw new JwtException("Invalid JWT signature: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new JwtException("Invalid JWT token: " + e.getMessage());
        }
    }

    /**
     * SECURITY FIX: Revoke token by adding to blacklist
     */
    public void revokeToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            
            String jwtId = claims.getId();
            if (jwtId != null) {
                long expiration = claims.getExpiration().getTime();
                tokenBlacklist.put(jwtId, expiration);
                
                // SECURITY FIX: Log token revocation for audit
                System.out.println("SECURITY: Token revoked - JTI: " + jwtId + 
                                 " Subject: " + claims.getSubject() + 
                                 " Time: " + java.time.Instant.now());
            }
        } catch (Exception e) {
            // SECURITY FIX: Log revocation attempts even if token is invalid
            System.err.println("SECURITY ALERT: Token revocation failed: " + e.getMessage());
        }
    }

    /**
     * SECURITY FIX: Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String jwtId) {
        Long expiration = tokenBlacklist.get(jwtId);
        if (expiration != null) {
            // SECURITY FIX: Remove expired blacklist entries
            if (expiration < System.currentTimeMillis()) {
                tokenBlacklist.remove(jwtId);
                return false;
            }
            return true;
        }
        return false;
    }

    /**
     * SECURITY FIX: Generate cryptographically secure JWT ID
     */
    private String generateSecureJwtId() {
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return UUID.nameUUIDFromBytes(randomBytes).toString();
    }

    /**
     * SECURITY FIX: Clean up expired blacklist entries periodically
     */
    public void cleanupExpiredBlacklistEntries() {
        long now = System.currentTimeMillis();
        tokenBlacklist.entrySet().removeIf(entry -> entry.getValue() < now);
    }

    /**
     * SECURITY FIX: Extract session ID from token for session binding validation
     */
    public String getSessionIdFromToken(String token) {
        try {
            Claims claims = validateToken(token);
            return (String) claims.get("sessionId");
        } catch (JwtException e) {
            return null;
        }
    }

    /**
     * SECURITY FIX: Check if token is of specific type (access/refresh)
     */
    public boolean isTokenType(String token, String expectedType) {
        try {
            Claims claims = validateToken(token);
            String tokenType = (String) claims.get("tokenType");
            return expectedType.equals(tokenType);
        } catch (JwtException e) {
            return false;
        }
    }
}

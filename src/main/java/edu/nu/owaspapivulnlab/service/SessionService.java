package edu.nu.owaspapivulnlab.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;

/**
 * SECURITY FIX: Session management service for JWT token binding
 */
@Service
public class SessionService {
    
    private final ConcurrentHashMap<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    
    /**
     * SECURITY FIX: Create new session with binding information
     */
    public String createSession(String username, String ipAddress, String userAgent) {
        String sessionId = generateSecureSessionId();
        
        SessionInfo sessionInfo = SessionInfo.builder()
                .sessionId(sessionId)
                .username(username)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .createdAt(System.currentTimeMillis())
                .lastAccessedAt(System.currentTimeMillis())
                .build();
        
        activeSessions.put(sessionId, sessionInfo);
        
        // SECURITY FIX: Log session creation for audit
        System.out.println("SECURITY: Session created - ID: " + sessionId + 
                         " User: " + username + " IP: " + ipAddress + 
                         " Time: " + java.time.Instant.now());
        
        return sessionId;
    }
    
    /**
     * SECURITY FIX: Validate session binding
     */
    public boolean validateSession(String sessionId, String ipAddress, String userAgent) {
        SessionInfo session = activeSessions.get(sessionId);
        if (session == null) {
            return false;
        }
        
        // SECURITY FIX: Validate IP address binding (optional - can be disabled for mobile users)
        boolean ipValid = session.getIpAddress().equals(ipAddress);
        
        // SECURITY FIX: Validate user agent binding
        boolean userAgentValid = session.getUserAgent().equals(userAgent);
        
        if (ipValid && userAgentValid) {
            // SECURITY FIX: Update last accessed time
            session.setLastAccessedAt(System.currentTimeMillis());
            return true;
        }
        
        // SECURITY FIX: Log suspicious session access
        System.err.println("SECURITY ALERT: Session validation failed - " +
                         "SessionID: " + sessionId + 
                         " Expected IP: " + session.getIpAddress() + " Actual IP: " + ipAddress +
                         " Expected UA: " + session.getUserAgent() + " Actual UA: " + userAgent +
                         " Time: " + java.time.Instant.now());
        
        return false;
    }
    
    /**
     * SECURITY FIX: Invalidate session
     */
    public void invalidateSession(String sessionId) {
        SessionInfo session = activeSessions.remove(sessionId);
        if (session != null) {
            System.out.println("SECURITY: Session invalidated - ID: " + sessionId + 
                             " User: " + session.getUsername() + 
                             " Time: " + java.time.Instant.now());
        }
    }
    
    /**
     * SECURITY FIX: Get session information
     */
    public SessionInfo getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    /**
     * SECURITY FIX: Clean up expired sessions
     */
    public void cleanupExpiredSessions(long maxInactiveTime) {
        long now = System.currentTimeMillis();
        activeSessions.entrySet().removeIf(entry -> {
            SessionInfo session = entry.getValue();
            boolean expired = (now - session.getLastAccessedAt()) > maxInactiveTime;
            if (expired) {
                System.out.println("SECURITY: Session expired - ID: " + entry.getKey() + 
                                 " User: " + session.getUsername());
            }
            return expired;
        });
    }
    
    /**
     * SECURITY FIX: Generate cryptographically secure session ID
     */
    private String generateSecureSessionId() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return UUID.nameUUIDFromBytes(randomBytes).toString();
    }
    
    /**
     * SECURITY FIX: Session information holder
     */
    public static class SessionInfo {
        private String sessionId;
        private String username;
        private String ipAddress;
        private String userAgent;
        private long createdAt;
        private long lastAccessedAt;
        
        public static SessionInfoBuilder builder() {
            return new SessionInfoBuilder();
        }
        
        // Getters and setters
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        
        public long getCreatedAt() { return createdAt; }
        public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
        
        public long getLastAccessedAt() { return lastAccessedAt; }
        public void setLastAccessedAt(long lastAccessedAt) { this.lastAccessedAt = lastAccessedAt; }
        
        public static class SessionInfoBuilder {
            private SessionInfo sessionInfo = new SessionInfo();
            
            public SessionInfoBuilder sessionId(String sessionId) {
                sessionInfo.setSessionId(sessionId);
                return this;
            }
            
            public SessionInfoBuilder username(String username) {
                sessionInfo.setUsername(username);
                return this;
            }
            
            public SessionInfoBuilder ipAddress(String ipAddress) {
                sessionInfo.setIpAddress(ipAddress);
                return this;
            }
            
            public SessionInfoBuilder userAgent(String userAgent) {
                sessionInfo.setUserAgent(userAgent);
                return this;
            }
            
            public SessionInfoBuilder createdAt(long createdAt) {
                sessionInfo.setCreatedAt(createdAt);
                return this;
            }
            
            public SessionInfoBuilder lastAccessedAt(long lastAccessedAt) {
                sessionInfo.setLastAccessedAt(lastAccessedAt);
                return this;
            }
            
            public SessionInfo build() {
                return sessionInfo;
            }
        }
    }
}
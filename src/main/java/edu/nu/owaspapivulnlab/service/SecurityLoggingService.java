package edu.nu.owaspapivulnlab.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * SECURITY FIX: Centralized security logging service with structured logging
 */
@Service
public class SecurityLoggingService {
    
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    private static final Logger errorLogger = LoggerFactory.getLogger("ERROR");
    
    /**
     * SECURITY FIX: Log authentication events
     */
    public void logAuthenticationEvent(String eventType, String username, String ipAddress, 
                                     String userAgent, boolean success, String details) {
        try {
            MDC.put("eventType", "AUTHENTICATION");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("username", sanitizeForLogging(username));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            MDC.put("userAgent", sanitizeForLogging(userAgent));
            MDC.put("success", String.valueOf(success));
            
            if (success) {
                securityLogger.info("Authentication {} - User: {} from IP: {} - {}", 
                                  eventType, username, ipAddress, details);
            } else {
                securityLogger.warn("Authentication {} FAILED - User: {} from IP: {} - {}", 
                                  eventType, username, ipAddress, details);
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Log authorization events
     */
    public void logAuthorizationEvent(String username, String resource, String action, 
                                    boolean granted, String ipAddress, String reason) {
        try {
            MDC.put("eventType", "AUTHORIZATION");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("username", sanitizeForLogging(username));
            MDC.put("resource", sanitizeForLogging(resource));
            MDC.put("action", sanitizeForLogging(action));
            MDC.put("granted", String.valueOf(granted));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            
            if (granted) {
                auditLogger.info("Authorization GRANTED - User: {} Action: {} Resource: {} from IP: {}", 
                               username, action, resource, ipAddress);
            } else {
                securityLogger.warn("Authorization DENIED - User: {} Action: {} Resource: {} from IP: {} - Reason: {}", 
                                  username, action, resource, ipAddress, reason);
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Log security violations
     */
    public void logSecurityViolation(String violationType, String username, String ipAddress, 
                                   String details, String severity) {
        try {
            MDC.put("eventType", "SECURITY_VIOLATION");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("violationType", sanitizeForLogging(violationType));
            MDC.put("username", sanitizeForLogging(username));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            MDC.put("severity", sanitizeForLogging(severity));
            
            switch (severity.toUpperCase()) {
                case "CRITICAL":
                    securityLogger.error("CRITICAL SECURITY VIOLATION - Type: {} User: {} IP: {} - {}", 
                                       violationType, username, ipAddress, details);
                    break;
                case "HIGH":
                    securityLogger.error("HIGH SECURITY VIOLATION - Type: {} User: {} IP: {} - {}", 
                                       violationType, username, ipAddress, details);
                    break;
                case "MEDIUM":
                    securityLogger.warn("MEDIUM SECURITY VIOLATION - Type: {} User: {} IP: {} - {}", 
                                      violationType, username, ipAddress, details);
                    break;
                default:
                    securityLogger.info("SECURITY VIOLATION - Type: {} User: {} IP: {} - {}", 
                                      violationType, username, ipAddress, details);
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Log rate limiting events
     */
    public void logRateLimitEvent(String username, String ipAddress, String endpoint, 
                                String limitType, long remainingAttempts) {
        try {
            MDC.put("eventType", "RATE_LIMIT");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("username", sanitizeForLogging(username));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            MDC.put("endpoint", sanitizeForLogging(endpoint));
            MDC.put("limitType", sanitizeForLogging(limitType));
            MDC.put("remainingAttempts", String.valueOf(remainingAttempts));
            
            securityLogger.warn("Rate limit exceeded - User: {} IP: {} Endpoint: {} Type: {} Remaining: {}", 
                              username, ipAddress, endpoint, limitType, remainingAttempts);
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Log application errors with security context
     */
    public void logApplicationError(String errorType, String message, Throwable throwable, 
                                  String username, String ipAddress, String requestPath) {
        try {
            MDC.put("eventType", "APPLICATION_ERROR");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("errorType", sanitizeForLogging(errorType));
            MDC.put("username", sanitizeForLogging(username));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            MDC.put("requestPath", sanitizeForLogging(requestPath));
            
            if (throwable != null) {
                errorLogger.error("Application error - Type: {} User: {} IP: {} Path: {} - {}", 
                                errorType, username, ipAddress, requestPath, message, throwable);
            } else {
                errorLogger.error("Application error - Type: {} User: {} IP: {} Path: {} - {}", 
                                errorType, username, ipAddress, requestPath, message);
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Log financial transactions for audit
     */
    public void logFinancialTransaction(String transactionType, String username, String accountId, 
                                      Double amount, Double previousBalance, Double newBalance, 
                                      String ipAddress, boolean success, String transactionId) {
        try {
            MDC.put("eventType", "FINANCIAL_TRANSACTION");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("transactionType", sanitizeForLogging(transactionType));
            MDC.put("username", sanitizeForLogging(username));
            MDC.put("accountId", sanitizeForLogging(accountId));
            MDC.put("amount", String.valueOf(amount));
            MDC.put("success", String.valueOf(success));
            MDC.put("transactionId", sanitizeForLogging(transactionId));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            
            if (success) {
                auditLogger.info("Financial transaction {} - User: {} Account: {} Amount: {} " +
                               "Previous: {} New: {} TxnID: {} IP: {}", 
                               transactionType, username, accountId, amount, 
                               previousBalance, newBalance, transactionId, ipAddress);
            } else {
                securityLogger.warn("Financial transaction {} FAILED - User: {} Account: {} " +
                                  "Amount: {} TxnID: {} IP: {}", 
                                  transactionType, username, accountId, amount, transactionId, ipAddress);
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Log admin operations for audit
     */
    public void logAdminOperation(String operation, String adminUser, String targetUser, 
                                String details, String ipAddress, boolean success) {
        try {
            MDC.put("eventType", "ADMIN_OPERATION");
            MDC.put("eventId", UUID.randomUUID().toString());
            MDC.put("timestamp", Instant.now().toString());
            MDC.put("operation", sanitizeForLogging(operation));
            MDC.put("adminUser", sanitizeForLogging(adminUser));
            MDC.put("targetUser", sanitizeForLogging(targetUser));
            MDC.put("success", String.valueOf(success));
            MDC.put("ipAddress", sanitizeForLogging(ipAddress));
            
            if (success) {
                auditLogger.info("Admin operation {} - Admin: {} Target: {} IP: {} - {}", 
                               operation, adminUser, targetUser, ipAddress, details);
            } else {
                securityLogger.warn("Admin operation {} FAILED - Admin: {} Target: {} IP: {} - {}", 
                                  operation, adminUser, targetUser, ipAddress, details);
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * SECURITY FIX: Sanitize input for logging to prevent log injection
     */
    private String sanitizeForLogging(String input) {
        if (input == null) {
            return "null";
        }
        
        // SECURITY FIX: Remove potential log injection characters
        return input.replaceAll("[\r\n\t]", "_")
                   .replaceAll("[\\p{Cntrl}]", "_")
                   .trim();
    }
}
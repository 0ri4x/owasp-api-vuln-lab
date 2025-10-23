package edu.nu.owaspapivulnlab.web.dto;

import lombok.*;

import java.time.Instant;
import java.util.Map;

/**
 * SECURITY FIX: Enhanced secure error response DTO with structured error information
 * Provides consistent error format while preventing information disclosure
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecureErrorResponse {
    
    // SECURITY FIX: Unique error ID for correlation with server logs
    private String errorId;
    
    // SECURITY FIX: Structured error code for client handling
    private String errorCode;
    
    // SECURITY FIX: User-safe error message
    private String message;
    
    // SECURITY FIX: Timestamp for error tracking
    private Instant timestamp;
    
    // SECURITY FIX: Request path for context
    private String path;
    
    // SECURITY FIX: Optional retry information for rate limiting
    private Long retryAfter;
    
    // SECURITY FIX: Optional additional details (only in development mode)
    private Map<String, Object> details;
    
    // SECURITY FIX: Exclude sensitive fields like:
    // - Stack traces (security risk)
    // - Internal error messages (information disclosure)
    // - Database errors (system information)
    // - File paths (system structure)
    // - Configuration details (security configuration)
}

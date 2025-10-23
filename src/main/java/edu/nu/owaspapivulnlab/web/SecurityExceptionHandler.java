package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.service.SecurityLoggingService;
import edu.nu.owaspapivulnlab.web.dto.SecureErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;
import java.util.UUID;

/**
 * SECURITY FIX: Enhanced security exception handler with comprehensive logging
 * Handles runtime exceptions with secure error responses and detailed logging
 */
@ControllerAdvice
public class SecurityExceptionHandler {
    
    private final SecurityLoggingService securityLoggingService;

    public SecurityExceptionHandler(SecurityLoggingService securityLoggingService) {
        this.securityLoggingService = securityLoggingService;
    }
    
    /**
     * SECURITY FIX: Handle runtime exceptions with secure logging and responses
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<SecureErrorResponse> handleRuntimeException(RuntimeException ex, HttpServletRequest request) {
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        if (ex.getMessage() != null && ex.getMessage().contains("Access denied")) {
            // SECURITY FIX: Log access denied attempts
            securityLoggingService.logAuthorizationEvent(
                username,
                request.getRequestURI(),
                request.getMethod(),
                false,
                ipAddress,
                "Access denied: " + ex.getMessage() + " | ErrorID: " + errorId
            );
            
            SecureErrorResponse error = SecureErrorResponse.builder()
                    .errorId(errorId)
                    .errorCode("ACCESS_DENIED")
                    .message("Access denied. You do not have permission to access this resource.")
                    .timestamp(Instant.now())
                    .path(request.getRequestURI())
                    .build();
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
        }
        
        // SECURITY FIX: Log other runtime exceptions
        securityLoggingService.logApplicationError(
            "RUNTIME_EXCEPTION",
            ex.getMessage(),
            ex,
            username,
            ipAddress,
            request.getRequestURI()
        );
        
        // SECURITY FIX: Generic error response for security
        SecureErrorResponse error = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode("INTERNAL_ERROR")
                .message("An internal error occurred. Please try again later.")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
    
    /**
     * SECURITY FIX: Get current authenticated username safely
     */
    private String getCurrentUsername() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return (auth != null && auth.getName() != null) ? auth.getName() : "anonymous";
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    /**
     * SECURITY FIX: Extract client IP address considering proxies
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

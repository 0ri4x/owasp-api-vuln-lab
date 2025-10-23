package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.exception.*;
import edu.nu.owaspapivulnlab.service.SecurityLoggingService;
import edu.nu.owaspapivulnlab.web.dto.SecureErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * SECURITY FIX: Global exception handler with secure error responses
 * Prevents information disclosure while maintaining proper logging
 */
@RestControllerAdvice
public class GlobalSecurityExceptionHandler {
    
    private final SecurityLoggingService securityLoggingService;
    
    @Value("${spring.profiles.active:dev}")
    private String activeProfile;
    
    public GlobalSecurityExceptionHandler(SecurityLoggingService securityLoggingService) {
        this.securityLoggingService = securityLoggingService;
    }
    
    /**
     * SECURITY FIX: Handle authentication exceptions
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<SecureErrorResponse> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Log detailed error server-side
        securityLoggingService.logSecurityViolation(
            "AUTHENTICATION_ERROR", 
            username, 
            ipAddress, 
            ex.getInternalMessage() + " | ErrorID: " + errorId,
            "HIGH"
        );
        
        // SECURITY FIX: Return sanitized error to client
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode(ex.getErrorCode())
                .message(ex.getUserMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
    
    /**
     * SECURITY FIX: Handle authorization exceptions
     */
    @ExceptionHandler({AuthorizationException.class, AccessDeniedException.class})
    public ResponseEntity<SecureErrorResponse> handleAuthorizationException(
            Exception ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Log authorization failure
        securityLoggingService.logAuthorizationEvent(
            username,
            request.getRequestURI(),
            request.getMethod(),
            false,
            ipAddress,
            ex.getMessage() + " | ErrorID: " + errorId
        );
        
        // SECURITY FIX: Generic access denied message
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode("ACCESS_DENIED")
                .message("Access denied. You do not have permission to access this resource.")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }
    
    /**
     * SECURITY FIX: Handle validation exceptions
     */
    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<SecureErrorResponse> handleValidationException(
            ValidationException ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Log validation error
        securityLoggingService.logSecurityViolation(
            "VALIDATION_ERROR",
            username,
            ipAddress,
            ex.getInternalMessage() + " | ErrorID: " + errorId,
            "MEDIUM"
        );
        
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode(ex.getErrorCode())
                .message(ex.getUserMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    /**
     * SECURITY FIX: Handle rate limit exceptions
     */
    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<SecureErrorResponse> handleRateLimitException(
            RateLimitException ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Log rate limit violation
        securityLoggingService.logRateLimitEvent(
            username,
            ipAddress,
            request.getRequestURI(),
            "RATE_LIMIT_EXCEEDED",
            ex.getRemainingAttempts()
        );
        
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode(ex.getErrorCode())
                .message(ex.getUserMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .retryAfter(ex.getRetryAfter())
                .build();
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                           .header("Retry-After", String.valueOf(ex.getRetryAfter()))
                           .body(response);
    }
    
    /**
     * SECURITY FIX: Handle Spring validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<SecureErrorResponse> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Extract validation errors safely
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }
        
        // SECURITY FIX: Log validation details server-side
        securityLoggingService.logSecurityViolation(
            "INPUT_VALIDATION_ERROR",
            username,
            ipAddress,
            "Field validation errors: " + fieldErrors + " | ErrorID: " + errorId,
            "LOW"
        );
        
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode("VALIDATION_ERROR")
                .message("Input validation failed. Please check your request data.")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .details(isDevMode() ? fieldErrors : null) // SECURITY FIX: Only show details in dev
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    /**
     * SECURITY FIX: Handle type mismatch errors
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<SecureErrorResponse> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Log type mismatch attempt
        securityLoggingService.logSecurityViolation(
            "TYPE_MISMATCH_ERROR",
            username,
            ipAddress,
            "Parameter: " + ex.getName() + " Value: " + ex.getValue() + 
            " Expected: " + ex.getRequiredType() + " | ErrorID: " + errorId,
            "LOW"
        );
        
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode("INVALID_PARAMETER")
                .message("Invalid parameter format. Please check your request.")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    /**
     * SECURITY FIX: Handle all other exceptions
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<SecureErrorResponse> handleGenericException(
            Exception ex, HttpServletRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        String username = getCurrentUsername();
        String ipAddress = getClientIpAddress(request);
        
        // SECURITY FIX: Log unexpected errors with full details server-side
        securityLoggingService.logApplicationError(
            "UNEXPECTED_ERROR",
            ex.getMessage(),
            ex,
            username,
            ipAddress,
            request.getRequestURI()
        );
        
        // SECURITY FIX: Generic error message for production
        String userMessage = isDevMode() ? 
            "An error occurred: " + ex.getMessage() : 
            "An internal error occurred. Please try again later.";
        
        SecureErrorResponse response = SecureErrorResponse.builder()
                .errorId(errorId)
                .errorCode("INTERNAL_ERROR")
                .message(userMessage)
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
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
    
    /**
     * SECURITY FIX: Check if running in development mode
     */
    private boolean isDevMode() {
        return "dev".equals(activeProfile) || "development".equals(activeProfile);
    }
}
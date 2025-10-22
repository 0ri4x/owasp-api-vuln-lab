package edu.nu.owaspapivulnlab.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class SecurityExceptionHandler {
    
    /**
     * Handle access denied exceptions with proper HTTP status codes
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleAccessDenied(RuntimeException ex) {
        Map<String, String> error = new HashMap<>();
        
        if (ex.getMessage().contains("Access denied")) {
            error.put("error", ex.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
        }
        
        // For other runtime exceptions, return generic error
        error.put("error", "An error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}

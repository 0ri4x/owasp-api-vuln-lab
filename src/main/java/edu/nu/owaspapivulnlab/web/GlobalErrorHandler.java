package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import edu.nu.owaspapivulnlab.web.dto.SecureErrorResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

// SECURE: Sanitized error responses to prevent information disclosure
@ControllerAdvice
public class GlobalErrorHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SecureErrorResponse> all(Exception e) {
        // SECURE: Log detailed error for monitoring but don't expose to client
        System.err.println("Internal error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        
        SecureErrorResponse error = SecureErrorResponse.builder()
                .errorId(java.util.UUID.randomUUID().toString())
                .errorCode("INTERNAL_SERVER_ERROR")
                .message("An unexpected error occurred. Please try again later.")
                .timestamp(java.time.Instant.now())
                .build();
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<SecureErrorResponse> db(DataAccessException e) {
        // SECURE: Log database error for monitoring but don't expose to client
        System.err.println("Database error: " + e.getMessage());
        
        SecureErrorResponse error = SecureErrorResponse.builder()
                .errorId(java.util.UUID.randomUUID().toString())
                .errorCode("DATABASE_ERROR")
                .message("A database error occurred. Please try again later.")
                .timestamp(java.time.Instant.now())
                .build();
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
    
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<SecureErrorResponse> runtime(RuntimeException e) {
        // SECURE: Handle runtime exceptions (like access denied) with appropriate status
        if (e.getMessage().contains("Access denied")) {
            SecureErrorResponse error = SecureErrorResponse.builder()
                    .errorId(java.util.UUID.randomUUID().toString())
                    .errorCode("ACCESS_DENIED")
                    .message(e.getMessage())
                    .timestamp(java.time.Instant.now())
                    .build();
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
        }
        
        // For other runtime exceptions, return generic error
        SecureErrorResponse error = SecureErrorResponse.builder()
                .errorId(java.util.UUID.randomUUID().toString())
                .errorCode("REQUEST_ERROR")
                .message("An error occurred while processing your request.")
                .timestamp(java.time.Instant.now())
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }
}

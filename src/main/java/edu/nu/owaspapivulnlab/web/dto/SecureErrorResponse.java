package edu.nu.owaspapivulnlab.web.dto;

import lombok.*;

/**
 * SECURE: Generic error response DTO to prevent information disclosure
 * Provides consistent error structure without exposing sensitive details
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecureErrorResponse {
    private String error;
    private String message;
    private String timestamp;
    
    // SECURE: Exclude detailed exception information, stack traces, and internal system details
    // Only include user-friendly error messages
}

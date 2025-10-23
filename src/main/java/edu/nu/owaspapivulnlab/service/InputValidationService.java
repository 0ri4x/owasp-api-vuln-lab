package edu.nu.owaspapivulnlab.service;

import org.springframework.stereotype.Service;
import java.util.regex.Pattern;

/**
 * SECURITY FIX: Input validation service to prevent mass assignment and injection attacks
 */
@Service
public class InputValidationService {
    
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,50}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern ROLE_PATTERN = Pattern.compile("^(USER|ADMIN|MODERATOR)$");
    
    /**
     * SECURITY FIX: Validate username format and prevent injection
     */
    public boolean isValidUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username.trim()).matches();
    }
    
    /**
     * SECURITY FIX: Validate email format
     */
    public boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }
    
    /**
     * SECURITY FIX: Validate role values to prevent privilege escalation
     */
    public boolean isValidRole(String role) {
        if (role == null || role.trim().isEmpty()) {
            return false;
        }
        return ROLE_PATTERN.matcher(role.trim().toUpperCase()).matches();
    }
    
    /**
     * SECURITY FIX: Sanitize string input to prevent injection attacks
     */
    public String sanitizeString(String input) {
        if (input == null) {
            return null;
        }
        
        return input.trim()
                   .replaceAll("[<>\"'&]", "") // Remove potential XSS characters
                   .replaceAll("\\s+", " ");   // Normalize whitespace
    }
    
    /**
     * SECURITY FIX: Check for potential mass assignment attempts in request
     */
    public boolean containsSensitiveFields(String requestBody) {
        if (requestBody == null) {
            return false;
        }
        
        String lowerBody = requestBody.toLowerCase();
        return lowerBody.contains("\"role\"") || 
               lowerBody.contains("\"isadmin\"") || 
               lowerBody.contains("\"password\"") ||
               lowerBody.contains("\"id\"");
    }
}
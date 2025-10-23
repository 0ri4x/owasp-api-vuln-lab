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
     * SECURITY FIX: Validate financial amounts with strict business rules
     */
    public boolean isValidTransferAmount(Double amount) {
        if (amount == null) {
            return false;
        }
        
        // SECURITY FIX: Reject negative amounts
        if (amount <= 0) {
            return false;
        }
        
        // SECURITY FIX: Reject excessively large amounts (max $1,000,000)
        if (amount > 1000000.0) {
            return false;
        }
        
        // SECURITY FIX: Reject amounts with more than 2 decimal places
        if (amount * 100 != Math.floor(amount * 100)) {
            return false;
        }
        
        // SECURITY FIX: Reject NaN and infinite values
        if (Double.isNaN(amount) || Double.isInfinite(amount)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * SECURITY FIX: Validate account balance with business constraints
     */
    public boolean isValidBalance(Double balance) {
        if (balance == null) {
            return false;
        }
        
        // SECURITY FIX: Allow negative balances but within reasonable limits (-$100,000)
        if (balance < -100000.0) {
            return false;
        }
        
        // SECURITY FIX: Maximum balance limit ($10,000,000)
        if (balance > 10000000.0) {
            return false;
        }
        
        // SECURITY FIX: Validate decimal precision (max 2 decimal places)
        if (balance * 100 != Math.floor(balance * 100)) {
            return false;
        }
        
        // SECURITY FIX: Reject NaN and infinite values
        if (Double.isNaN(balance) || Double.isInfinite(balance)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * SECURITY FIX: Validate numeric IDs with range constraints
     */
    public boolean isValidId(Long id) {
        if (id == null) {
            return false;
        }
        
        // SECURITY FIX: Reject negative IDs
        if (id <= 0) {
            return false;
        }
        
        // SECURITY FIX: Reject excessively large IDs (max Long.MAX_VALUE / 1000)
        if (id > Long.MAX_VALUE / 1000) {
            return false;
        }
        
        return true;
    }
    
    /**
     * SECURITY FIX: Validate page numbers and sizes for pagination
     */
    public boolean isValidPageNumber(Integer page) {
        if (page == null) {
            return false;
        }
        
        // SECURITY FIX: Page numbers start from 0
        if (page < 0) {
            return false;
        }
        
        // SECURITY FIX: Maximum page number to prevent resource exhaustion
        if (page > 10000) {
            return false;
        }
        
        return true;
    }
    
    /**
     * SECURITY FIX: Validate page size for pagination
     */
    public boolean isValidPageSize(Integer size) {
        if (size == null) {
            return false;
        }
        
        // SECURITY FIX: Minimum page size
        if (size < 1) {
            return false;
        }
        
        // SECURITY FIX: Maximum page size to prevent resource exhaustion
        if (size > 100) {
            return false;
        }
        
        return true;
    }
    
    /**
     * SECURITY FIX: Validate numeric ranges for general integers
     */
    public boolean isValidIntegerRange(Integer value, int min, int max) {
        if (value == null) {
            return false;
        }
        
        return value >= min && value <= max;
    }
    
    /**
     * SECURITY FIX: Validate numeric ranges for general doubles
     */
    public boolean isValidDoubleRange(Double value, double min, double max) {
        if (value == null) {
            return false;
        }
        
        // SECURITY FIX: Reject NaN and infinite values
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            return false;
        }
        
        return value >= min && value <= max;
    }
    
    /**
     * SECURITY FIX: Validate string length with strict limits
     */
    public boolean isValidStringLength(String value, int minLength, int maxLength) {
        if (value == null) {
            return minLength == 0;
        }
        
        int length = value.trim().length();
        return length >= minLength && length <= maxLength;
    }
    
    /**
     * SECURITY FIX: Validate IBAN format (basic validation)
     */
    public boolean isValidIban(String iban) {
        if (iban == null || iban.trim().isEmpty()) {
            return false;
        }
        
        String cleanIban = iban.replaceAll("\\s", "").toUpperCase();
        
        // SECURITY FIX: Basic IBAN length validation (15-34 characters)
        if (cleanIban.length() < 15 || cleanIban.length() > 34) {
            return false;
        }
        
        // SECURITY FIX: IBAN should start with 2 letters followed by 2 digits
        if (!cleanIban.matches("^[A-Z]{2}[0-9]{2}[A-Z0-9]+$")) {
            return false;
        }
        
        return true;
    }
    
    /**
     * SECURITY FIX: Validate search query parameters
     */
    public boolean isValidSearchQuery(String query) {
        if (query == null || query.trim().isEmpty()) {
            return false;
        }
        
        String trimmedQuery = query.trim();
        
        // SECURITY FIX: Minimum search length
        if (trimmedQuery.length() < 2) {
            return false;
        }
        
        // SECURITY FIX: Maximum search length to prevent DoS
        if (trimmedQuery.length() > 100) {
            return false;
        }
        
        // SECURITY FIX: Reject queries with only special characters
        if (trimmedQuery.matches("^[^a-zA-Z0-9]+$")) {
            return false;
        }
        
        // SECURITY FIX: Reject potential SQL injection patterns
        String lowerQuery = trimmedQuery.toLowerCase();
        String[] sqlKeywords = {"select", "insert", "update", "delete", "drop", "union", "script", "javascript"};
        for (String keyword : sqlKeywords) {
            if (lowerQuery.contains(keyword)) {
                return false;
            }
        }
        
        return true;
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
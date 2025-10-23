package edu.nu.owaspapivulnlab.exception;

/**
 * SECURITY FIX: Input validation exception
 */
public class ValidationException extends SecurityException {
    
    public ValidationException(String userMessage, String internalMessage) {
        super("VALIDATION_ERROR", userMessage, internalMessage);
    }
    
    public ValidationException(String userMessage, String internalMessage, Throwable cause) {
        super("VALIDATION_ERROR", userMessage, internalMessage, cause);
    }
}
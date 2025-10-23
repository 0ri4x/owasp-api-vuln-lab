package edu.nu.owaspapivulnlab.exception;

/**
 * SECURITY FIX: Authentication-specific exception
 */
public class AuthenticationException extends SecurityException {
    
    public AuthenticationException(String userMessage, String internalMessage) {
        super("AUTH_ERROR", userMessage, internalMessage);
    }
    
    public AuthenticationException(String userMessage, String internalMessage, Throwable cause) {
        super("AUTH_ERROR", userMessage, internalMessage, cause);
    }
}
package edu.nu.owaspapivulnlab.exception;

/**
 * SECURITY FIX: Authorization-specific exception
 */
public class AuthorizationException extends SecurityException {
    
    public AuthorizationException(String userMessage, String internalMessage) {
        super("AUTHZ_ERROR", userMessage, internalMessage);
    }
    
    public AuthorizationException(String userMessage, String internalMessage, Throwable cause) {
        super("AUTHZ_ERROR", userMessage, internalMessage, cause);
    }
}
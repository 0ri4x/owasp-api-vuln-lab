package edu.nu.owaspapivulnlab.exception;

/**
 * SECURITY FIX: Base security exception for consistent error handling
 */
public class SecurityException extends RuntimeException {
    
    private final String errorCode;
    private final String userMessage;
    private final String internalMessage;
    
    public SecurityException(String errorCode, String userMessage, String internalMessage) {
        super(internalMessage);
        this.errorCode = errorCode;
        this.userMessage = userMessage;
        this.internalMessage = internalMessage;
    }
    
    public SecurityException(String errorCode, String userMessage, String internalMessage, Throwable cause) {
        super(internalMessage, cause);
        this.errorCode = errorCode;
        this.userMessage = userMessage;
        this.internalMessage = internalMessage;
    }
    
    public String getErrorCode() {
        return errorCode;
    }
    
    public String getUserMessage() {
        return userMessage;
    }
    
    public String getInternalMessage() {
        return internalMessage;
    }
}
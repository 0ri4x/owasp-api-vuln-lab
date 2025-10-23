package edu.nu.owaspapivulnlab.exception;

/**
 * SECURITY FIX: Rate limiting exception
 */
public class RateLimitException extends SecurityException {
    
    private final long retryAfter;
    private final long remainingAttempts;
    
    public RateLimitException(String userMessage, String internalMessage, long retryAfter, long remainingAttempts) {
        super("RATE_LIMIT_ERROR", userMessage, internalMessage);
        this.retryAfter = retryAfter;
        this.remainingAttempts = remainingAttempts;
    }
    
    public long getRetryAfter() {
        return retryAfter;
    }
    
    public long getRemainingAttempts() {
        return remainingAttempts;
    }
}
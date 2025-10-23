package edu.nu.owaspapivulnlab.service;

import edu.nu.owaspapivulnlab.config.RateLimitConfig;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

/**
 * SECURITY FIX: Rate limiting service to prevent brute-force and DoS attacks
 */
@Service
public class RateLimitService {

    private final RateLimitConfig rateLimitConfig;

    public RateLimitService(RateLimitConfig rateLimitConfig) {
        this.rateLimitConfig = rateLimitConfig;
    }

    /**
     * SECURITY FIX: Check rate limit for authentication endpoints
     * @param request HTTP request to extract client identifier
     * @return true if request is allowed, false if rate limited
     */
    public boolean isAuthAllowed(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getAuthBucket(key);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return probe.isConsumed();
    }

    /**
     * SECURITY FIX: Check rate limit for financial operations
     * @param request HTTP request to extract client identifier
     * @return true if request is allowed, false if rate limited
     */
    public boolean isFinancialAllowed(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getFinancialBucket(key);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return probe.isConsumed();
    }

    /**
     * SECURITY FIX: Check rate limit for data access endpoints
     * @param request HTTP request to extract client identifier
     * @return true if request is allowed, false if rate limited
     */
    public boolean isDataAccessAllowed(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getDataAccessBucket(key);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return probe.isConsumed();
    }

    /**
     * SECURITY FIX: Check rate limit for admin operations
     * @param request HTTP request to extract client identifier
     * @return true if request is allowed, false if rate limited
     */
    public boolean isAdminAllowed(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getAdminBucket(key);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return probe.isConsumed();
    }

    /**
     * SECURITY FIX: Check rate limit for general API endpoints
     * @param request HTTP request to extract client identifier
     * @return true if request is allowed, false if rate limited
     */
    public boolean isGeneralAllowed(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getGeneralBucket(key);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return probe.isConsumed();
    }

    /**
     * SECURITY FIX: Get remaining tokens for authentication bucket
     */
    public long getAuthRemainingTokens(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getAuthBucket(key);
        return bucket.getAvailableTokens();
    }

    /**
     * SECURITY FIX: Get remaining tokens for financial bucket
     */
    public long getFinancialRemainingTokens(HttpServletRequest request) {
        String key = getClientKey(request);
        Bucket bucket = rateLimitConfig.getFinancialBucket(key);
        return bucket.getAvailableTokens();
    }

    /**
     * SECURITY FIX: Extract client identifier from request
     * Uses IP address as primary identifier, with X-Forwarded-For support
     */
    private String getClientKey(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // Take the first IP in the chain
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}
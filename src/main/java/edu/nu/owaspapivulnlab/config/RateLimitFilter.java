package edu.nu.owaspapivulnlab.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.service.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * SECURITY FIX: Rate limiting filter to prevent brute-force and DoS attacks
 * Applied globally to all API endpoints with different limits per endpoint type
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        // SECURITY FIX: Apply different rate limits based on endpoint sensitivity
        boolean allowed = true;
        String limitType = "general";
        
        if (isAuthEndpoint(path, method)) {
            allowed = rateLimitService.isAuthAllowed(request);
            limitType = "authentication";
        } else if (isFinancialEndpoint(path, method)) {
            allowed = rateLimitService.isFinancialAllowed(request);
            limitType = "financial";
        } else if (isAdminEndpoint(path)) {
            allowed = rateLimitService.isAdminAllowed(request);
            limitType = "admin";
        } else if (isDataAccessEndpoint(path, method)) {
            allowed = rateLimitService.isDataAccessAllowed(request);
            limitType = "data access";
        } else if (path.startsWith("/api/")) {
            allowed = rateLimitService.isGeneralAllowed(request);
        }
        
        if (!allowed) {
            sendRateLimitResponse(response, limitType);
            return;
        }
        
        filterChain.doFilter(request, response);
    }   
 /**
     * SECURITY FIX: Check if endpoint is authentication-related (most sensitive)
     */
    private boolean isAuthEndpoint(String path, String method) {
        return ("POST".equals(method) && 
                (path.equals("/api/auth/login") || path.equals("/api/auth/signup")));
    }
    
    /**
     * SECURITY FIX: Check if endpoint is financial-related (highly sensitive)
     */
    private boolean isFinancialEndpoint(String path, String method) {
        return (path.startsWith("/api/accounts/") && 
                (path.contains("/transfer") || path.contains("/balance")));
    }
    
    /**
     * SECURITY FIX: Check if endpoint is admin-related (sensitive)
     */
    private boolean isAdminEndpoint(String path) {
        return path.startsWith("/api/admin/");
    }
    
    /**
     * SECURITY FIX: Check if endpoint is data access-related (moderate sensitivity)
     */
    private boolean isDataAccessEndpoint(String path, String method) {
        return (path.startsWith("/api/users/") && 
                (path.contains("/search") || "GET".equals(method)));
    }
    
    /**
     * SECURITY FIX: Send rate limit exceeded response with proper headers
     */
    private void sendRateLimitResponse(HttpServletResponse response, String limitType) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("X-RateLimit-Limit-Type", limitType);
        response.setHeader("Retry-After", "60"); // Suggest retry after 60 seconds
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Rate limit exceeded");
        errorResponse.put("message", "Too many requests for " + limitType + " operations. Please try again later.");
        errorResponse.put("type", "RATE_LIMIT_EXCEEDED");
        errorResponse.put("retryAfter", 60);
        
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
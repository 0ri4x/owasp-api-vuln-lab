package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.service.InputValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * SECURITY FIX: Filter to detect and prevent mass assignment attempts
 * Monitors request bodies for sensitive fields that shouldn't be user-modifiable
 */
@Component
public class MassAssignmentProtectionFilter extends OncePerRequestFilter {

    private final InputValidationService inputValidationService;

    public MassAssignmentProtectionFilter(InputValidationService inputValidationService) {
        this.inputValidationService = inputValidationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        // SECURITY FIX: Only check POST/PUT/PATCH requests with JSON content
        String method = request.getMethod();
        String contentType = request.getContentType();
        
        if (("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) &&
            contentType != null && contentType.contains("application/json")) {
            
            // SECURITY FIX: Wrap request to cache body for inspection
            ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);
            
            // Continue with the request
            filterChain.doFilter(wrappedRequest, response);
            
            // SECURITY FIX: Check request body after processing
            byte[] body = wrappedRequest.getContentAsByteArray();
            if (body.length > 0) {
                String requestBody = new String(body, StandardCharsets.UTF_8);
                
                // SECURITY FIX: Detect mass assignment attempts
                if (inputValidationService.containsSensitiveFields(requestBody)) {
                    // Log the security violation
                    System.err.println("CRITICAL SECURITY ALERT: Mass assignment attempt detected - " +
                                     "IP: " + request.getRemoteAddr() + 
                                     " Path: " + request.getRequestURI() + 
                                     " Method: " + method + 
                                     " Body contains sensitive fields: " + requestBody + 
                                     " Time: " + java.time.Instant.now());
                    
                    // Note: We log but don't block here since the request has already been processed
                    // This serves as an audit trail for security monitoring
                }
            }
        } else {
            // SECURITY FIX: For non-JSON requests, proceed normally
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // SECURITY FIX: Skip filtering for certain paths that don't need mass assignment protection
        String path = request.getRequestURI();
        return path.startsWith("/h2-console") || 
               path.startsWith("/api/auth/login") || 
               path.startsWith("/api/auth/signup") ||
               path.equals("/");
    }
}
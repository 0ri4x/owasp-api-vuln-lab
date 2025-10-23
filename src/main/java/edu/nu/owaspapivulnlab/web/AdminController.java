package edu.nu.owaspapivulnlab.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import edu.nu.owaspapivulnlab.service.RateLimitService;
import edu.nu.owaspapivulnlab.web.dto.AdminMetricsDTO;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final RateLimitService rateLimitService;

    public AdminController(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    // SECURITY FIX: Enhanced admin metrics endpoint with admin rate limiting
    @GetMapping("/metrics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> metrics(Authentication auth, HttpServletRequest request) {
        // SECURITY FIX: Admin rate limiting for system metrics access
        if (!rateLimitService.isAdminAllowed(request)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many admin requests. Please try again later.");
            
            // SECURITY FIX: Log suspicious admin activity
            System.err.println("SECURITY ALERT: Rate limit exceeded for admin metrics from IP: " + 
                             request.getRemoteAddr() + " by admin: " + auth.getName() + 
                             " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        
        // SECURITY FIX: Log admin metrics access for audit trail
        System.out.println("INFO: Admin metrics accessed by: " + auth.getName() + 
                         " from IP: " + request.getRemoteAddr() + " at " + java.time.Instant.now());
        
        // SECURE: Return sanitized metrics without exposing sensitive system details
        AdminMetricsDTO metrics = AdminMetricsDTO.builder()
                .uptimeHours(rt.getUptime() / (1000 * 60 * 60)) // Convert to hours, not milliseconds
                .activeThreads(ManagementFactory.getThreadMXBean().getThreadCount())
                .status("operational")
                .build();
        
        Map<String, Object> response = new HashMap<>();
        response.put("metrics", metrics);
        response.put("accessedBy", auth.getName());
        response.put("timestamp", java.time.Instant.now());
        
        return ResponseEntity.ok(response);
    }
}

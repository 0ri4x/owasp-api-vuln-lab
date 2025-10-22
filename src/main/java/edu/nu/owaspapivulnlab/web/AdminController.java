package edu.nu.owaspapivulnlab.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import edu.nu.owaspapivulnlab.web.dto.AdminMetricsDTO;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // SECURE: Admin-only metrics endpoint with sanitized system information
    @GetMapping("/metrics")
    @PreAuthorize("hasRole('ADMIN')")
    public AdminMetricsDTO metrics() {
        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        
        // SECURE: Return sanitized metrics without exposing sensitive system details
        return AdminMetricsDTO.builder()
                .uptimeHours(rt.getUptime() / (1000 * 60 * 60)) // Convert to hours, not milliseconds
                .activeThreads(ManagementFactory.getThreadMXBean().getThreadCount())
                .status("operational")
                .build();
    }
}

package edu.nu.owaspapivulnlab.web.dto;

import lombok.*;

/**
 * SECURE: Admin metrics DTO with sanitized system information
 * Excludes sensitive system details like Java version, exact uptime, etc.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminMetricsDTO {
    private Long uptimeHours;        // SECURE: Hours instead of milliseconds
    private Integer activeThreads;    // SECURE: Thread count for load monitoring
    private String status;            // SECURE: Generic status instead of detailed system info
    
    // SECURE: Exclude sensitive fields like:
    // - Java version (reveals potential vulnerabilities)
    // - Exact uptime in milliseconds (reveals restart patterns)
    // - System properties (may contain sensitive configuration)
    // - Memory details (may reveal system architecture)
}

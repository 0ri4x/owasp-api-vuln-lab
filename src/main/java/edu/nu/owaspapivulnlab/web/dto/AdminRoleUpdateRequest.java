package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;

/**
 * SECURITY FIX: Admin-only DTO for role and privilege management
 * Separated from regular user operations to prevent privilege escalation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminRoleUpdateRequest {
    
    @NotNull(message = "User ID is required")
    private Long userId;
    
    @NotBlank(message = "Role is required")
    @Pattern(regexp = "^(USER|ADMIN|MODERATOR)$", message = "Role must be USER, ADMIN, or MODERATOR")
    private String role;
    
    @NotNull(message = "Admin status is required")
    private Boolean isAdmin;
    
    // SECURITY NOTE: This DTO is exclusively for administrative operations
    // and should only be accessible by users with ADMIN role
}
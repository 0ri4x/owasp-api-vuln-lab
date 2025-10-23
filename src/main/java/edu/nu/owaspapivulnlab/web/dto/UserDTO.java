package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * SECURITY FIX: Secure UserDTO with sensitive fields removed
 * This DTO is now safe for general user operations and responses
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {
    private Long id;
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @Email(message = "Email must be valid")
    private String email;
    
    // SECURITY FIX: Removed sensitive fields to prevent mass assignment
    // - role: Moved to AdminUserDTO for admin-only access
    // - isAdmin: Moved to AdminUserDTO for admin-only access
    
    // Note: Password field is intentionally excluded to prevent exposure
    // Password handling is done separately in AuthController
    
    /**
     * SECURITY NOTE: Sensitive fields have been moved to:
     * - AdminUserDTO: For administrative operations (includes role, isAdmin)
     * - PublicUserDTO: For public user information (excludes sensitive data)
     */
}

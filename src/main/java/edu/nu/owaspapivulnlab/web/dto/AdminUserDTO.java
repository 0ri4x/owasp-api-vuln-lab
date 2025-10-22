package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * SECURE: Admin user DTO that includes administrative fields
 * Used only by administrators for user management
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminUserDTO {
    private Long id;
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @Email(message = "Email must be valid")
    private String email;
    
    // SECURE: Include administrative fields for admin use only
    private String role;
    private boolean isAdmin;
    
    // Note: Password field is intentionally excluded to prevent exposure
    // Password handling is done separately in AuthController
}

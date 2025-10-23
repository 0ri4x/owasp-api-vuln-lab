package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * SECURITY FIX: Secure DTO for user creation that excludes sensitive fields
 * Prevents mass assignment vulnerabilities by only allowing safe fields
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateUserRequest {
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @Email(message = "Email must be valid")
    @NotBlank(message = "Email is required")
    private String email;
    
    // SECURITY FIX: Explicitly exclude sensitive fields to prevent mass assignment:
    // - role (should only be set by administrators)
    // - isAdmin (should only be set by administrators) 
    // - password (handled separately through authentication endpoints)
    // - id (auto-generated)
}
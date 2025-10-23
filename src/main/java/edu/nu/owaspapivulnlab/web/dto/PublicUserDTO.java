package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * SECURE: Public user DTO that excludes sensitive administrative fields
 * Used for regular users viewing other users' profiles
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PublicUserDTO {
    private Long id;
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @Email(message = "Email must be valid")
    private String email;
    
    // SECURE: Exclude role and isAdmin fields for public consumption
    // These fields are only visible to admins or the user themselves
}

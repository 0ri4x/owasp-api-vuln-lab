package edu.nu.owaspapivulnlab.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.*;

/**
 * SECURE: Account DTO for proper account data exposure control
 * Excludes sensitive internal fields like ownerUserId
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountDTO {
    private Long id;
    
    @NotBlank(message = "IBAN is required")
    private String iban;
    
    @NotNull(message = "Balance is required")
    @PositiveOrZero(message = "Balance must be non-negative")
    private Double balance;
    
    // SECURE: Exclude ownerUserId field to prevent user enumeration
    // Ownership validation is handled at the controller level
}

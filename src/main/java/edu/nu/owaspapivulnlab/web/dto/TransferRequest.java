package edu.nu.owaspapivulnlab.web.dto;

import edu.nu.owaspapivulnlab.validation.ValidTransferAmount;
import jakarta.validation.constraints.*;
import lombok.*;

import java.math.BigDecimal;

/**
 * SECURITY FIX: Secure transfer request DTO with comprehensive validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TransferRequest {
    
    @NotNull(message = "Transfer amount is required")
    @ValidTransferAmount(min = 0.01, max = 1000000.0)
    private BigDecimal amount;
    
    @NotBlank(message = "Destination account is required")
    @Size(min = 15, max = 34, message = "Destination account must be a valid IBAN (15-34 characters)")
    @Pattern(regexp = "^[A-Z]{2}[0-9]{2}[A-Z0-9]+$", message = "Invalid IBAN format")
    private String destinationAccount;
    
    @Size(max = 500, message = "Transfer description cannot exceed 500 characters")
    @Pattern(regexp = "^[a-zA-Z0-9\\s.,!?-]*$", message = "Transfer description contains invalid characters")
    private String description;
    
    @NotBlank(message = "Transfer type is required")
    @Pattern(regexp = "^(INTERNAL|EXTERNAL|WIRE)$", message = "Transfer type must be INTERNAL, EXTERNAL, or WIRE")
    private String transferType;
    
    // SECURITY FIX: Exclude sensitive fields that should not be user-modifiable:
    // - accountId (determined from authentication context)
    // - transactionId (generated server-side)
    // - timestamp (set server-side)
    // - fees (calculated server-side)
}
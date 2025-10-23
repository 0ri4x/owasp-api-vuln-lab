package edu.nu.owaspapivulnlab.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * SECURITY FIX: Custom validation annotation for transfer amounts
 */
@Documented
@Constraint(validatedBy = TransferAmountValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidTransferAmount {
    
    String message() default "Invalid transfer amount. Must be positive, not exceed $1,000,000, and have at most 2 decimal places.";
    
    Class<?>[] groups() default {};
    
    Class<? extends Payload>[] payload() default {};
    
    double min() default 0.01;
    
    double max() default 1000000.0;
}
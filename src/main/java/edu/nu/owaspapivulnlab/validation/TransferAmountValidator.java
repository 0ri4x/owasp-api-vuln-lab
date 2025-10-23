package edu.nu.owaspapivulnlab.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.math.BigDecimal;

/**
 * SECURITY FIX: Custom validator for transfer amounts with business rules
 */
public class TransferAmountValidator implements ConstraintValidator<ValidTransferAmount, BigDecimal> {
    
    private double min;
    private double max;
    
    @Override
    public void initialize(ValidTransferAmount constraintAnnotation) {
        this.min = constraintAnnotation.min();
        this.max = constraintAnnotation.max();
    }
    
    @Override
    public boolean isValid(BigDecimal value, ConstraintValidatorContext context) {
        if (value == null) {
            return false;
        }
        
        double doubleValue = value.doubleValue();
        
        // SECURITY FIX: Reject negative or zero amounts
        if (doubleValue < min) {
            addConstraintViolation(context, "Transfer amount must be at least $" + min);
            return false;
        }
        
        // SECURITY FIX: Reject excessively large amounts
        if (doubleValue > max) {
            addConstraintViolation(context, "Transfer amount cannot exceed $" + max);
            return false;
        }
        
        // SECURITY FIX: Reject amounts with more than 2 decimal places
        if (value.scale() > 2) {
            addConstraintViolation(context, "Transfer amount cannot have more than 2 decimal places");
            return false;
        }
        
        // SECURITY FIX: Reject NaN and infinite values
        if (Double.isNaN(doubleValue) || Double.isInfinite(doubleValue)) {
            addConstraintViolation(context, "Transfer amount must be a valid number");
            return false;
        }
        
        return true;
    }
    
    private void addConstraintViolation(ConstraintValidatorContext context, String message) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    }
}
package edu.nu.owaspapivulnlab.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.UserService;
import edu.nu.owaspapivulnlab.service.AccountService;
import edu.nu.owaspapivulnlab.service.RateLimitService;
import edu.nu.owaspapivulnlab.service.InputValidationService;
import edu.nu.owaspapivulnlab.service.SecurityLoggingService;
import edu.nu.owaspapivulnlab.web.dto.AccountDTO;
import edu.nu.owaspapivulnlab.web.dto.TransferRequest;
import edu.nu.owaspapivulnlab.exception.ValidationException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final UserService userService;
    private final AccountService accountService;
    private final RateLimitService rateLimitService;
    private final InputValidationService inputValidationService;
    private final SecurityLoggingService securityLoggingService;

    public AccountController(AccountRepository accounts, AppUserRepository users, UserService userService, 
                           AccountService accountService, RateLimitService rateLimitService,
                           InputValidationService inputValidationService, SecurityLoggingService securityLoggingService) {
        this.accounts = accounts;
        this.users = users;
        this.userService = userService;
        this.accountService = accountService;
        this.rateLimitService = rateLimitService;
        this.inputValidationService = inputValidationService;
        this.securityLoggingService = securityLoggingService;
    }

    // SECURITY FIX: Enhanced balance endpoint with comprehensive input validation
    @GetMapping("/{id}/balance")
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserIdByUsername(authentication.name) == @accountService.getAccountOwnerId(#id)")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth, HttpServletRequest request) {
        
        // SECURITY FIX: Validate account ID parameter
        if (!inputValidationService.isValidId(id)) {
            securityLoggingService.logSecurityViolation(
                "INVALID_ACCOUNT_ID",
                auth.getName(),
                getClientIpAddress(request),
                "Invalid account ID: " + id,
                "MEDIUM"
            );
            
            throw new ValidationException(
                "Invalid account ID format",
                "Account ID validation failed: " + id + " from user: " + auth.getName()
            );
        }
        // SECURITY FIX: Financial rate limiting for balance checks
        if (!rateLimitService.isFinancialAllowed(request)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many balance requests. Please try again later.");
            error.put("remainingAttempts", rateLimitService.getFinancialRemainingTokens(request));
            
            // SECURITY FIX: Log suspicious financial activity
            System.err.println("SECURITY ALERT: Rate limit exceeded for balance check from IP: " + 
                             request.getRemoteAddr() + " for account: " + id + " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURE: Double-check ownership validation in method body
        if (!validateAccountOwnership(id, auth)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied: You can only access your own accounts");
            
            // SECURITY FIX: Log unauthorized access attempts
            System.err.println("SECURITY ALERT: Unauthorized balance access attempt by user: " + 
                             auth.getName() + " for account: " + id + " from IP: " + request.getRemoteAddr());
            
            return ResponseEntity.status(403).body(error);
        }
        
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        
        // SECURITY FIX: Log balance access for audit trail
        System.out.println("INFO: Balance accessed for account: " + id + " by user: " + 
                         auth.getName() + " from IP: " + request.getRemoteAddr());
        
        Map<String, Object> response = new HashMap<>();
        response.put("accountId", id);
        response.put("balance", a.getBalance());
        response.put("timestamp", java.time.Instant.now());
        
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Enhanced transfer endpoint with comprehensive validation
    @PostMapping("/{id}/transfer")
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserIdByUsername(authentication.name) == @accountService.getAccountOwnerId(#id)")
    public ResponseEntity<?> transfer(@PathVariable Long id, @Valid @RequestBody TransferRequest transferRequest, 
                                    Authentication auth, HttpServletRequest request) {
        
        // SECURITY FIX: Validate account ID parameter
        if (!inputValidationService.isValidId(id)) {
            securityLoggingService.logSecurityViolation(
                "INVALID_ACCOUNT_ID",
                auth.getName(),
                getClientIpAddress(request),
                "Invalid account ID for transfer: " + id,
                "HIGH"
            );
            
            throw new ValidationException(
                "Invalid account ID format",
                "Account ID validation failed for transfer: " + id + " from user: " + auth.getName()
            );
        }
        
        // SECURITY FIX: Convert BigDecimal to Double for legacy compatibility
        Double amount = transferRequest.getAmount().doubleValue();
        // SECURITY FIX: Strict financial rate limiting for transfers
        if (!rateLimitService.isFinancialAllowed(request)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many transfer requests. Financial operations are strictly limited for security.");
            error.put("remainingAttempts", rateLimitService.getFinancialRemainingTokens(request));
            
            // SECURITY FIX: Log suspicious transfer activity - HIGH PRIORITY ALERT
            System.err.println("CRITICAL SECURITY ALERT: Rate limit exceeded for transfer from IP: " + 
                             request.getRemoteAddr() + " for account: " + id + " amount: " + amount + 
                             " by user: " + auth.getName() + " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Comprehensive financial amount validation
        if (!inputValidationService.isValidTransferAmount(amount)) {
            securityLoggingService.logSecurityViolation(
                "INVALID_TRANSFER_AMOUNT",
                auth.getName(),
                getClientIpAddress(request),
                "Invalid transfer amount: " + amount + " for account: " + id,
                "HIGH"
            );
            
            throw new ValidationException(
                "Invalid transfer amount. Amount must be positive, not exceed $1,000,000, and have at most 2 decimal places.",
                "Transfer amount validation failed: " + amount + " from user: " + auth.getName()
            );
        }
        
        // SECURITY FIX: Validate destination account IBAN
        if (!inputValidationService.isValidIban(transferRequest.getDestinationAccount())) {
            securityLoggingService.logSecurityViolation(
                "INVALID_DESTINATION_IBAN",
                auth.getName(),
                getClientIpAddress(request),
                "Invalid destination IBAN: " + transferRequest.getDestinationAccount(),
                "MEDIUM"
            );
            
            throw new ValidationException(
                "Invalid destination account format",
                "IBAN validation failed: " + transferRequest.getDestinationAccount() + " from user: " + auth.getName()
            );
        }
        
        // SECURITY FIX: Validate transfer description if provided
        if (transferRequest.getDescription() != null && 
            !inputValidationService.isValidStringLength(transferRequest.getDescription(), 0, 500)) {
            
            throw new ValidationException(
                "Transfer description is too long (maximum 500 characters)",
                "Description length validation failed from user: " + auth.getName()
            );
        }
        
        // SECURE: Double-check ownership validation in method body
        if (!validateAccountOwnership(id, auth)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied: You can only transfer from your own accounts");
            
            // SECURITY FIX: Log unauthorized transfer attempts - CRITICAL
            System.err.println("CRITICAL SECURITY ALERT: Unauthorized transfer attempt by user: " + 
                             auth.getName() + " for account: " + id + " amount: " + amount + 
                             " from IP: " + request.getRemoteAddr());
            
            return ResponseEntity.status(403).body(error);
        }
        
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        
        // SECURITY FIX: Check sufficient balance
        if (a.getBalance() < amount) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Insufficient balance for transfer");
            return ResponseEntity.status(400).body(error);
        }
        
        double previousBalance = a.getBalance();
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);
        
        // SECURITY FIX: Log financial transaction using security logging service
        securityLoggingService.logFinancialTransaction(
            transferRequest.getTransferType(),
            auth.getName(),
            id.toString(),
            amount,
            previousBalance,
            a.getBalance(),
            getClientIpAddress(request),
            true,
            transactionId
        );
        
        // SECURITY FIX: Generate secure transaction ID
        String transactionId = java.util.UUID.randomUUID().toString();
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("transactionId", transactionId);
        response.put("amount", amount);
        response.put("destinationAccount", inputValidationService.sanitizeString(transferRequest.getDestinationAccount()));
        response.put("transferType", transferRequest.getTransferType());
        response.put("description", inputValidationService.sanitizeString(transferRequest.getDescription()));
        response.put("remainingBalance", a.getBalance());
        response.put("timestamp", java.time.Instant.now());
        
        return ResponseEntity.ok(response);
    }

    // SECURE: Require authentication to view own accounts with proper DTOs
    @GetMapping("/mine")
    public List<AccountDTO> mine(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return Collections.emptyList();
        }
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return Collections.emptyList();
        }
        
        // SECURE: Return AccountDTOs instead of raw Account entities
        return accounts.findByOwnerUserId(me.getId()).stream()
                .map(this::convertToDTO)
                .collect(java.util.stream.Collectors.toList());
    }
    
    /**
     * SECURE: Validate that the authenticated user owns the specified account
     * @param accountId the account ID to check
     * @param auth the authentication context
     * @return true if user owns the account or is admin, false otherwise
     */
    private boolean validateAccountOwnership(Long accountId, Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return false;
        }
        
        // Check if user is admin
        if (auth.getAuthorities().stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))) {
            return true;
        }
        
        // Get current user's ID
        Long currentUserId = userService.getUserIdByUsername(auth.getName());
        if (currentUserId == null) {
            return false;
        }
        
        // Get account owner ID
        Long accountOwnerId = accountService.getAccountOwnerId(accountId);
        if (accountOwnerId == null) {
            return false;
        }
        
        // Check ownership
        return currentUserId.equals(accountOwnerId);
    }
    
    /**
     * SECURE: Convert Account to AccountDTO to prevent sensitive field exposure
     */
    private AccountDTO convertToDTO(Account account) {
        return AccountDTO.builder()
                .id(account.getId())
                .iban(account.getIban())
                .balance(account.getBalance())
                .build();
    }
    
    /**
     * SECURITY FIX: Extract client IP address considering proxies
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}

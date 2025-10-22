package edu.nu.owaspapivulnlab.web;

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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final UserService userService;
    private final AccountService accountService;

    public AccountController(AccountRepository accounts, AppUserRepository users, UserService userService, AccountService accountService) {
        this.accounts = accounts;
        this.users = users;
        this.userService = userService;
        this.accountService = accountService;
    }

    // SECURE: Require authentication and ownership validation
    @GetMapping("/{id}/balance")
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserIdByUsername(authentication.name) == @accountService.getAccountOwnerId(#id)")
    public Double balance(@PathVariable Long id, Authentication auth) {
        // SECURE: Double-check ownership validation in method body
        if (!validateAccountOwnership(id, auth)) {
            throw new RuntimeException("Access denied: You can only access your own accounts");
        }
        
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        return a.getBalance();
    }

    // SECURE: Require authentication and ownership validation for transfers
    @PostMapping("/{id}/transfer")
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserIdByUsername(authentication.name) == @accountService.getAccountOwnerId(#id)")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        // SECURE: Double-check ownership validation in method body
        if (!validateAccountOwnership(id, auth)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied: You can only transfer from your own accounts");
            return ResponseEntity.status(403).body(error);
        }
        
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // SECURE: Require authentication to view own accounts
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return Collections.emptyList();
        }
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
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
}

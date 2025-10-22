package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // SECURE: Require authentication and ownership validation
    @GetMapping("/{id}/balance")
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserIdByUsername(authentication.name) == @accountService.getAccountOwnerId(#id)")
    public Double balance(@PathVariable Long id) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        return a.getBalance();
    }

    // SECURE: Require authentication and ownership validation for transfers
    @PostMapping("/{id}/transfer")
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserIdByUsername(authentication.name) == @accountService.getAccountOwnerId(#id)")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount) {
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
}

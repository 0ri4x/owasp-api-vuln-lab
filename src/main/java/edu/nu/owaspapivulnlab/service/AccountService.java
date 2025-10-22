package edu.nu.owaspapivulnlab.service;

import edu.nu.owaspapivulnlab.repo.AccountRepository;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    
    private final AccountRepository accountRepository;
    
    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }
    
    /**
     * Get the owner user ID for an account
     * @param accountId the account ID
     * @return the owner user ID
     */
    public Long getAccountOwnerId(Long accountId) {
        return accountRepository.findById(accountId)
                .map(account -> account.getOwnerUserId())
                .orElse(null);
    }
}

package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.PasswordService;

@Configuration
public class DataSeeder {
    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordService passwordService) {
        return args -> {
            if (users.count() == 0) {
                // SECURE: Hash passwords before storing in database
                AppUser u1 = users.save(AppUser.builder()
                        .username("alice")
                        .password(passwordService.hashPassword("alice123")) // SECURE: Hash password
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false)
                        .build());
                
                AppUser u2 = users.save(AppUser.builder()
                        .username("bob")
                        .password(passwordService.hashPassword("bob123")) // SECURE: Hash password
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true)
                        .build());
                
                accounts.save(Account.builder().ownerUserId(u1.getId()).iban("PK00-ALICE").balance(1000.0).build());
                accounts.save(Account.builder().ownerUserId(u2.getId()).iban("PK00-BOB").balance(5000.0).build());
            }
        };
    }
}

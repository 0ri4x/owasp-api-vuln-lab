package edu.nu.owaspapivulnlab.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {
    
    private final PasswordEncoder passwordEncoder;
    
    public PasswordService() {
        // Use BCrypt with strength 12 (recommended for production)
        this.passwordEncoder = new BCryptPasswordEncoder(12);
    }
    
    /**
     * Hash a plaintext password using BCrypt
     * @param plainPassword the plaintext password to hash
     * @return the hashed password
     */
    public String hashPassword(String plainPassword) {
        if (plainPassword == null || plainPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        return passwordEncoder.encode(plainPassword);
    }
    
    /**
     * Verify a plaintext password against a hashed password
     * @param plainPassword the plaintext password to verify
     * @param hashedPassword the hashed password to compare against
     * @return true if the password matches, false otherwise
     */
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        if (plainPassword == null || hashedPassword == null) {
            return false;
        }
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
    
    /**
     * Check if a password is already hashed (starts with BCrypt identifier)
     * @param password the password to check
     * @return true if the password appears to be hashed
     */
    public boolean isPasswordHashed(String password) {
        return password != null && password.startsWith("$2a$");
    }
}

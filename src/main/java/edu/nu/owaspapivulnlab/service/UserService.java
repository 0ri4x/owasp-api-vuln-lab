package edu.nu.owaspapivulnlab.service;

import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    
    private final AppUserRepository userRepository;
    
    public UserService(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    /**
     * Get username by user ID for ownership validation
     * @param userId the user ID
     * @return the username
     */
    public String getUsernameById(Long userId) {
        return userRepository.findById(userId)
                .map(user -> user.getUsername())
                .orElse(null);
    }
    
    /**
     * Get user ID by username for ownership validation
     * @param username the username
     * @return the user ID
     */
    public Long getUserIdByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> user.getId())
                .orElse(null);
    }
}

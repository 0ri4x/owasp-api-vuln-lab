package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.UserService;
import edu.nu.owaspapivulnlab.web.dto.UserDTO;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final UserService userService;

    public UserController(AppUserRepository users, UserService userService) {
        this.users = users;
        this.userService = userService;
    }

    // SECURE: Require authentication and ownership validation
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or authentication.name == @userService.getUsernameById(#id)")
    public UserDTO get(@PathVariable Long id, Authentication auth) {
        // SECURE: Double-check ownership validation in method body
        if (!validateUserAccess(id, auth)) {
            throw new RuntimeException("Access denied: You can only access your own profile");
        }
        
        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return convertToDTO(user);
    }

    // SECURE: Prevent mass assignment by using explicit DTO and setting defaults
    @PostMapping
    public UserDTO create(@Valid @RequestBody UserDTO body) {
        // SECURE: Prevent mass assignment - only allow setting safe fields
        AppUser newUser = AppUser.builder()
                .username(body.getUsername())
                .email(body.getEmail())
                .role("USER") // Default role - prevent privilege escalation
                .isAdmin(false) // Default to non-admin - prevent privilege escalation
                .password("") // Password must be set through auth/signup endpoint
                .build();
        
        AppUser savedUser = users.save(newUser);
        return convertToDTO(savedUser);
    }

    // SECURE: Require authentication for user search
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserDTO> search(@RequestParam String q) {
        return users.search(q).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    // SECURE: Require admin role for listing all users
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserDTO> list() {
        return users.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    // SECURE: Require admin role for user deletion
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
    
    /**
     * SECURE: Validate that the authenticated user can access the specified user resource
     * @param targetUserId the user ID to check access for
     * @param auth the authentication context
     * @return true if user can access the resource (owns it or is admin), false otherwise
     */
    private boolean validateUserAccess(Long targetUserId, Authentication auth) {
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
        
        // Check if user is accessing their own profile
        return currentUserId.equals(targetUserId);
    }
    
    /**
     * Convert AppUser to UserDTO to prevent password exposure
     */
    private UserDTO convertToDTO(AppUser user) {
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .isAdmin(user.isAdmin())
                .build();
    }
}

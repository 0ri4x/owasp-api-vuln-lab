package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.web.dto.UserDTO;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // SECURE: Return UserDTO instead of AppUser to prevent password exposure
    @GetMapping("/{id}")
    public UserDTO get(@PathVariable Long id) {
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

    // SECURE: Return UserDTOs instead of AppUsers to prevent password exposure
    @GetMapping("/search")
    public List<UserDTO> search(@RequestParam String q) {
        return users.search(q).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    // SECURE: Return UserDTOs instead of AppUsers to prevent password exposure
    @GetMapping
    public List<UserDTO> list() {
        return users.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
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

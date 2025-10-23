package edu.nu.owaspapivulnlab.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.UserService;
import edu.nu.owaspapivulnlab.service.RateLimitService;
import edu.nu.owaspapivulnlab.service.InputValidationService;
import edu.nu.owaspapivulnlab.service.SecurityLoggingService;
import edu.nu.owaspapivulnlab.exception.ValidationException;
import edu.nu.owaspapivulnlab.web.dto.UserDTO;
import edu.nu.owaspapivulnlab.web.dto.PublicUserDTO;
import edu.nu.owaspapivulnlab.web.dto.AdminUserDTO;
import edu.nu.owaspapivulnlab.web.dto.CreateUserRequest;
import edu.nu.owaspapivulnlab.web.dto.AdminRoleUpdateRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final UserService userService;
    private final RateLimitService rateLimitService;
    private final InputValidationService inputValidationService;
    private final SecurityLoggingService securityLoggingService;

    public UserController(AppUserRepository users, UserService userService, RateLimitService rateLimitService, 
                         InputValidationService inputValidationService, SecurityLoggingService securityLoggingService) {
        this.users = users;
        this.userService = userService;
        this.rateLimitService = rateLimitService;
        this.inputValidationService = inputValidationService;
        this.securityLoggingService = securityLoggingService;
    }

    // SECURITY FIX: Enhanced user retrieval with ID validation
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or authentication.name == @userService.getUsernameById(#id)")
    public Object get(@PathVariable Long id, Authentication auth, HttpServletRequest request) {
        
        // SECURITY FIX: Validate user ID parameter
        if (!inputValidationService.isValidId(id)) {
            securityLoggingService.logSecurityViolation(
                "INVALID_USER_ID",
                auth.getName(),
                getClientIpAddress(request),
                "Invalid user ID: " + id,
                "MEDIUM"
            );
            
            throw new ValidationException(
                "Invalid user ID format",
                "User ID validation failed: " + id + " from user: " + auth.getName()
            );
        }
        // SECURE: Double-check ownership validation in method body
        if (!validateUserAccess(id, auth)) {
            throw new RuntimeException("Access denied: You can only access your own profile");
        }
        
        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        
        // SECURE: Return different DTOs based on user role
        if (isAdmin(auth)) {
            return convertToAdminDTO(user);
        } else {
            return convertToPublicDTO(user);
        }
    }

    // SECURITY FIX: Mass assignment protection using secure DTO
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest request, Authentication auth, HttpServletRequest httpRequest) {
        // SECURITY FIX: Rate limiting for user creation
        if (!rateLimitService.isAdminAllowed(httpRequest)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many user creation requests. Please try again later.");
            
            System.err.println("SECURITY ALERT: Rate limit exceeded for user creation from IP: " + 
                             httpRequest.getRemoteAddr() + " by admin: " + auth.getName() + 
                             " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Enhanced input validation using InputValidationService
        if (!inputValidationService.isValidUsername(request.getUsername())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid username format. Username must be 3-50 characters and contain only letters, numbers, underscore, or dash.");
            
            System.err.println("SECURITY ALERT: Invalid username format attempt from IP: " + 
                             httpRequest.getRemoteAddr() + " username: " + request.getUsername() + 
                             " by admin: " + auth.getName());
            
            return ResponseEntity.status(400).body(error);
        }
        
        if (!inputValidationService.isValidEmail(request.getEmail())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid email format");
            
            System.err.println("SECURITY ALERT: Invalid email format attempt from IP: " + 
                             httpRequest.getRemoteAddr() + " email: " + request.getEmail() + 
                             " by admin: " + auth.getName());
            
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURITY FIX: Sanitize inputs to prevent injection attacks
        String sanitizedUsername = inputValidationService.sanitizeString(request.getUsername()).toLowerCase();
        String sanitizedEmail = inputValidationService.sanitizeString(request.getEmail()).toLowerCase();
        
        // SECURITY FIX: Check for existing users
        if (users.findByUsername(sanitizedUsername).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username already exists");
            return ResponseEntity.status(409).body(error);
        }
        
        if (users.findByEmail(sanitizedEmail).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email already exists");
            return ResponseEntity.status(409).body(error);
        }
        
        // SECURITY FIX: Create user with secure defaults - no mass assignment possible
        AppUser newUser = AppUser.builder()
                .username(sanitizedUsername)
                .email(sanitizedEmail)
                .role("USER") // SECURITY: Always default to USER role
                .isAdmin(false) // SECURITY: Always default to non-admin
                .password("") // SECURITY: Password must be set through auth/signup endpoint
                .build();
        
        AppUser savedUser = users.save(newUser);
        
        // SECURITY FIX: Log admin user creation for audit
        System.out.println("INFO: User created by admin - Username: " + savedUser.getUsername() + 
                         " by admin: " + auth.getName() + " from IP: " + httpRequest.getRemoteAddr());
        
        return ResponseEntity.status(201).body(convertToDTO(savedUser));
    }

    // SECURITY FIX: Enhanced user search with data access rate limiting
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth, HttpServletRequest request) {
        // SECURITY FIX: Data access rate limiting for search operations
        if (!rateLimitService.isDataAccessAllowed(request)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many search requests. Please try again later.");
            
            // SECURITY FIX: Log suspicious search activity
            System.err.println("SECURITY ALERT: Rate limit exceeded for user search from IP: " + 
                             request.getRemoteAddr() + " query: " + q + " by admin: " + auth.getName() + 
                             " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Enhanced search query validation
        if (!inputValidationService.isValidSearchQuery(q)) {
            securityLoggingService.logSecurityViolation(
                "INVALID_SEARCH_QUERY",
                auth.getName(),
                getClientIpAddress(request),
                "Invalid search query: " + q,
                "MEDIUM"
            );
            
            throw new ValidationException(
                "Invalid search query. Query must be 2-100 characters and contain valid characters only.",
                "Search query validation failed: " + q + " from admin: " + auth.getName()
            );
        }
        
        String sanitizedQuery = inputValidationService.sanitizeString(q);
        
        // SECURITY FIX: Log admin search activities for audit
        System.out.println("INFO: Admin search executed - Query: " + sanitizedQuery + 
                         " by admin: " + auth.getName() + " from IP: " + request.getRemoteAddr());
        
        List<UserDTO> results = users.search(sanitizedQuery).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
        
        Map<String, Object> response = new HashMap<>();
        response.put("query", sanitizedQuery);
        response.put("results", results);
        response.put("count", results.size());
        response.put("timestamp", java.time.Instant.now());
        
        return ResponseEntity.ok(response);
    }

    // SECURE: Require admin role for listing all users with role-based data filtering
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<AdminUserDTO> list(Authentication auth) {
        // SECURE: Only admins can see full user details
        return users.findAll().stream()
                .map(this::convertToAdminDTO)
                .collect(Collectors.toList());
    }

    // SECURITY FIX: Admin-only role and privilege management endpoint
    @PutMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUserRole(@PathVariable Long id, @Valid @RequestBody AdminRoleUpdateRequest request, 
                                          Authentication auth, HttpServletRequest httpRequest) {
        // SECURITY FIX: Rate limiting for role updates
        if (!rateLimitService.isAdminAllowed(httpRequest)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Rate limit exceeded");
            error.put("message", "Too many role update requests. Please try again later.");
            
            System.err.println("SECURITY ALERT: Rate limit exceeded for role update from IP: " + 
                             httpRequest.getRemoteAddr() + " by admin: " + auth.getName() + 
                             " at " + java.time.Instant.now());
            
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Validate role input using InputValidationService
        if (!inputValidationService.isValidRole(request.getRole())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid role. Must be USER, ADMIN, or MODERATOR");
            
            System.err.println("SECURITY ALERT: Invalid role assignment attempt from IP: " + 
                             httpRequest.getRemoteAddr() + " role: " + request.getRole() + 
                             " by admin: " + auth.getName());
            
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURITY FIX: Validate that the target user exists
        AppUser targetUser = users.findById(id).orElse(null);
        if (targetUser == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "User not found");
            return ResponseEntity.status(404).body(error);
        }
        
        // SECURITY FIX: Prevent self-demotion (admin removing their own admin privileges)
        Long currentUserId = userService.getUserIdByUsername(auth.getName());
        if (currentUserId != null && currentUserId.equals(id) && !request.getIsAdmin()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Cannot remove admin privileges from yourself");
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURITY FIX: Update role and admin status with validation
        String previousRole = targetUser.getRole();
        boolean previousAdminStatus = targetUser.isAdmin();
        
        targetUser.setRole(request.getRole());
        targetUser.setAdmin(request.getIsAdmin());
        
        AppUser updatedUser = users.save(targetUser);
        
        // SECURITY FIX: Log all role changes for audit trail
        System.out.println("CRITICAL AUDIT: Role updated - User: " + updatedUser.getUsername() + 
                         " Previous Role: " + previousRole + " New Role: " + updatedUser.getRole() + 
                         " Previous Admin: " + previousAdminStatus + " New Admin: " + updatedUser.isAdmin() + 
                         " Updated by: " + auth.getName() + " IP: " + httpRequest.getRemoteAddr() + 
                         " Time: " + java.time.Instant.now());
        
        return ResponseEntity.ok(convertToAdminDTO(updatedUser));
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
     * SECURE: Check if the authenticated user is an admin
     */
    private boolean isAdmin(Authentication auth) {
        if (auth == null || auth.getAuthorities() == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
    }
    
    /**
     * SECURE: Convert AppUser to PublicUserDTO (excludes sensitive fields)
     */
    private PublicUserDTO convertToPublicDTO(AppUser user) {
        return PublicUserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
    
    /**
     * SECURE: Convert AppUser to AdminUserDTO (includes administrative fields for admins only)
     */
    private AdminUserDTO convertToAdminDTO(AppUser user) {
        return AdminUserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .isAdmin(user.isAdmin())
                .build();
    }
    
    /**
     * SECURITY FIX: Convert AppUser to secure UserDTO (excludes sensitive fields)
     */
    private UserDTO convertToDTO(AppUser user) {
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                // SECURITY FIX: Removed role and isAdmin fields to prevent exposure
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

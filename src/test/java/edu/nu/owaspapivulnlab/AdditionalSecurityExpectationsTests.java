package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * SECURITY FIX: Updated tests to validate security fixes in the hardened application
 * These tests now verify that security vulnerabilities have been properly addressed
 */
@SpringBootTest(properties = {
    "app.rate-limit.enabled=false",
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.data.redis.repositories.enabled=false",
    "app.jwt.secret=test-secret-key-that-is-at-least-256-bits-long-for-testing-purposes-only"
})
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    @BeforeEach
    void setUp() throws Exception {
        // Setup for tests - rate limiting disabled in test environment
    }

    /**
     * SECURITY FIX: Updated login method to work with new JWT response format
     */
    String login(String user, String pw) throws Exception {
        String res = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\""+user+"\",\"password\":\""+pw+"\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode n = om.readTree(res);
        // SECURITY FIX: Use new accessToken field instead of token
        return n.get("accessToken").asText();
    }

    /**
     * SECURITY FIX: Login method for admin users
     */
    String loginAdmin() throws Exception {
        return login("bob", "bob123");
    }

    @Test
    void protected_endpoints_require_authentication() throws Exception {
        // SECURITY FIX: Test that protected endpoints require authentication
        mvc.perform(get("/api/users"))
                .andExpect(status().isForbidden());
        
        mvc.perform(get("/api/accounts/mine"))
                .andExpect(status().isForbidden());
        
        mvc.perform(get("/api/admin/metrics"))
                .andExpect(status().isForbidden());
    }

    @Test
    void delete_user_requires_admin() throws Exception {
        // SECURITY FIX: Test that non-admin users cannot delete users
        String regularUser = login("alice","alice123"); // not admin
        mvc.perform(delete("/api/users/1").header("Authorization","Bearer "+regularUser))
                .andExpect(status().isForbidden());
        
        // SECURITY FIX: Test that admin users can delete users
        String adminUser = loginAdmin();
        mvc.perform(delete("/api/users/1").header("Authorization","Bearer "+adminUser))
                .andExpect(status().isOk());
    }

    @Test
    void jwt_tokens_work_correctly() throws Exception {
        // SECURITY FIX: Test that valid JWT tokens work
        String validToken = login("alice","alice123");
        mvc.perform(get("/api/accounts/mine").header("Authorization","Bearer "+validToken))
                .andExpect(status().isOk());
        
        // SECURITY FIX: Test that invalid JWT tokens are rejected
        mvc.perform(get("/api/accounts/mine").header("Authorization","Bearer invalid.token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void account_owner_only_access() throws Exception {
        // SECURITY FIX: Test that users can only access their own accounts
        String alice = login("alice","alice123");
        
        // SECURITY FIX: Test accessing non-existent or unauthorized account
        mvc.perform(get("/api/accounts/999/balance").header("Authorization","Bearer "+alice))
                .andExpect(status().isForbidden());
    }
}
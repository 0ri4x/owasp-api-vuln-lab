package edu.nu.owaspapivulnlab.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SECURITY FIX: Rate limiting configuration using Bucket4j
 * Implements token bucket algorithm for different endpoint types
 */
@Configuration
public class RateLimitConfig {

    // In-memory storage for rate limiting buckets (use Redis in production)
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    /**
     * SECURITY FIX: Redis configuration for distributed rate limiting
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory("localhost", 6379);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
        return template;
    }

    /**
     * SECURITY FIX: Get or create rate limiting bucket for authentication endpoints
     * Strict limits: 5 attempts per minute, 20 per hour
     */
    public Bucket getAuthBucket(String key) {
        return buckets.computeIfAbsent("auth:" + key, k -> 
            Bucket.builder()
                .addLimit(Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(20, Refill.intervally(20, Duration.ofHours(1))))
                .build()
        );
    }

    /**
     * SECURITY FIX: Get or create rate limiting bucket for financial operations
     * Very strict limits: 3 transfers per minute, 10 per hour
     */
    public Bucket getFinancialBucket(String key) {
        return buckets.computeIfAbsent("financial:" + key, k -> 
            Bucket.builder()
                .addLimit(Bandwidth.classic(3, Refill.intervally(3, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(10, Refill.intervally(10, Duration.ofHours(1))))
                .build()
        );
    }

    /**
     * SECURITY FIX: Get or create rate limiting bucket for data access endpoints
     * Moderate limits: 30 requests per minute, 200 per hour
     */
    public Bucket getDataAccessBucket(String key) {
        return buckets.computeIfAbsent("data:" + key, k -> 
            Bucket.builder()
                .addLimit(Bandwidth.classic(30, Refill.intervally(30, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(200, Refill.intervally(200, Duration.ofHours(1))))
                .build()
        );
    }

    /**
     * SECURITY FIX: Get or create rate limiting bucket for admin operations
     * Conservative limits: 10 requests per minute, 50 per hour
     */
    public Bucket getAdminBucket(String key) {
        return buckets.computeIfAbsent("admin:" + key, k -> 
            Bucket.builder()
                .addLimit(Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(50, Refill.intervally(50, Duration.ofHours(1))))
                .build()
        );
    }

    /**
     * SECURITY FIX: Get or create rate limiting bucket for general API endpoints
     * Standard limits: 60 requests per minute, 1000 per hour
     */
    public Bucket getGeneralBucket(String key) {
        return buckets.computeIfAbsent("general:" + key, k -> 
            Bucket.builder()
                .addLimit(Bandwidth.classic(60, Refill.intervally(60, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(1000, Refill.intervally(1000, Duration.ofHours(1))))
                .build()
        );
    }
}
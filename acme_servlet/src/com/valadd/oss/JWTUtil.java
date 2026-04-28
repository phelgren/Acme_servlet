/*
 * Copyright (c) 2026 Pete Helgren
 *
 * Licensed under the Pete Helgren Non-Commercial Source License v1.1.
 *
 * This software is licensed for non-commercial use only.
 * Commercial use requires prior written permission.
 *
 * Prohibited Uses:
 * - Training or improving artificial intelligence systems
 * - Inclusion in machine learning datasets
 * - Automated scraping or harvesting for AI or data-driven purposes
 *
 * See LICENSE.txt in the project root for complete terms.
 */

package com.valadd.oss;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Properties;

/**
 * Simple JWT utility for token generation and validation
 * Uses JWT_secret from lecm.properties file
 */
public class JWTUtil {

    private static final String PROPERTIES_FILE = "/etc/acmedcm/conf/acmedcm.properties";
    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 24 hours
    private static SecretKey key;

    static {
        try {
            // Load JWT secret from externalized properties
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
                props.load(fis);
            }

            String jwtSecret = props.getProperty("JWT_secret");
            if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
                throw new IllegalStateException("JWT_secret not configured in " + PROPERTIES_FILE);
            }

            key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            SystemLogger.log("JWT secret loaded successfully from " + PROPERTIES_FILE);

        } catch (IOException e) {
            throw new IllegalStateException("Failed to load JWT secret from " + PROPERTIES_FILE, e);
        }
    }

    /**
     * Generate JWT token
     */
    public static String generateToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + EXPIRATION_TIME);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validate token and return username (null if invalid)
     */
    public static String validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            return null;
        }
    }
}
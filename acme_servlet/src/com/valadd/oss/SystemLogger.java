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

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Utility class for conditional system logging based on systemLogging property.
 * This allows enabling/disabling System.out and System.err logging without code
 * changes.
 */
public class SystemLogger {
    private static final String PROPERTIES_FILE = "/etc/acmedcm/conf/acmedcm.properties";
    private static Boolean systemLoggingEnabled = null;
    private static long lastLoadTime = 0;
    private static final long CACHE_DURATION = 60000; // 1 minute cache

    /**
     * Check if system logging is enabled from properties file.
     * Caches the result for 1 minute to avoid repeated file reads.
     */
    private static boolean isSystemLoggingEnabled() {
        long currentTime = System.currentTimeMillis();

        // Reload if cache expired or not yet loaded
        if (systemLoggingEnabled == null || (currentTime - lastLoadTime) > CACHE_DURATION) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
                props.load(fis);
                systemLoggingEnabled = Boolean.parseBoolean(props.getProperty("systemLogging", "false"));
                lastLoadTime = currentTime;
            } catch (IOException e) {
                // If properties file can't be read, default to false (no logging)
                systemLoggingEnabled = false;
                lastLoadTime = currentTime;
            }
        }

        return systemLoggingEnabled;
    }

    /**
     * Log a message to System.out if system logging is enabled.
     */
    public static void log(String message) {
        if (isSystemLoggingEnabled()) {
            System.out.println(message);
        }
    }

    /**
     * Log an error message to System.err if system logging is enabled.
     */
    public static void logError(String message) {
        if (isSystemLoggingEnabled()) {
            System.err.println(message);
        }
    }

    /**
     * Log an exception with stack trace to System.err if system logging is enabled.
     */
    public static void logError(String message, Throwable throwable) {
        if (isSystemLoggingEnabled()) {
            System.err.println(message);
            throwable.printStackTrace();
        }
    }

    /**
     * Clear the cache to force reload on next call.
     * Useful for testing or when properties file is updated.
     */
    public static void clearCache() {
        systemLoggingEnabled = null;
        lastLoadTime = 0;
    }
}

// Made with Bob

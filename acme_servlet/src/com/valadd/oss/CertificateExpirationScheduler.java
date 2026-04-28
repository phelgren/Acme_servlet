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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.exception.AcmeException;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Certificate Expiration Scheduler
 * Runs daily to check certificate expiration dates and send push notifications
 * to subscribed users at 30, 14, and 7 days before expiration.
 */
public class CertificateExpirationScheduler implements ServletContextListener {

    private static final String PROPERTIES_FILE = "/etc/acmedcm/conf/acmedcm.properties";
    private ScheduledExecutorService scheduler;
    private Properties properties;

    // Notification thresholds (days before expiration)
    // This will be loaded from properties file (autoRenewDays setting)
    private int autoRenewDays = 30; // Default value

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        SystemLogger.log("Certificate Expiration Scheduler: Initializing...");

        // Register Bouncy Castle security provider for web-push encryption
        try {
            Security.addProvider(new BouncyCastleProvider());
            SystemLogger.log("Bouncy Castle security provider registered successfully");
        } catch (Exception e) {
            SystemLogger.logError("Failed to register Bouncy Castle provider: " + e.getMessage(), e);
        }

        // Load properties
        loadProperties();

        // Load auto-renewal days from properties
        try {
            autoRenewDays = Integer.parseInt(properties.getProperty("autoRenewDays", "30"));
            SystemLogger.log("Certificate Expiration Scheduler: Auto-renewal set to " + autoRenewDays
                    + " days before expiration");
        } catch (NumberFormatException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Invalid autoRenewDays value, using default (30)");
            autoRenewDays = 30;
        }

        // Create scheduler that runs daily at 2 AM
        scheduler = Executors.newScheduledThreadPool(1);

        // Calculate initial delay to next 2 AM
        long initialDelay = calculateInitialDelay();

        // Schedule the task to run daily
        scheduler.scheduleAtFixedRate(
                this::checkCertificateExpirations,
                initialDelay,
                TimeUnit.DAYS.toSeconds(1), // Run every 24 hours
                TimeUnit.SECONDS);

        SystemLogger.log("Certificate Expiration Scheduler: Started. Next run in " +
                (initialDelay / 3600) + " hours");
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        SystemLogger.log("Certificate Expiration Scheduler: Shutting down...");
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(60, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        SystemLogger.log("Certificate Expiration Scheduler: Stopped");
    }

    /**
     * Calculate seconds until next 2 AM
     */
    private long calculateInitialDelay() {
        Calendar now = Calendar.getInstance();
        Calendar next2AM = Calendar.getInstance();

        next2AM.set(Calendar.HOUR_OF_DAY, 2);
        next2AM.set(Calendar.MINUTE, 0);
        next2AM.set(Calendar.SECOND, 0);
        next2AM.set(Calendar.MILLISECOND, 0);

        // If 2 AM has passed today, schedule for tomorrow
        if (now.after(next2AM)) {
            next2AM.add(Calendar.DAY_OF_MONTH, 1);
        }

        long delayMillis = next2AM.getTimeInMillis() - now.getTimeInMillis();
        return delayMillis / 1000; // Convert to seconds
    }

    /**
     * Load properties from file
     */
    private void loadProperties() {
        properties = new Properties();
        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
            properties.load(fis);
            SystemLogger.log("Certificate Expiration Scheduler: Properties loaded");
        } catch (IOException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error loading properties: " + e.getMessage());
        }
    }

    /**
     * Main task: Check certificate expirations and send notifications
     */
    private void checkCertificateExpirations() {
        SystemLogger.log("Certificate Expiration Scheduler: Starting certificate check at " +
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));

        com.ibm.as400.access.AS400 as400 = null;
        try {
            // Create AS400 connection
            String os400IP = properties.getProperty("os400IP", "localhost");
            String os400User = properties.getProperty("os400User");
            String os400PW = properties.getProperty("os400PW");

            as400 = new com.ibm.as400.access.AS400(os400IP, os400User, os400PW);

            // Get all certificates
            String certificateStore = properties.getProperty("certificateStore", "*SYSTEM");
            String certificateStorePassword = properties.getProperty("certificateStorePassword", "*NONE");

            List<CertificateUtils.CertInfo> certificates = CertificateUtils.getCertificates(
                    as400, certificateStore, certificateStorePassword);
            SystemLogger.log("Certificate Expiration Scheduler: Found " + certificates.size() + " certificates");

            // Check each certificate for expiration
            // Filter out certificates with "privatekey" in the alias name
            for (CertificateUtils.CertInfo cert : certificates) {
                if (cert.getLabel() != null &&
                        cert.getLabel().toLowerCase().contains("privatekey")) {
                    SystemLogger.log(
                            "Certificate Expiration Scheduler: Skipping certificate with 'privatekey' in alias: " +
                                    cert.getLabel());
                    continue;
                }
                checkAndNotify(cert);
            }

            SystemLogger.log("Certificate Expiration Scheduler: Check completed");

        } catch (Exception e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error during check: " + e.getMessage(), e);
        } finally {
            // Close AS400 connection
            if (as400 != null) {
                try {
                    as400.disconnectAllServices();
                } catch (Exception e) {
                    SystemLogger.logError(
                            "Certificate Expiration Scheduler: Error closing AS400 connection: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Check if certificate needs notification and send if needed
     * Also attempt automatic renewal if ACME config exists
     */
    private void checkAndNotify(CertificateUtils.CertInfo cert) {
        try {
            // Calculate days until expiration
            LocalDate today = LocalDate.now();
            LocalDate expirationDate = cert.getExpirationDate();
            long daysUntilExpiration = ChronoUnit.DAYS.between(today, expirationDate);

            // Check if we should attempt renewal at the configured threshold
            if (daysUntilExpiration <= autoRenewDays && daysUntilExpiration >= 0) {
                // Check if we already attempted renewal today for this certificate
                if (!wasNotificationSent(cert.getLabel(), (int) daysUntilExpiration)) {
                    // Attempt automatic renewal if ACME config exists
                    RenewalResult result = attemptAutomaticRenewal(cert.getLabel(), (int) daysUntilExpiration);

                    // Send notification about the renewal result
                    if (result.attempted) {
                        sendRenewalNotification(cert, result.success, result.errorMessage);
                    } else {
                        // No ACME config, send expiration warning
                        sendExpirationNotification(cert, (int) daysUntilExpiration);
                    }

                    recordNotificationSent(cert.getLabel(), (int) daysUntilExpiration);
                    SystemLogger.log("Certificate Expiration Scheduler: Processed certificate " +
                            cert.getLabel() + " (" + daysUntilExpiration + " days)");
                } else {
                    SystemLogger.log("Certificate Expiration Scheduler: Already processed today for " +
                            cert.getLabel() + " (" + daysUntilExpiration + " days)");
                }
            }

            // Also check if already expired
            if (daysUntilExpiration < 0) {
                SystemLogger.log("Certificate Expiration Scheduler: WARNING - Certificate expired: " +
                        cert.getLabel() + " (expired " + Math.abs(daysUntilExpiration) + " days ago)");
            }

        } catch (Exception e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error checking certificate " +
                    cert.getLabel() + ": " + e.getMessage());
        }
    }

    /**
     * Check if notification was already sent today for this certificate
     * This ensures we only send one notification per day per certificate,
     * but will send daily notifications as long as expiration is within
     * autoRenewDays window
     */
    private boolean wasNotificationSent(String certLabel, int daysUntilExpiration) {
        String os400IP = properties.getProperty("os400IP", "localhost");
        String os400User = properties.getProperty("os400User");
        String os400PW = properties.getProperty("os400PW");

        String jdbcUrl = "jdbc:as400://" + os400IP + "/ACMEDCM";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, os400User, os400PW)) {
            // Check if any notification was sent today for this certificate
            // regardless of the days_threshold value
            String sql = "SELECT COUNT(*) FROM ACMEDCM.CERT_NOTIFICATIONS " +
                    "WHERE CERT_LABEL = ? " +
                    "AND DATE(SENT_TIMESTAMP) = CURRENT_DATE";

            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, certLabel);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getInt(1) > 0;
                    }
                }
            }
        } catch (SQLException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error checking notification history: " +
                    e.getMessage());
        }

        return false;
    }

    /**
     * Record that notification was sent
     */
    private void recordNotificationSent(String certLabel, int daysThreshold) {
        String os400IP = properties.getProperty("os400IP", "localhost");
        String os400User = properties.getProperty("os400User");
        String os400PW = properties.getProperty("os400PW");

        String jdbcUrl = "jdbc:as400://" + os400IP + "/ACMEDCM";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, os400User, os400PW)) {
            String sql = "INSERT INTO ACMEDCM.CERT_NOTIFICATIONS " +
                    "(CERT_LABEL, DAYS_THRESHOLD, SENT_TIMESTAMP) " +
                    "VALUES (?, ?, CURRENT_TIMESTAMP)";

            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, certLabel);
                stmt.setInt(2, daysThreshold);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error recording notification: " +
                    e.getMessage());
        }
    }

    /**
     * Result of a renewal attempt
     */
    private static class RenewalResult {
        boolean attempted;
        boolean success;
        String errorMessage;

        RenewalResult(boolean attempted, boolean success, String errorMessage) {
            this.attempted = attempted;
            this.success = success;
            this.errorMessage = errorMessage;
        }
    }

    /**
     * Attempt automatic renewal of certificate if ACME config exists
     *
     * @param certLabel           The certificate label/alias
     * @param daysUntilExpiration Days until expiration
     * @return RenewalResult with attempt status and outcome
     */
    private RenewalResult attemptAutomaticRenewal(String certLabel, int daysUntilExpiration) {
        try {
            // Get ACME config for this certificate
            ACMEConfig config = getAcmeConfigForCertificate(certLabel);

            if (config == null) {
                SystemLogger.log("Certificate Expiration Scheduler: No ACME config found for " + certLabel);
                return new RenewalResult(false, false, null);
            }

            SystemLogger.log("Certificate Expiration Scheduler: Attempting automatic renewal for " + certLabel);

            // Create ACMEprocessor instance with config parameters
            Collection<String> domains = Arrays.asList(config.getDomain().split(",", -1));

            ACMEprocessor processor = new ACMEprocessor(
                    domains,
                    config.getChallengeType(),
                    String.valueOf(config.getTimeout()),
                    config.getRequestType(),
                    config.getAccountKey(),
                    config.getCsr(),
                    config.getWrkFolder(),
                    config.getCertificatePath(),
                    config.getWellKnownDir() != null ? config.getWellKnownDir() : config.getWrkFolder());

            // Execute the renewal process
            processor.prepcert(null);

            SystemLogger
                    .log("Certificate Expiration Scheduler: Automatic renewal completed successfully for " + certLabel);
            return new RenewalResult(true, true, null);

        } catch (IOException | AcmeException e) {
            String errorMsg = e.getMessage();
            SystemLogger.logError("Certificate Expiration Scheduler: Error during automatic renewal for " +
                    certLabel + ": " + errorMsg, e);
            return new RenewalResult(true, false, errorMsg);
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            SystemLogger.logError("Certificate Expiration Scheduler: Unexpected error during renewal for " +
                    certLabel + ": " + errorMsg, e);
            return new RenewalResult(true, false, errorMsg);
        }
    }

    /**
     * Get ACME configuration for a certificate from the database
     * 
     * @param certLabel The certificate label/alias
     * @return ACMEConfig object or null if not found
     */
    private ACMEConfig getAcmeConfigForCertificate(String certLabel) {
        String os400IP = properties.getProperty("os400IP", "localhost");
        String os400User = properties.getProperty("os400User");
        String os400PW = properties.getProperty("os400PW");

        String jdbcUrl = "jdbc:as400://" + os400IP + "/ACMEDCM";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, os400User, os400PW)) {
            String sql = "SELECT ID, NAME, CHALLENGE_TYPE, TIMEOUT, REQUEST_TYPE, DOMAIN, " +
                    "ACCOUNT_KEY, CSR, WELL_KNOWN_DIR, CERTIFICATE_PATH, WRK_FOLDER, DNS_TXT_RECORD " +
                    "FROM ACMEDCM.ACME_CONFIGS WHERE NAME = ?";

            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, certLabel);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        ACMEConfig config = new ACMEConfig();
                        config.setId(rs.getString("ID"));
                        config.setName(rs.getString("NAME"));
                        config.setChallengeType(rs.getString("CHALLENGE_TYPE"));
                        config.setTimeout(rs.getInt("TIMEOUT"));
                        config.setRequestType(rs.getString("REQUEST_TYPE"));
                        config.setDomain(rs.getString("DOMAIN"));
                        config.setAccountKey(rs.getString("ACCOUNT_KEY"));
                        config.setCsr(rs.getString("CSR"));
                        config.setWellKnownDir(rs.getString("WELL_KNOWN_DIR"));
                        config.setCertificatePath(rs.getString("CERTIFICATE_PATH"));
                        config.setWrkFolder(rs.getString("WRK_FOLDER"));
                        config.setDnsTxtRecord(rs.getString("DNS_TXT_RECORD"));
                        return config;
                    }
                }
            }
        } catch (SQLException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error getting ACME config: " +
                    e.getMessage());
        }

        return null;
    }

    /**
     * Send push notification about renewal attempt result
     * Uses PushNotificationServlet static methods
     *
     * @param cert         The certificate information
     * @param success      Whether renewal was successful
     * @param errorMessage Error message if renewal failed
     */
    private void sendRenewalNotification(CertificateUtils.CertInfo cert, boolean success, String errorMessage) {
        try {
            // Get all push subscriptions using PushNotificationServlet
            List<PushNotificationServlet.PushSubscriptionData> subscriptions = PushNotificationServlet
                    .getAllSubscriptions();

            if (subscriptions.isEmpty()) {
                SystemLogger.log("Certificate Expiration Scheduler: No subscriptions found");
                return;
            }

            // Create notification message based on renewal result
            String title;
            String body;
            String notificationType;

            if (success) {
                title = "Certificate Renewal Successful";
                body = String.format("Certificate '%s' has been successfully renewed.", cert.getLabel());
                notificationType = "renewal_success";
            } else {
                title = "Certificate Renewal Failed";
                body = String.format("Attempt to renew certificate '%s' failed. %s",
                        cert.getLabel(),
                        errorMessage != null ? "Error: " + errorMessage : "Please check logs for details.");
                notificationType = "renewal_failed";
            }

            // Create unique tag for this certificate renewal
            String safeLabel = cert.getLabel().toLowerCase().replaceAll("[^a-z0-9]+", "-");
            String tag = "cert-renewal-" + safeLabel + "-" + System.currentTimeMillis();

            // Send to each subscription using PushNotificationServlet
            int successCount = 0;
            for (PushNotificationServlet.PushSubscriptionData subscription : subscriptions) {
                try {
                    PushNotificationServlet.sendPushNotification(
                            subscription.id,
                            subscription.username,
                            subscription.endpoint,
                            subscription.p256dhKey,
                            subscription.authKey,
                            notificationType,
                            title,
                            body,
                            tag);
                    successCount++;
                } catch (Exception e) {
                    SystemLogger.logError("Certificate Expiration Scheduler: Error sending to subscription: " +
                            e.getMessage());
                }
            }

            SystemLogger.log("Certificate Expiration Scheduler: Sent renewal notifications to " +
                    successCount + " of " + subscriptions.size() + " subscribers");

        } catch (SQLException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error getting subscriptions: " +
                    e.getMessage());
        }
    }

    /**
     * Send push notification about certificate expiration (no ACME config)
     * Uses PushNotificationServlet static methods
     *
     * @param cert                The certificate information
     * @param daysUntilExpiration Days until expiration
     */
    private void sendExpirationNotification(CertificateUtils.CertInfo cert, int daysUntilExpiration) {
        try {
            // Get all push subscriptions using PushNotificationServlet
            List<PushNotificationServlet.PushSubscriptionData> subscriptions = PushNotificationServlet
                    .getAllSubscriptions();

            if (subscriptions.isEmpty()) {
                SystemLogger.log("Certificate Expiration Scheduler: No subscriptions found");
                return;
            }

            // Create notification message
            String title = "Certificate Expiring Soon";
            String body = String.format("Certificate '%s' will expire in %d days. No automatic renewal configured.",
                    cert.getLabel(), daysUntilExpiration);

            // Create unique tag for this certificate and threshold
            String safeLabel = cert.getLabel().toLowerCase().replaceAll("[^a-z0-9]+", "-");
            String tag = "cert-expiry-" + safeLabel + "-" + daysUntilExpiration;

            // Send to each subscription using PushNotificationServlet
            int successCount = 0;
            for (PushNotificationServlet.PushSubscriptionData subscription : subscriptions) {
                try {
                    PushNotificationServlet.sendPushNotification(
                            subscription.id,
                            subscription.username,
                            subscription.endpoint,
                            subscription.p256dhKey,
                            subscription.authKey,
                            "expiration",
                            title,
                            body,
                            tag);
                    successCount++;
                } catch (Exception e) {
                    SystemLogger.logError("Certificate Expiration Scheduler: Error sending to subscription: " +
                            e.getMessage());
                }
            }

            SystemLogger.log("Certificate Expiration Scheduler: Sent expiration notifications to " +
                    successCount + " of " + subscriptions.size() + " subscribers");

        } catch (SQLException e) {
            SystemLogger.logError("Certificate Expiration Scheduler: Error getting subscriptions: " +
                    e.getMessage());
        }
    }
}
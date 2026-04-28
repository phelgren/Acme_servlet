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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Servlet to provide application configuration from properties file
 * GET /api/config/properties - Get public configuration values
 */
public class ConfigPropertiesServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();
    private static final String PROPERTIES_FILE = "/etc/acmedcm/conf/acmedcm.properties";

    // Cache the properties to avoid reading file on every request
    private static Properties cachedProperties = null;
    private static long lastLoadTime = 0;
    private static final long CACHE_DURATION = 60000; // 1 minute cache

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            Properties props = loadProperties();

            // Build response with all frontend-needed configuration values
            Map<String, Object> config = new HashMap<>();

            // API URLs - construct from request if not in properties
            String apiUrl = props.getProperty("apiUrl");
            String servletUrl = props.getProperty("servletUrl");

            // If not in properties, construct from current request
            if (apiUrl == null || apiUrl.isEmpty()) {
                String scheme = request.getScheme();
                String serverName = request.getServerName();
                int serverPort = request.getServerPort();
                String contextPath = request.getContextPath();

                servletUrl = scheme + "://" + serverName + ":" + serverPort + contextPath;
                apiUrl = servletUrl + "/api";

                SystemLogger.log("Constructed URLs from request - apiUrl: " + apiUrl + ", servletUrl: " + servletUrl);
            }

            config.put("apiUrl", apiUrl);
            config.put("servletUrl", servletUrl);
            config.put("apiTimeout", Integer.parseInt(props.getProperty("apiTimeout", "30000")));
            config.put("production", Boolean.parseBoolean(props.getProperty("production", "false")));

            // Certificate store configuration
            config.put("certificateStore", props.getProperty("certificateStore", "*SYSTEM"));
            config.put("certificateStorePassword", props.getProperty("certificateStorePassword", "*NONE"));

            // API URLs (for ACME integration)
            config.put("baseURL", props.getProperty("baseURL", ""));
            config.put("acmeURL", props.getProperty("acmeURL", ""));

            // IBM i connection info (for display purposes only, not credentials)
            config.put("os400IP", props.getProperty("os400IP", "localhost"));

            // Push Notifications - VAPID Public Key (safe to expose to frontend)
            String vapidPublicKey = props.getProperty("vapid.publicKey", "");
            if (!vapidPublicKey.isEmpty()) {
                config.put("vapidPublicKey", vapidPublicKey);
                SystemLogger.log("VAPID public key loaded from properties");
                SystemLogger.log("VAPID public key loaded: " + vapidPublicKey);
            } else {
                SystemLogger.logError("Warning: vapid.publicKey not found in properties file");
            }

            // Auto-renewal settings
            config.put("autoRenewDays", Integer.parseInt(props.getProperty("autoRenewDays", "30")));

            // Console logging setting (frontend logging control)
            config.put("consoleLogging", Boolean.parseBoolean(props.getProperty("consoleLogging", "false")));

            // System logging setting (backend logging control)
            config.put("systemLogging", Boolean.parseBoolean(props.getProperty("systemLogging", "false")));

            // Build response wrapper
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("data", config);

            response.getWriter().write(gson.toJson(responseData));

        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Error loading configuration: " + e.getMessage());
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            // Read request body
            StringBuilder sb = new StringBuilder();
            BufferedReader reader = request.getReader();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            // Parse JSON
            JsonObject jsonRequest = JsonParser.parseString(sb.toString()).getAsJsonObject();

            if (!jsonRequest.has("autoRenewDays")) {
                sendError(response, 400, "Missing required field: autoRenewDays");
                return;
            }

            int autoRenewDays = jsonRequest.get("autoRenewDays").getAsInt();

            // Validate value
            if (autoRenewDays < 1 || autoRenewDays > 90) {
                sendError(response, 400, "autoRenewDays must be between 1 and 90");
                return;
            }

            // Load current properties
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
                props.load(fis);
            } catch (IOException e) {
                SystemLogger.logError("Warning: Could not load properties file: " + PROPERTIES_FILE);
                // Continue with empty properties - will create new file
            }

            // Update property
            props.setProperty("autoRenewDays", String.valueOf(autoRenewDays));

            // Save properties back to file
            try (FileOutputStream fos = new FileOutputStream(PROPERTIES_FILE)) {
                props.store(fos, "ACME DCM Configuration - Updated by ConfigPropertiesServlet");
                SystemLogger.log("Updated autoRenewDays to " + autoRenewDays + " in " + PROPERTIES_FILE);
            }

            // Clear cache to force reload
            reloadProperties();

            // Build success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("message", "Auto-renewal setting updated successfully");

            Map<String, Object> data = new HashMap<>();
            data.put("autoRenewDays", autoRenewDays);
            responseData.put("data", data);

            response.getWriter().write(gson.toJson(responseData));

        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Error updating configuration: " + e.getMessage());
        }
    }

    /**
     * Load properties from file with caching
     */
    private Properties loadProperties() throws IOException {
        long currentTime = System.currentTimeMillis();

        // Return cached properties if still valid
        if (cachedProperties != null && (currentTime - lastLoadTime) < CACHE_DURATION) {
            return cachedProperties;
        }

        // Load properties from file
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
            props.load(fis);
            SystemLogger.log("Loaded configuration from: " + PROPERTIES_FILE);
        } catch (IOException e) {
            SystemLogger.logError("Warning: Could not load properties file: " + PROPERTIES_FILE);
            SystemLogger.logError("Using default values");
            // Set defaults
            props.setProperty("certificateStore", "*SYSTEM");
            props.setProperty("certificateStorePassword", "*NONE");
        }

        // Update cache
        cachedProperties = props;
        lastLoadTime = currentTime;

        return props;
    }

    /**
     * Force reload of properties (can be called via management endpoint)
     */
    public static void reloadProperties() {
        cachedProperties = null;
        lastLoadTime = 0;
        SystemLogger.log("Properties cache cleared - will reload on next request");
    }

    private void sendError(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("error", message);
        response.getWriter().write(gson.toJson(error));
    }
}
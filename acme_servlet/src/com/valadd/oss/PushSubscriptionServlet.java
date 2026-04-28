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
import com.ibm.as400.access.AS400;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Push Subscription Management Servlet
 * POST /api/push/subscribe - Subscribe to push notifications
 * POST /api/push/unsubscribe - Unsubscribe from push notifications
 * GET /api/push/status - Get subscription status
 */
public class PushSubscriptionServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    static {
        try {
            Class.forName("com.ibm.as400.access.AS400JDBCDriver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("JDBC driver not found", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String pathInfo = request.getPathInfo();

        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                sendError(response, 401, "No session found");
                return;
            }

            String username = (String) session.getAttribute("username");
            if (username == null) {
                sendError(response, 401, "User not authenticated");
                return;
            }

            if ("/status".equals(pathInfo)) {
                // Get endpoint parameter to check for specific browser subscription
                String endpoint = request.getParameter("endpoint");

                try (Connection conn = getConnection(request)) {
                    boolean hasSubscription;
                    if (endpoint != null && !endpoint.isEmpty()) {
                        // Check for specific endpoint (browser-specific check)
                        hasSubscription = checkSubscriptionExists(conn, username, endpoint);
                    } else {
                        // Check if user has any subscription (legacy behavior)
                        hasSubscription = checkSubscriptionExists(conn, username);
                    }

                    Map<String, Object> status = new HashMap<>();
                    status.put("subscribed", hasSubscription);
                    status.put("username", username);

                    sendSuccess(response, status);
                }
            } else {
                sendError(response, 404, "Endpoint not found");
            }

        } catch (SQLException e) {
            e.printStackTrace();
            sendError(response, 500, "Database error: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Server error: " + e.getMessage());
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String pathInfo = request.getPathInfo();

        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                sendError(response, 401, "No session found");
                return;
            }

            String username = (String) session.getAttribute("username");
            if (username == null) {
                sendError(response, 401, "User not authenticated");
                return;
            }

            String body = readBody(request);

            @SuppressWarnings("unchecked")
            Map<String, Object> subscriptionData = gson.fromJson(body, Map.class);

            // This connection will be closed automatically
            try (Connection conn = getConnection(request)) {

                if ("/subscribe".equals(pathInfo)) {
                    saveSubscription(conn, username, subscriptionData);

                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Subscription saved successfully");
                    result.put("username", username);

                    sendSuccess(response, result);

                } else if ("/unsubscribe".equals(pathInfo)) {
                    removeSubscription(conn, username, subscriptionData);

                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Subscription removed successfully");
                    result.put("username", username);

                    sendSuccess(response, result);

                } else {
                    sendError(response, 404, "Endpoint not found");
                }
            }

        } catch (SQLException e) {
            e.printStackTrace();
            sendError(response, 500, "Database error: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Server error: " + e.getMessage());
        }
    }

    /**
     * Check if user has an active subscription (any browser)
     */
    private boolean checkSubscriptionExists(Connection conn, String username) throws SQLException {
        String sql = "SELECT COUNT(*) FROM PUSH_SUBSCRIPTIONS WHERE USRPRF = ? AND ENABLED = 'Y'";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        }
        return false;
    }

    /**
     * Check if user has an active subscription for a specific endpoint
     * (browser-specific)
     */
    private boolean checkSubscriptionExists(Connection conn, String username, String endpoint) throws SQLException {
        String sql = "SELECT COUNT(*) FROM PUSH_SUBSCRIPTIONS WHERE USRPRF = ? AND ENDPOINT = ? AND ENABLED = 'Y'";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, endpoint);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        }
        return false;
    }

    /**
     * Save push subscription
     */
    private void saveSubscription(Connection conn, String username, Map<String, Object> subscriptionData)
            throws SQLException {

        String endpoint = (String) subscriptionData.get("endpoint");
        @SuppressWarnings("unchecked")
        Map<String, String> keys = (Map<String, String>) subscriptionData.get("keys");

        if (endpoint == null || keys == null) {
            throw new SQLException("Invalid subscription data");
        }

        String p256dhKey = keys.get("p256dh");
        String authKey = keys.get("auth");

        if (p256dhKey == null || authKey == null) {
            throw new SQLException("Missing encryption keys");
        }

        SystemLogger.log("SAVE p256dh len=" + p256dhKey.length() + ", auth len=" + authKey.length());

        // Check if subscription already exists for this endpoint
        String checkSql = "SELECT ID FROM PUSH_SUBSCRIPTIONS WHERE ENDPOINT = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(checkSql)) {
            pstmt.setString(1, endpoint);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    // Update existing subscription (same endpoint, possibly updated keys)
                    String updateSql = "UPDATE PUSH_SUBSCRIPTIONS SET USRPRF = ?, P256DH_KEY = ?, " +
                            "AUTH_KEY = ?, ENABLED = 'Y' WHERE ENDPOINT = ?";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                        updateStmt.setString(1, username);
                        updateStmt.setString(2, p256dhKey);
                        updateStmt.setString(3, authKey);
                        updateStmt.setString(4, endpoint);
                        updateStmt.executeUpdate();
                        SystemLogger.log("Updated push subscription for user: " + username);
                    }
                    return;
                }
            }
        }

        // Insert new subscription
        // Note: We don't delete old subscriptions here because users may have multiple
        // browsers
        // (Chrome, Firefox, etc.) each with their own valid subscription endpoint.
        // Old/orphaned subscriptions should be cleaned up by a separate maintenance
        // process
        // that checks if endpoints are still valid with the push service.
        String insertSql = "INSERT INTO PUSH_SUBSCRIPTIONS (USRPRF, ENDPOINT, P256DH_KEY, AUTH_KEY, ENABLED) " +
                "VALUES (?, ?, ?, ?, 'Y')";
        try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, endpoint);
            pstmt.setString(3, p256dhKey);
            pstmt.setString(4, authKey);
            pstmt.executeUpdate();
            SystemLogger.log("Created push subscription for user: " + username);
        }
    }

    /**
     * Remove push subscription
     */
    private void removeSubscription(Connection conn, String username, Map<String, Object> subscriptionData)
            throws SQLException {

        String endpoint = (String) subscriptionData.get("endpoint");

        if (endpoint == null) {
            throw new SQLException("Invalid subscription data");
        }

        // Disable the subscription (soft delete)
        String sql = "UPDATE PUSH_SUBSCRIPTIONS SET ENABLED = 'N' WHERE USRPRF = ? AND ENDPOINT = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, endpoint);
            int updated = pstmt.executeUpdate();
            SystemLogger.log("Disabled push subscription for user: " + username + " (rows: " + updated + ")");
        }
    }

    /**
     * Get database connection using authenticated user's AS400 object
     */
    private Connection getConnection(HttpServletRequest request) throws SQLException {
        HttpSession session = request.getSession(false);

        if (session == null) {
            throw new SQLException("No session found - user not authenticated");
        }

        AS400 as400 = (AS400) session.getAttribute("as400");

        if (as400 == null) {
            throw new SQLException("No authenticated AS400 connection in session");
        }

        try {
            com.ibm.as400.access.AS400JDBCDriver driver = new com.ibm.as400.access.AS400JDBCDriver();
            Connection conn = driver.connect(as400);

            // Set the default schema to ACMEDCM
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("SET SCHEMA ACMEDCM");
            } catch (SQLException e) {
                SystemLogger.logError("Warning: Could not set schema to ACMEDCM: " + e.getMessage());
            }

            return conn;

        } catch (Exception e) {
            throw new SQLException("Failed to create database connection: " + e.getMessage(), e);
        }
    }

    /**
     * Read request body
     */
    private String readBody(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = request.getReader();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    /**
     * Send success response
     */
    private void sendSuccess(HttpServletResponse response, Object data) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("data", data);
        response.getWriter().write(gson.toJson(result));
    }

    /**
     * Send error response
     */
    private void sendError(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("error", message);
        response.getWriter().write(gson.toJson(error));
    }
}
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
import nl.martijndwars.webpush.*;

import nl.martijndwars.webpush.Notification;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.jose4j.lang.JoseException;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.*;
import java.util.*;

/**
 * Push Notification Servlet
 * Provides both HTTP endpoints for testing and static utility methods for
 * sending push notifications
 * 
 * HTTP Endpoints:
 * GET /api/push/test - Show test form
 * POST /api/push/test - Send test notification to specific user
 * GET /api/push/test/all - Send test notification to all users
 * 
 * Static Methods (for use by other servlets/schedulers):
 * - sendPushNotification() - Send notification to a specific subscription
 * - getAllSubscriptions() - Get all active subscriptions from database
 * - createPushService() - Create configured PushService instance
 */
public class PushNotificationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final String PROPERTIES_FILE = "/etc/acmedcm/conf/acmedcm.properties";
    private static final Gson gson = new Gson();

    static {
        try {
            Class.forName("com.ibm.as400.access.AS400JDBCDriver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("JDBC driver not found", e);
        }
    }

    @Override
    public void destroy() {
        SystemLogger.log("PushNotificationServlet shutting down");
        super.destroy();
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // CORS preflight handling is done by CORSFilter
        response.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if ("/all".equals(pathInfo)) {
            // Send test notification to all subscribed users
            sendTestToAll(request, response);
        } else {
            // Show test form
            showTestForm(request, response);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            // Parse request body
            String body = readBody(request);
            @SuppressWarnings("unchecked")
            Map<String, String> data = gson.fromJson(body, Map.class);

            String username = data.get("username");
            String title = data.getOrDefault("title", "Test Notification");
            String message = data.getOrDefault("body", "This is a test push notification");
            String endpoint = data.get("endpoint");

            if (username == null || username.trim().isEmpty()) {
                sendError(response, 400, "Username is required");
                return;
            }

            // Get user's subscriptions
            try (Connection conn = getConnection()) {

                List<PushSubscription> subscriptions;

                if (endpoint != null && !endpoint.trim().isEmpty()) {
                    PushSubscription sub = getSubscriptionByEndpoint(conn, username, endpoint);
                    subscriptions = new ArrayList<>();
                    if (sub != null) {
                        subscriptions.add(sub);
                    }
                } else {
                    subscriptions = getSubscriptions(conn, username);
                }

                if (subscriptions.isEmpty()) {
                    sendError(response, 404, "No active subscriptions found for user: " + username);
                    return;
                }

                // Send notification to all user's subscriptions
                int successCount = 0;
                int failCount = 0;
                List<String> errors = new ArrayList<>();

                for (PushSubscription sub : subscriptions) {
                    try {
                        sendTestPushNotification(sub.endpoint, sub.p256dhKey, sub.authKey, title, message);
                        successCount++;
                        logNotification(conn, sub.id, username, "test", title, message, "success", null);
                    } catch (Exception e) {
                        failCount++;
                        errors.add(e.getMessage());
                        logNotification(conn, sub.id, username, "test", title, message, "failed", e.getMessage());
                    }
                }

                // Return results
                Map<String, Object> result = new HashMap<>();
                result.put("username", username);
                result.put("subscriptions", subscriptions.size());
                result.put("success", successCount);
                result.put("failed", failCount);
                if (!errors.isEmpty()) {
                    result.put("errors", errors);
                }

                sendSuccess(response, result);
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
     * Send test notification to all subscribed users
     */
    private void sendTestToAll(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try (Connection conn = getConnection()) {

            List<PushSubscription> allSubscriptions = getAllSubscriptionsInternal(conn);

            if (allSubscriptions.isEmpty()) {
                sendError(response, 404, "No active subscriptions found");
                return;
            }

            String title = "Test Notification";
            String message = "This is a test notification sent to all users";

            int successCount = 0;
            int failCount = 0;
            Map<String, Integer> userResults = new HashMap<>();

            for (PushSubscription sub : allSubscriptions) {
                try {
                    sendTestPushNotification(sub.endpoint, sub.p256dhKey, sub.authKey, title, message);
                    successCount++;
                    userResults.put(sub.username, userResults.getOrDefault(sub.username, 0) + 1);
                    logNotification(conn, sub.id, sub.username, "test", title, message, "success", null);
                } catch (Exception e) {
                    failCount++;
                    logNotification(conn, sub.id, sub.username, "test", title, message, "failed", e.getMessage());
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("totalSubscriptions", allSubscriptions.size());
            result.put("success", successCount);
            result.put("failed", failCount);
            result.put("userResults", userResults);

            sendSuccess(response, result);

        } catch (SQLException e) {
            e.printStackTrace();
            sendError(response, 500, "Database error: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Server error: " + e.getMessage());
        }
    }

    /**
     * Show HTML test form
     */
    private void showTestForm(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html>\n<head>\n");
        html.append("<title>Push Notification Test</title>\n");
        html.append("<style>\n");
        html.append("body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }\n");
        html.append("h1 { color: #3f51b5; }\n");
        html.append(".form-group { margin-bottom: 15px; }\n");
        html.append("label { display: block; margin-bottom: 5px; font-weight: bold; }\n");
        html.append("input, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }\n");
        html.append(
                "button { background-color: #3f51b5; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }\n");
        html.append("button:hover { background-color: #303f9f; }\n");
        html.append(".result { margin-top: 20px; padding: 15px; border-radius: 4px; }\n");
        html.append(".success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }\n");
        html.append(".error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }\n");
        html.append(
                ".info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; padding: 15px; margin-bottom: 20px; border-radius: 4px; }\n");
        html.append("</style>\n");
        html.append("</head>\n<body>\n");

        html.append("<h1>🔔 Push Notification Test</h1>\n");

        html.append("<div class='info'>\n");
        html.append("<strong>Instructions:</strong><br>\n");
        html.append("1. Make sure you've enabled push notifications in Settings<br>\n");
        html.append("2. Enter your username below<br>\n");
        html.append("3. Customize the notification message<br>\n");
        html.append("4. Click 'Send Test Notification'<br>\n");
        html.append("5. You should receive a notification in your browser\n");
        html.append("</div>\n");

        html.append("<form id='testForm'>\n");
        html.append("<div class='form-group'>\n");
        html.append("<label for='username'>Username:</label>\n");
        html.append(
                "<input type='text' id='username' name='username' required placeholder='Enter your IBM i username'>\n");
        html.append("</div>\n");

        html.append("<div class='form-group'>\n");
        html.append("<label for='title'>Notification Title:</label>\n");
        html.append("<input type='text' id='title' name='title' value='Test Notification' required>\n");
        html.append("</div>\n");

        html.append("<div class='form-group'>\n");
        html.append("<label for='body'>Notification Message:</label>\n");
        html.append(
                "<textarea id='body' name='body' rows='3' required>This is a test push notification from IBM i</textarea>\n");
        html.append("</div>\n");

        html.append("<button type='submit'>Send Test Notification</button>\n");
        html.append("<button type='button' onclick='sendToAll()'>Send to All Users</button>\n");
        html.append("</form>\n");

        html.append("<div id='result'></div>\n");

        html.append("<script>\n");
        html.append("document.getElementById('testForm').addEventListener('submit', async (e) => {\n");
        html.append("  e.preventDefault();\n");
        html.append("  const formData = {\n");
        html.append("    username: document.getElementById('username').value,\n");
        html.append("    title: document.getElementById('title').value,\n");
        html.append("    body: document.getElementById('body').value\n");
        html.append("  };\n");
        html.append("  try {\n");
        html.append("    const response = await fetch('/acme_dcm/api/push/test', {\n");
        html.append("      method: 'POST',\n");
        html.append("      headers: { 'Content-Type': 'application/json' },\n");
        html.append("      body: JSON.stringify(formData)\n");
        html.append("    });\n");
        html.append("    const data = await response.json();\n");
        html.append("    showResult(data, response.ok);\n");
        html.append("  } catch (error) {\n");
        html.append("    showResult({ error: error.message }, false);\n");
        html.append("  }\n");
        html.append("});\n");

        html.append("async function sendToAll() {\n");
        html.append("  if (!confirm('Send test notification to ALL subscribed users?')) return;\n");
        html.append("  try {\n");
        html.append("    const response = await fetch('/acme_dcm/api/push/test/all');\n");
        html.append("    const data = await response.json();\n");
        html.append("    showResult(data, response.ok);\n");
        html.append("  } catch (error) {\n");
        html.append("    showResult({ error: error.message }, false);\n");
        html.append("  }\n");
        html.append("}\n");

        html.append("function showResult(data, success) {\n");
        html.append("  const resultDiv = document.getElementById('result');\n");
        html.append("  resultDiv.className = 'result ' + (success ? 'success' : 'error');\n");
        html.append("  resultDiv.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';\n");
        html.append("}\n");
        html.append("</script>\n");

        html.append("</body>\n</html>");

        response.getWriter().write(html.toString());
    }

    // ========================================================================
    // PUBLIC STATIC METHODS - For use by other servlets/schedulers
    // ========================================================================

    /**
     * Send push notification to a subscription with logging
     * PUBLIC STATIC METHOD - Can be called from other classes
     *
     * @param subscriptionId   Subscription ID for logging
     * @param username         Username for logging
     * @param endpoint         Subscription endpoint URL
     * @param p256dhKey        User's public key
     * @param authKey          Authentication secret
     * @param notificationType Type of notification (e.g., "expiration", "test")
     * @param title            Notification title
     * @param body             Notification body text
     * @param tag              Notification tag (for grouping/replacing)
     * @throws Exception if notification fails
     */
    public static void sendPushNotification(
            int subscriptionId,
            String username,
            String endpoint,
            String p256dhKey,
            String authKey,
            String notificationType,
            String title,
            String body,
            String tag) throws Exception {

        Exception thrownException = null;
        try {
            // Create notification payload
            Map<String, Object> payload = new HashMap<>();
            payload.put("title", title);
            payload.put("body", body);
            payload.put("icon", "/favicon.ico");
            payload.put("badge", "/favicon.ico");
            payload.put("tag", tag != null ? tag : "notification-" + System.currentTimeMillis());
            payload.put("timestamp", System.currentTimeMillis());

            Map<String, Object> data = new HashMap<>();
            data.put("url", "/dashboard");
            payload.put("data", data);

            String payloadJson = gson.toJson(payload);

            // Create notification with endpoint, user public key, auth, and payload
            Notification notification = new Notification(endpoint, p256dhKey, authKey, payloadJson);

            // Create and use push service
            PushService pushService = createPushService();

            // Send notification
            HttpResponse httpResponse;
            try {
                httpResponse = pushService.send(notification);
            } catch (JoseException e) {
                throw new IOException("Push send failed: " + e.getMessage(), e);
            }

            if (httpResponse == null) {
                throw new IOException("Push send failed: no HTTP response returned");
            }

            int statusCode = httpResponse.getStatusLine().getStatusCode();

            SystemLogger.log("Push notification response status: " + statusCode);

            if (statusCode != 201) {
                String responseBody = httpResponse.getEntity() != null
                        ? EntityUtils.toString(httpResponse.getEntity())
                        : "";
                SystemLogger.logError("Push error response: " + responseBody);
            }

            if (statusCode < 200 || statusCode >= 300) {
                throw new IOException("Push notification failed with status: " + statusCode);
            }

            // Log successful notification
            logNotificationStatic(subscriptionId, username, notificationType, title, body, "success", null);

        } catch (Exception e) {
            thrownException = e;
            // Log failed notification
            logNotificationStatic(subscriptionId, username, notificationType, title, body, "failed", e.getMessage());
            throw e;
        }
    }

    /**
     * Send test push notification (simplified method for testing)
     * PUBLIC STATIC METHOD - For test endpoints only
     *
     * @param endpoint  Subscription endpoint URL
     * @param p256dhKey User's public key
     * @param authKey   Authentication secret
     * @param title     Notification title
     * @param body      Notification body text
     * @throws Exception if notification fails
     */
    public static void sendTestPushNotification(
            String endpoint,
            String p256dhKey,
            String authKey,
            String title,
            String body) throws Exception {

        // Create notification payload
        Map<String, Object> payload = new HashMap<>();
        payload.put("title", title);
        payload.put("body", body);
        payload.put("icon", "/favicon.ico");
        payload.put("badge", "/favicon.ico");
        payload.put("tag", "test-" + System.currentTimeMillis());
        payload.put("timestamp", System.currentTimeMillis());

        Map<String, Object> data = new HashMap<>();
        data.put("url", "/dashboard");
        payload.put("data", data);

        String payloadJson = gson.toJson(payload);

        // Create notification with endpoint, user public key, auth, and payload
        Notification notification = new Notification(endpoint, p256dhKey, authKey, payloadJson);

        // Create and use push service
        PushService pushService = createPushService();

        // Send notification
        HttpResponse httpResponse;
        try {
            httpResponse = pushService.send(notification);
        } catch (JoseException e) {
            throw new IOException("Push send failed: " + e.getMessage(), e);
        }

        if (httpResponse == null) {
            throw new IOException("Push send failed: no HTTP response returned");
        }

        int statusCode = httpResponse.getStatusLine().getStatusCode();

        SystemLogger.log("Push notification response status: " + statusCode);

        if (statusCode != 201) {
            String responseBody = httpResponse.getEntity() != null
                    ? EntityUtils.toString(httpResponse.getEntity())
                    : "";
            SystemLogger.logError("Push error response: " + responseBody);
        }

        if (statusCode < 200 || statusCode >= 300) {
            throw new IOException("Push notification failed with status: " + statusCode);
        }
    }

    /**
     * Get all active push subscriptions from database
     * PUBLIC STATIC METHOD - Can be called from other classes
     * 
     * @return List of subscription data
     * @throws SQLException if database error occurs
     */
    public static List<PushSubscriptionData> getAllSubscriptions() throws SQLException {
        List<PushSubscriptionData> subscriptions = new ArrayList<>();

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
            props.load(fis);
        } catch (IOException e) {
            throw new SQLException("Failed to load properties", e);
        }

        String os400IP = props.getProperty("os400IP", "localhost");
        String os400User = props.getProperty("os400User");
        String os400PW = props.getProperty("os400PW");

        String jdbcUrl = "jdbc:as400://" + os400IP + "/ACMEDCM";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, os400User, os400PW)) {
            String sql = "SELECT ID, USRPRF, ENDPOINT, P256DH_KEY, AUTH_KEY FROM ACMEDCM.PUSH_SUBSCRIPTIONS WHERE ENABLED = 'Y'";

            try (PreparedStatement stmt = conn.prepareStatement(sql);
                    ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    PushSubscriptionData sub = new PushSubscriptionData();
                    sub.id = rs.getInt("ID");
                    sub.username = rs.getString("USRPRF");
                    sub.endpoint = rs.getString("ENDPOINT");
                    sub.p256dhKey = rs.getString("P256DH_KEY");
                    sub.authKey = rs.getString("AUTH_KEY");
                    subscriptions.add(sub);
                }
            }
        }

        return subscriptions;
    }

    /**
     * Create configured PushService instance
     * PUBLIC STATIC METHOD - Can be called from other classes
     * 
     * @return Configured PushService
     * @throws IOException              if properties cannot be loaded
     * @throws GeneralSecurityException if VAPID keys are invalid
     */
    public static PushService createPushService() throws IOException, GeneralSecurityException {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
            props.load(fis);
        }

        String publicKey = props.getProperty("vapid.publicKey");
        String privateKey = props.getProperty("vapid.privateKey");
        String subject = props.getProperty("vapid.subject", "mailto:admin@example.com");

        if (publicKey == null || privateKey == null) {
            throw new IOException("VAPID keys not configured in " + PROPERTIES_FILE);
        }

        PushService service = new PushService();
        service.setPublicKey(publicKey);
        service.setPrivateKey(privateKey);
        service.setSubject(subject);

        return service;
    }

    /**
     * Static method to log notification to database
     * PUBLIC STATIC METHOD - Can be called from other classes
     */
    private static void logNotificationStatic(int subscriptionId, String username, String type, String title,
            String message, String status, String errorMsg) {

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
            props.load(fis);
        } catch (IOException e) {
            SystemLogger.logError("Failed to load properties for logging: " + e.getMessage());
            return;
        }

        String os400IP = props.getProperty("os400IP", "localhost");
        String os400User = props.getProperty("os400User");
        String os400PW = props.getProperty("os400PW");

        String jdbcUrl = "jdbc:as400://" + os400IP + "/ACMEDCM";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, os400User, os400PW)) {
            String sql = "INSERT INTO NOTIFICATION_LOG (USRPRF, SUBSCRIPTION_ID, TYPE, TITLE, BODY, STATUS, ERROR_MESSAGE) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)";

            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, username);
                pstmt.setInt(2, subscriptionId);
                pstmt.setString(3, type);
                pstmt.setString(4, title);
                pstmt.setString(5, message);
                pstmt.setString(6, status);
                pstmt.setString(7, errorMsg);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            SystemLogger.logError("Failed to log notification: " + e.getMessage());
        }
    }

    // ========================================================================
    // PRIVATE INSTANCE METHODS - For servlet HTTP handling
    // ========================================================================

    /**
     * Get subscriptions for a specific user
     */
    private List<PushSubscription> getSubscriptions(Connection conn, String username) throws SQLException {
        List<PushSubscription> subscriptions = new ArrayList<>();

        String sql = "SELECT ID, USRPRF, ENDPOINT, P256DH_KEY, AUTH_KEY FROM PUSH_SUBSCRIPTIONS " +
                "WHERE USRPRF = ? AND ENABLED = 'Y'";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username.toUpperCase());
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    PushSubscription sub = new PushSubscription();
                    sub.id = rs.getInt("ID");
                    sub.username = rs.getString("USRPRF");
                    sub.endpoint = rs.getString("ENDPOINT");
                    sub.p256dhKey = rs.getString("P256DH_KEY");
                    sub.authKey = rs.getString("AUTH_KEY");
                    subscriptions.add(sub);
                }
            }
        }

        return subscriptions;
    }

    /**
     * Get all active subscriptions (instance method)
     */
    private List<PushSubscription> getAllSubscriptionsInternal(Connection conn) throws SQLException {
        List<PushSubscription> subscriptions = new ArrayList<>();

        String sql = "SELECT ID, USRPRF, ENDPOINT, P256DH_KEY, AUTH_KEY FROM PUSH_SUBSCRIPTIONS " +
                "WHERE ENABLED = 'Y'";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    PushSubscription sub = new PushSubscription();
                    sub.id = rs.getInt("ID");
                    sub.username = rs.getString("USRPRF");
                    sub.endpoint = rs.getString("ENDPOINT");
                    sub.p256dhKey = rs.getString("P256DH_KEY");
                    sub.authKey = rs.getString("AUTH_KEY");
                    subscriptions.add(sub);
                }
            }
        }

        return subscriptions;
    }

    /**
     * Log notification to database
     */
    private void logNotification(Connection conn, int subscriptionId, String username, String type, String title,
            String message, String status, String errorMsg) {
        String sql = "INSERT INTO NOTIFICATION_LOG (USRPRF, SUBSCRIPTION_ID, TYPE, TITLE, BODY, STATUS, ERROR_MESSAGE) "
                +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setInt(2, subscriptionId);
            pstmt.setString(3, type);
            pstmt.setString(4, title);
            pstmt.setString(5, message);
            pstmt.setString(6, status);
            pstmt.setString(7, errorMsg);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            SystemLogger.logError("Failed to log notification: " + e.getMessage());
        }
    }

    private PushSubscription getSubscriptionByEndpoint(Connection conn, String username, String endpoint)
            throws SQLException {
        String sql = "SELECT ID, USRPRF, ENDPOINT, P256DH_KEY, AUTH_KEY " +
                "FROM PUSH_SUBSCRIPTIONS " +
                "WHERE USRPRF = ? AND ENDPOINT = ? AND ENABLED = 'Y'";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username.toUpperCase());
            pstmt.setString(2, endpoint);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    PushSubscription sub = new PushSubscription();
                    sub.id = rs.getInt("ID");
                    sub.username = rs.getString("USRPRF");
                    sub.endpoint = rs.getString("ENDPOINT");
                    sub.p256dhKey = rs.getString("P256DH_KEY");
                    sub.authKey = rs.getString("AUTH_KEY");
                    return sub;
                }
            }
        }

        return null;
    }

    /**
     * Get database connection
     */
    private Connection getConnection() throws SQLException {
        try {
            // Load connection properties
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
                props.load(fis);
            }

            String host = props.getProperty("os400IP", "localhost");
            String user = props.getProperty("os400User");
            String password = props.getProperty("os400PW");

            String url = "jdbc:as400://" + host + "/ACMEDCM";
            Connection conn = DriverManager.getConnection(url, user, password);

            // Set schema
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("SET SCHEMA ACMEDCM");
            }

            return conn;

        } catch (IOException e) {
            throw new SQLException("Failed to load connection properties", e);
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
    private void sendError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("error", message);
        response.getWriter().write(gson.toJson(error));
    }

    // ========================================================================
    // DATA CLASSES
    // ========================================================================

    /**
     * Push subscription data class (for internal servlet use)
     */
    private static class PushSubscription {
        int id;
        String username;
        String endpoint;
        String p256dhKey;
        String authKey;
    }

    /**
     * Push subscription data class (for external use by other classes)
     * PUBLIC - Can be used by other servlets/schedulers
     */
    public static class PushSubscriptionData {
        public int id;
        public String username;
        public String endpoint;
        public String p256dhKey;
        public String authKey;
    }
}

// Made with Bob

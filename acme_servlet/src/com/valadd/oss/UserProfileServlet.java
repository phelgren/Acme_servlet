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
import com.ibm.as400.access.User;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * User Profile Management Servlet
 * GET /api/user/profile - Get user profile (name from IBM i + email/phone from
 * extension)
 * PUT /api/user/profile - Update user profile (email/phone only)
 * 
 * Note: Full name comes from IBM i user profile TEXT field (read-only)
 * Email and phone are stored in USER_PROFILE_EXT table (editable)
 */
public class UserProfileServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    // Email validation pattern (RFC 5322 simplified)
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$");

    // Phone validation pattern (allows various formats)
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "^[+]?[(]?[0-9]{1,4}[)]?[-\\s\\.]?[(]?[0-9]{1,4}[)]?[-\\s\\.]?[0-9]{1,9}$");

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

        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                sendError(response, 401, "No session found");
                return;
            }

            String username = (String) session.getAttribute("username");
            AS400 as400 = (AS400) session.getAttribute("as400");

            if (username == null || as400 == null) {
                sendError(response, 401, "User not authenticated");
                return;
            }

            // Get user profile data
            UserProfile profile = getUserProfile(as400, username);

            if (profile == null) {
                sendError(response, 404, "User profile not found");
                return;
            }

            sendSuccess(response, profile);

        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Error retrieving user profile: " + e.getMessage());
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                sendError(response, 401, "No session found");
                return;
            }

            String username = (String) session.getAttribute("username");
            AS400 as400 = (AS400) session.getAttribute("as400");

            if (username == null || as400 == null) {
                sendError(response, 401, "User not authenticated");
                return;
            }

            // Read and parse request body
            String body = readBody(request);
            @SuppressWarnings("unchecked")
            Map<String, Object> profileData = gson.fromJson(body, Map.class);

            String email = profileData.get("email") != null ? profileData.get("email").toString() : null;
            String phone = profileData.get("phone") != null ? profileData.get("phone").toString() : null;

            // Validate email if provided
            if (email != null && !email.trim().isEmpty()) {
                if (!EMAIL_PATTERN.matcher(email.trim()).matches()) {
                    sendError(response, 400, "Invalid email format");
                    return;
                }
            }

            // Validate phone if provided
            if (phone != null && !phone.trim().isEmpty()) {
                if (!PHONE_PATTERN.matcher(phone.trim()).matches()) {
                    sendError(response, 400, "Invalid phone number format");
                    return;
                }
            }

            // Update profile extension
            updateUserProfileExtension(as400, username, email, phone);

            // Return updated profile
            UserProfile updatedProfile = getUserProfile(as400, username);
            sendSuccess(response, updatedProfile);

        } catch (SQLException e) {
            e.printStackTrace();
            sendError(response, 500, "Database error: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Error updating user profile: " + e.getMessage());
        }
    }

    /**
     * Get complete user profile (name from IBM i + email/phone from extension)
     */
    private UserProfile getUserProfile(AS400 as400, String username) throws Exception {
        UserProfile profile = new UserProfile();
        profile.setUsername(username);

        // Get full name from IBM i user profile TEXT field
        try {
            User user = new User(as400, username);
            String fullName = user.getDescription();
            profile.setFullName(fullName != null ? fullName.trim() : username);
        } catch (Exception e) {
            SystemLogger.logError("Warning: Could not retrieve user description: " + e.getMessage());
            profile.setFullName(username); // Fallback to username
        }

        // Get email and phone from extension table

        try (Connection conn = getConnection(as400)) {

            String sql = "SELECT EMAIL, PHONE FROM USER_PROFILE_EXT WHERE USRPRF = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, username);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        profile.setEmail(rs.getString("EMAIL"));
                        profile.setPhone(rs.getString("PHONE"));
                    } else {
                        // No extension record exists yet - create one
                        createUserProfileExtension(conn, username);
                        profile.setEmail("");
                        profile.setPhone("");
                    }
                }
            }
        } catch (SQLException e) {
            SystemLogger.logError("Error closing connection: " + e.getMessage());
        }

        return profile;
    }

    /**
     * Create initial user profile extension record
     */
    private void createUserProfileExtension(Connection conn, String username) throws SQLException {
        String sql = "INSERT INTO USER_PROFILE_EXT (USRPRF, EMAIL, PHONE, UPDATED_BY) " +
                "VALUES (?, '', '', ?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, username);
            pstmt.executeUpdate();
            SystemLogger.log("Created profile extension for user: " + username);
        }
    }

    /**
     * Update user profile extension (email and phone only)
     */
    private void updateUserProfileExtension(AS400 as400, String username, String email, String phone)
            throws SQLException {

        try (Connection conn = getConnection(as400)) {

            // Check if record exists
            String checkSql = "SELECT USRPRF FROM USER_PROFILE_EXT WHERE USRPRF = ?";
            boolean exists = false;

            try (PreparedStatement pstmt = conn.prepareStatement(checkSql)) {
                pstmt.setString(1, username);
                try (ResultSet rs = pstmt.executeQuery()) {
                    exists = rs.next();
                }
            }

            if (exists) {
                // Build dynamic update SQL based on what fields are provided
                StringBuilder updateSql = new StringBuilder("UPDATE USER_PROFILE_EXT SET ");
                List<Object> params = new ArrayList<>();
                boolean first = true;

                if (email != null) {
                    updateSql.append("EMAIL = ?");
                    params.add(email.trim());
                    first = false;
                }

                if (phone != null) {
                    if (!first)
                        updateSql.append(", ");
                    updateSql.append("PHONE = ?");
                    params.add(phone.trim());
                    first = false;
                }

                if (!first)
                    updateSql.append(", ");
                updateSql.append("UPDATED_BY = ? WHERE USRPRF = ?");
                params.add(username);
                params.add(username);

                try (PreparedStatement pstmt = conn.prepareStatement(updateSql.toString())) {
                    for (int i = 0; i < params.size(); i++) {
                        pstmt.setObject(i + 1, params.get(i));
                    }
                    pstmt.executeUpdate();
                    SystemLogger.log("Updated profile extension for user: " + username);
                }
            } else {
                // Insert new record
                String insertSql = "INSERT INTO USER_PROFILE_EXT (USRPRF, EMAIL, PHONE, UPDATED_BY) " +
                        "VALUES (?, ?, ?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                    pstmt.setString(1, username);
                    pstmt.setString(2, email != null ? email.trim() : "");
                    pstmt.setString(3, phone != null ? phone.trim() : "");
                    pstmt.setString(4, username);
                    pstmt.executeUpdate();
                    SystemLogger.log("Created profile extension for user: " + username);
                }
            }

        } catch (SQLException e) {
            SystemLogger.logError("Error closing connection: " + e.getMessage());
        }
    }

    /**
     * Get database connection using authenticated user's AS400 object
     */
    private Connection getConnection(AS400 as400) throws SQLException {
        try {
            com.ibm.as400.access.AS400JDBCDriver driver = new com.ibm.as400.access.AS400JDBCDriver();
            Connection conn = driver.connect(as400);

            // Set the default schema to ACMEDCM
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("SET SCHEMA ACMEDCM");
            } catch (SQLException e) {
                System.err.println("Warning: Could not set schema to ACMEDCM: " + e.getMessage());
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

    /**
     * User Profile data class
     */
    public static class UserProfile {
        private String username;
        private String fullName; // From IBM i TEXT field (read-only)
        private String email; // From extension table (editable)
        private String phone; // From extension table (editable)

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getFullName() {
            return fullName;
        }

        public void setFullName(String fullName) {
            this.fullName = fullName;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPhone() {
            return phone;
        }

        public void setPhone(String phone) {
            this.phone = phone;
        }
    }
}
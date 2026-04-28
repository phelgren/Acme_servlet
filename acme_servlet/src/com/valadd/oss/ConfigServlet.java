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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Simple CRUD servlet for ACME configurations
 * GET /api/acme - Get all
 * GET /api/acme/{id} - Get one
 * POST /api/acme - Create
 * PUT /api/acme/{id} - Update
 * DELETE /api/acme/{id} - Delete
 *
 * Note: Servlet mapping is configured in web.xml
 */
public class ConfigServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final String DB_URL_TEMPLATE = "jdbc:as400://localhost/ACMEDCM;naming=system;libraries=ACMEDCM";
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

        // Prevent caching of configuration data
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");

        String pathInfo = request.getPathInfo();

        // Get AS400 connection from session
        try (Connection conn = getConnection(request)) {

            if (pathInfo == null || "/".equals(pathInfo)) {
                // Get all configs
                List<ACMEConfig> configs = getAllConfigs(conn);
                sendSuccess(response, configs);
            } else {
                // Get one config
                String id = pathInfo.substring(1);
                ACMEConfig config = getConfigById(conn, id);
                if (config != null) {
                    sendSuccess(response, config);
                } else {
                    sendError(response, 404, "Configuration not found");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); // Log to console
            sendError(response, 500, "Database error: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace(); // Log to console
            sendError(response, 500, "Server error: " + e.getMessage());
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try (Connection conn = getConnection(request)) {

            String body = readBody(request);
            ACMEConfig config = gson.fromJson(body, ACMEConfig.class);

            config.setId(UUID.randomUUID().toString());

            // Set user ID from authenticated user
            String username = (String) request.getAttribute("username");
            config.setUserId(username);

            createConfig(conn, config);

            response.setStatus(201);
            sendSuccess(response, config);

        } catch (SQLException e) {
            sendError(response, 500, "Database error: " + e.getMessage());
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String pathInfo = request.getPathInfo();
        if (pathInfo == null || "/".equals(pathInfo)) {
            sendError(response, 400, "ID is required");
            return;
        }

        try (Connection conn = getConnection(request)) {

            String id = pathInfo.substring(1);
            String body = readBody(request);
            ACMEConfig config = gson.fromJson(body, ACMEConfig.class);
            config.setId(id);

            // Set user ID from authenticated user
            String username = (String) request.getAttribute("username");
            config.setUserId(username);

            updateConfig(conn, config);
            sendSuccess(response, config);

        } catch (SQLException e) {
            sendError(response, 500, "Database error: " + e.getMessage());
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String pathInfo = request.getPathInfo();
        if (pathInfo == null || "/".equals(pathInfo)) {
            sendError(response, 400, "ID is required");
            return;
        }

        try (Connection conn = getConnection(request)) {

            String id = pathInfo.substring(1);
            deleteConfig(conn, id);

            Map<String, Object> result = new HashMap<>();
            result.put("message", "Configuration deleted");
            sendSuccess(response, result);

        } catch (SQLException e) {
            sendError(response, 500, "Database error: " + e.getMessage());
        }
    }

    // Get database connection using authenticated user's AS400 object from session
    private Connection getConnection(HttpServletRequest request) throws SQLException {
        HttpSession session = request.getSession(false);

        if (session == null) {
            SystemLogger.logError("ERROR: No session found");
            throw new SQLException("No session found - user not authenticated");
        }

        AS400 as400 = (AS400) session.getAttribute("as400");

        if (as400 == null) {
            SystemLogger.logError("ERROR: No AS400 object in session");
            SystemLogger.logError("Session ID: " + session.getId());
            SystemLogger.logError("Session attributes: " + java.util.Collections.list(session.getAttributeNames()));
            throw new SQLException("No authenticated AS400 connection in session");
        }

        // Build connection URL with user credentials from AS400 object
        String username = as400.getUserId();
        SystemLogger.log("Creating connection for user: " + username);

        // Use AS400JDBCConnectionPoolDataSource or direct connection
        // The AS400 object maintains the authentication, so we can use it directly
        try {
            SystemLogger.log("Creating connection for user: " + username + " on system: " + as400.getSystemName());

            // Use the AS400 object to create a connection - it will use stored credentials
            // Pass the AS400 object directly without URL or properties to avoid library
            // list issues
            com.ibm.as400.access.AS400JDBCDriver driver = new com.ibm.as400.access.AS400JDBCDriver();
            Connection conn = driver.connect(as400);
            SystemLogger.log("Connection created successfully");

            // Set the default schema to ACMEDCM so we don't need to qualify table names
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("SET SCHEMA ACMEDCM");
                SystemLogger.log("Schema set to ACMEDCM");
            } catch (SQLException e) {
                SystemLogger.logError("Warning: Could not set schema to ACMEDCM: " + e.getMessage());
                // Continue anyway - table names might need to be qualified
            }

            return conn;

        } catch (Exception e) {
            SystemLogger.logError("ERROR creating connection: " + e.getMessage(), e);
            throw new SQLException("Failed to create database connection: " + e.getMessage(), e);
        }
    }

    // Database operations

    private List<ACMEConfig> getAllConfigs(Connection conn) throws SQLException {
        List<ACMEConfig> configs = new ArrayList<>();
        String sql = "SELECT * FROM ACME_CONFIGS ORDER BY CREATED_AT DESC";

        try (Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                configs.add(mapResultSet(rs));
            }
        }
        return configs;
    }

    private ACMEConfig getConfigById(Connection conn, String id) throws SQLException {
        String sql = "SELECT * FROM ACME_CONFIGS WHERE ID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSet(rs);
                }
            }
        }
        return null;
    }

    private void createConfig(Connection conn, ACMEConfig config) throws SQLException {
        String sql = "INSERT INTO ACME_CONFIGS " +
                "(ID, NAME, CHALLENGE_TYPE, TIMEOUT, REQUEST_TYPE, DOMAIN, " +
                "ACCOUNT_KEY, CSR, WELL_KNOWN_DIR, CERTIFICATE_PATH, WRK_FOLDER, " +
                "DNS_TXT_RECORD, USER_ID) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, config.getId());
            pstmt.setString(2, config.getName());
            pstmt.setString(3, config.getChallengeType());
            pstmt.setInt(4, config.getTimeout());
            pstmt.setString(5, config.getRequestType());
            pstmt.setString(6, config.getDomain());
            pstmt.setString(7, config.getAccountKey());
            pstmt.setString(8, config.getCsr());
            pstmt.setString(9, config.getWellKnownDir());
            pstmt.setString(10, config.getCertificatePath());
            pstmt.setString(11, config.getWrkFolder());
            pstmt.setString(12, config.getDnsTxtRecord());
            pstmt.setString(13, config.getUserId());

            pstmt.executeUpdate();
        }
    }

    private void updateConfig(Connection conn, ACMEConfig config) throws SQLException {
        String sql = "UPDATE ACME_CONFIGS SET " +
                "NAME = ?, CHALLENGE_TYPE = ?, TIMEOUT = ?, REQUEST_TYPE = ?, " +
                "DOMAIN = ?, ACCOUNT_KEY = ?, CSR = ?, WELL_KNOWN_DIR = ?, " +
                "CERTIFICATE_PATH = ?, WRK_FOLDER = ?, DNS_TXT_RECORD = ?, USER_ID = ? " +
                "WHERE ID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, config.getName());
            pstmt.setString(2, config.getChallengeType());
            pstmt.setInt(3, config.getTimeout());
            pstmt.setString(4, config.getRequestType());
            pstmt.setString(5, config.getDomain());
            pstmt.setString(6, config.getAccountKey());
            pstmt.setString(7, config.getCsr());
            pstmt.setString(8, config.getWellKnownDir());
            pstmt.setString(9, config.getCertificatePath());
            pstmt.setString(10, config.getWrkFolder());
            pstmt.setString(11, config.getDnsTxtRecord());
            pstmt.setString(12, config.getUserId());
            pstmt.setString(13, config.getId());

            pstmt.executeUpdate();
        }
    }

    private void deleteConfig(Connection conn, String id) throws SQLException {
        String sql = "DELETE FROM ACME_CONFIGS WHERE ID = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, id);
            pstmt.executeUpdate();
        }
    }

    private ACMEConfig mapResultSet(ResultSet rs) throws SQLException {
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
        config.setUserId(rs.getString("USER_ID"));
        config.setCreatedAt(rs.getTimestamp("CREATED_AT"));
        config.setUpdatedAt(rs.getTimestamp("UPDATED_AT"));
        return config;
    }

    private String readBody(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = request.getReader();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    private void sendSuccess(HttpServletResponse response, Object data) throws IOException {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("data", data);
        response.getWriter().write(gson.toJson(result));
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
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
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Simple authentication servlet - IBM i login + JWT
 * POST /api/auth/login - Login with IBM i credentials
 */

public class AuthServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
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
            @SuppressWarnings("unchecked")
            Map<String, String> loginData = gson.fromJson(sb.toString(), Map.class);
            String username = loginData.get("username");
            if (username == null) {
                username = loginData.get("email"); // Backward compatibility
            }
            String password = loginData.get("password");

            // Validate input
            if (username == null || username.trim().isEmpty() ||
                    password == null || password.isEmpty()) {
                sendError(response, 400, "Username and password are required");
                return;
            }

            // Authenticate with IBM i
            username = username.toUpperCase();
            AS400 system = null;
            try {
                String host = getOSIP();
                system = new AS400(host, username, password);
                system.connectService(AS400.SIGNON);

                // Check user authorities for security features
                boolean hasSecurityAccess = checkUserAuthorities(system, username);

                // Register the connection for tracking
                AS400ConnectionCleanupListener.registerConnection(system);

                // Authentication successful - store AS400 object and authorities in session
                request.getSession().setAttribute("as400", system);
                request.getSession().setAttribute("username", username);
                request.getSession().setAttribute("hasSecurityAccess", hasSecurityAccess);

                // Generate JWT token
                String token = JWTUtil.generateToken(username);

                // Build user object
                Map<String, Object> user = new HashMap<>();
                user.put("id", username);
                user.put("email", username); // For compatibility
                user.put("username", username);
                user.put("name", username);
                user.put("role", "USER");
                user.put("hasSecurityAccess", hasSecurityAccess);

                // Build data object
                Map<String, Object> data = new HashMap<>();
                data.put("user", user);
                data.put("token", token);

                // Build response wrapper
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("message", "Login successful");
                responseData.put("data", data);

                response.getWriter().write(gson.toJson(responseData));

            } catch (Exception e) {
                sendError(response, 401, "Invalid credentials");
                // Don't disconnect on error - let it be garbage collected
                if (system != null) {
                    try {
                        system.disconnectAllServices();
                    } catch (Exception ignored) {
                    }
                }
            }

        } catch (Exception e) {
            sendError(response, 500, "Login failed: " + e.getMessage());
        }
    }

    /**
     * Check if user has security access based on IBM i authorities
     * Returns true if user has QSECOFR class OR *SECADM or *ALLOBJ special
     * authority
     */
    private boolean checkUserAuthorities(AS400 system, String username) {
        try {
            User user = new User(system, username);

            // Check user class
            String userClass = user.getUserClassName();
            if ("*SECOFR".equalsIgnoreCase(userClass) || "QSECOFR".equalsIgnoreCase(userClass)) {
                SystemLogger.log("User " + username + " has QSECOFR class - granting security access");
                return true;
            }

            // Check special authorities
            String[] specialAuthorities = user.getSpecialAuthority();
            if (specialAuthorities != null) {
                for (String authority : specialAuthorities) {
                    if ("*SECADM".equalsIgnoreCase(authority) || "*ALLOBJ".equalsIgnoreCase(authority)) {
                        SystemLogger.log(
                                "User " + username + " has " + authority + " authority - granting security access");
                        return true;
                    }
                }
            }

            SystemLogger.log("User " + username + " does not have security access");
            return false;

        } catch (Exception e) {
            SystemLogger.logError("Error checking user authorities for " + username + ": " + e.getMessage(), e);
            // Default to no access on error
            return false;
        }
    }

    private void sendError(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("error", message);
        response.getWriter().write(gson.toJson(error));
    }

    private static String getOSIP() {

        // we'll need to pull properties from the conf folder so we have the secret and
        // key
        // for GoDaddy API call

        boolean success = false;

        FileInputStream fis = null;

        Properties prop = null;

        try {

            fis = new FileInputStream("/etc/acmedcm/conf/acmedcm.properties");

            prop = new Properties();

            prop.load(fis);

            success = true;

        } catch (FileNotFoundException fnfe) {

            fnfe.printStackTrace();

        } catch (IOException ioe) {

            ioe.printStackTrace();

        } finally {

            try {
                fis.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        // If we were successful in getting what we need, continue
        String osIP = "";
        if (success) {
            osIP = prop.getProperty("os400IP");

        }

        return osIP;
    }
}
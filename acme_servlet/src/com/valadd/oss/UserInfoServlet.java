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

import com.ibm.as400.access.AS400;
import com.ibm.as400.access.User;
import com.google.gson.Gson;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Servlet to provide user information including security access
 * GET /api/user/info - Get current user info
 */
public class UserInfoServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

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
            Boolean hasSecurityAccess = (Boolean) session.getAttribute("hasSecurityAccess");

            if (username == null) {
                sendError(response, 401, "User not authenticated");
                return;
            }

            // Get full name from IBM i user profile TEXT field
            String fullName = username; // Default to username
            if (as400 != null) {
                try {
                    User user = new User(as400, username);
                    String description = user.getDescription();
                    if (description != null && !description.trim().isEmpty()) {
                        fullName = description.trim();
                    }
                } catch (Exception e) {
                    SystemLogger.logError("Warning: Could not retrieve user description: " + e.getMessage());
                    // Continue with username as fallback
                }
            }

            // Build user object
            Map<String, Object> user = new HashMap<>();
            user.put("id", username);
            user.put("email", username);
            user.put("username", username);
            user.put("name", fullName); // Using full name from IBM i TEXT field
            user.put("role", "USER");
            user.put("hasSecurityAccess", hasSecurityAccess != null ? hasSecurityAccess : false);

            // Build response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("data", user);

            response.getWriter().write(gson.toJson(responseData));

        } catch (Exception e) {
            sendError(response, 500, "Error retrieving user info: " + e.getMessage());
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
}
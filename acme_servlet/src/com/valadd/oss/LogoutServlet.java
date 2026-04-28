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
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Logout servlet that properly cleans up AS400 connections
 * POST /api/auth/logout - Logout and cleanup
 */
public class LogoutServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            HttpSession session = request.getSession(false);

            if (session != null) {
                // Get AS400 connection before invalidating session
                AS400 as400 = (AS400) session.getAttribute("as400");

                // Disconnect AS400 connection
                if (as400 != null) {
                    try {
                        SystemLogger.log("Logging out user: " + as400.getUserId());

                        // Unregister from tracking before disconnecting
                        AS400ConnectionCleanupListener.unregisterConnection(as400);

                        as400.disconnectAllServices();
                        SystemLogger.log("AS400 connection disconnected");
                    } catch (Exception e) {
                        SystemLogger.logError("Error disconnecting AS400: " + e.getMessage());
                    }
                }

                // Invalidate session
                session.invalidate();
            }

            // Send success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("message", "Logged out successfully");

            response.getWriter().write(gson.toJson(responseData));

        } catch (Exception e) {
            sendError(response, 500, "Logout failed: " + e.getMessage());
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
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
import com.ibm.as400.access.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.util.*;

/**
 * Servlet to list certificates from IBM i DCM certificate store
 * POST /api/certificates - Get certificates (store and password in request
 * body)
 * Body: { "store": "*SYSTEM", "password": "*NONE" }
 *
 * Note: Changed from GET to POST to avoid passing passwords in URL query
 * parameters
 */
public class CertificateListServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            // Read JSON body
            StringBuilder sb = new StringBuilder();
            String line;
            try (BufferedReader reader = request.getReader()) {
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }

            // Parse JSON to get store and password
            String storeName = "*SYSTEM";
            String storePassword = "*NONE";

            if (sb.length() > 0) {
                @SuppressWarnings("unchecked")
                Map<String, String> body = gson.fromJson(sb.toString(), Map.class);
                if (body != null) {
                    if (body.containsKey("store") && body.get("store") != null) {
                        storeName = body.get("store");
                    }
                    if (body.containsKey("password") && body.get("password") != null) {
                        storePassword = body.get("password");
                    }
                }
            }

            // Get AS400 connection from session
            HttpSession session = request.getSession(false);
            if (session == null) {
                sendError(response, 401, "No session found");
                return;
            }

            AS400 as400 = (AS400) session.getAttribute("as400");
            if (as400 == null) {
                sendError(response, 401, "No AS400 connection in session");
                return;
            }

            // Check if user has security access
            Boolean hasSecurityAccess = (Boolean) session.getAttribute("hasSecurityAccess");
            if (hasSecurityAccess == null || !hasSecurityAccess) {
                // Get username from session for the message
                String username = as400.getUserId();

                // Send user-friendly response instead of error
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", false);
                responseData.put("message", "User " + username + " does not have security access");
                responseData.put("data", new ArrayList<>());
                responseData.put("store", storeName);
                responseData.put("count", 0);

                response.getWriter().write(gson.toJson(responseData));
                return;
            }

            // Use CertificateUtils to get certificate list
            List<CertificateUtils.CertInfo> certInfoList = CertificateUtils.getCertificates(as400, storeName,
                    storePassword);

            // Convert to Map format for JSON response
            List<Map<String, Object>> certificates = new ArrayList<>();
            for (CertificateUtils.CertInfo certInfo : certInfoList) {
                certificates.add(certInfo.toMap());
            }

            // Send success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("data", certificates);
            responseData.put("store", storeName);
            responseData.put("count", certificates.size());

            response.getWriter().write(gson.toJson(responseData));

        } catch (Exception e) {
            e.printStackTrace();
            sendError(response, 500, "Error listing certificates: " + e.getMessage());
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
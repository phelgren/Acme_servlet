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

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Simple JWT authentication filter with session timeout handling
 * Note: Filter mapping is configured in web.xml
 */
public class AuthFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Skip OPTIONS requests (CORS preflight)
        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        // Get Authorization header
        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendError(httpResponse, 401, "No token provided");
            return;
        }

        // Validate token
        String token = authHeader.substring(7);
        String username = JWTUtil.validateToken(token);

        if (username == null) {
            sendError(httpResponse, 401, "Invalid or expired token");
            return;
        }

        // Check if session exists and has AS400 object
        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            SystemLogger.logError("Session expired for user: " + username);
            sendError(httpResponse, 401, "Session expired - please login again");
            return;
        }

        AS400 as400 = (AS400) session.getAttribute("as400");
        if (as400 == null) {
            SystemLogger.logError("AS400 object missing from session for user: " + username);
            sendError(httpResponse, 401, "Session expired - please login again");
            return;
        }

        // Set username in request for use in servlets
        httpRequest.setAttribute("username", username);

        // Continue
        chain.doFilter(request, response);
    }

    private void sendError(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"success\":false,\"error\":\"" + message + "\"}");
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }
}
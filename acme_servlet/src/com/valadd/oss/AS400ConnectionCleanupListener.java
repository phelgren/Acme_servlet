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

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Listener to properly clean up AS400 connections when sessions expire
 * or when the application shuts down to prevent memory leaks
 */
@WebListener
public class AS400ConnectionCleanupListener implements ServletContextListener, HttpSessionListener {

    // Thread-safe set to track all active AS400 connections
    private static final Set<AS400> activeConnections = Collections.synchronizedSet(new HashSet<>());

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        SystemLogger.log("AS400 Connection Cleanup Listener initialized");
        // Store the set in servlet context for access from other components
        sce.getServletContext().setAttribute("as400Connections", activeConnections);

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            SystemLogger.log("Registered BC security provider");
        } else {
            SystemLogger.log("BC security provider already registered");
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        SystemLogger.log("Application shutting down - cleaning up all AS400 connections");

        // Disconnect all tracked AS400 connections
        synchronized (activeConnections) {
            SystemLogger.log("Found " + activeConnections.size() + " active AS400 connections to clean up");

            for (AS400 as400 : activeConnections) {
                try {
                    if (as400 != null && as400.isConnected()) {
                        SystemLogger.log("Disconnecting AS400 connection for user: " + as400.getUserId());
                        as400.disconnectAllServices();
                        SystemLogger.log("AS400 connection disconnected successfully");
                    }
                } catch (Exception e) {
                    SystemLogger.logError("Error disconnecting AS400 connection during shutdown: " + e.getMessage());
                }
            }

            activeConnections.clear();
            SystemLogger.log("All AS400 connections cleaned up");

            // Deregister JDBC drivers loaded by this webapp
            deregisterJdbcDrivers();

            // Remove BC provider to avoid stale provider/classloader after redeploy
            Provider bc = Security.getProvider("BC");
            if (bc != null) {
                SystemLogger.log("Removing BC security provider: " + bc.getInfo());
                Security.removeProvider("BC");
            }
        }
    }

    /**
     * Register an AS400 connection for tracking
     */
    public static void registerConnection(AS400 as400) {
        if (as400 != null) {
            activeConnections.add(as400);
            SystemLogger.log("Registered AS400 connection for user: " + as400.getUserId() +
                    " (Total active: " + activeConnections.size() + ")");
        }
    }

    /**
     * Unregister an AS400 connection from tracking
     */
    public static void unregisterConnection(AS400 as400) {
        if (as400 != null) {
            activeConnections.remove(as400);
            SystemLogger.log("Unregistered AS400 connection for user: " + as400.getUserId() +
                    " (Total active: " + activeConnections.size() + ")");
        }
    }

    @Override
    public void sessionCreated(HttpSessionEvent se) {
        // Nothing to do when session is created
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        HttpSession session = se.getSession();
        SystemLogger.log("Session destroyed: " + session.getId() + " - cleaning up AS400 connection");

        // Get the AS400 object from the session
        AS400 as400 = (AS400) session.getAttribute("as400");

        if (as400 != null) {
            try {
                SystemLogger.log("Disconnecting AS400 connection for user: " + as400.getUserId());

                // Unregister from tracking
                unregisterConnection(as400);

                // Disconnect all services
                as400.disconnectAllServices();
                SystemLogger.log("AS400 connection disconnected successfully");
            } catch (Exception e) {
                SystemLogger.logError("Error disconnecting AS400 connection: " + e.getMessage(), e);
            }
        }
    }

    private void deregisterJdbcDrivers() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        java.util.Enumeration<java.sql.Driver> drivers = java.sql.DriverManager.getDrivers();

        while (drivers.hasMoreElements()) {
            java.sql.Driver driver = drivers.nextElement();
            if (driver.getClass().getClassLoader() == cl) {
                try {
                    java.sql.DriverManager.deregisterDriver(driver);
                    SystemLogger.log("Deregistered JDBC driver: " + driver);
                } catch (java.sql.SQLException e) {
                    SystemLogger.logError("Error deregistering JDBC driver: " + e.getMessage(), e);
                }
            }
        }
    }
}
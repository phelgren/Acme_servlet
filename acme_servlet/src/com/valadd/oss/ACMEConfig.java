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

import java.io.Serializable;
import java.sql.Timestamp;

/**
 * Simple model for ACME configuration
 */
public class ACMEConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    private String id;
    private String name;
    private String challengeType;
    private int timeout;
    private String requestType;
    private String domain;
    private String accountKey;
    private String csr;
    private String wellKnownDir;
    private String certificatePath;
    private String wrkFolder;
    private String dnsTxtRecord;
    private String userId;
    private Timestamp createdAt;
    private Timestamp updatedAt;

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getChallengeType() {
        return challengeType;
    }

    public void setChallengeType(String challengeType) {
        this.challengeType = challengeType;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getAccountKey() {
        return accountKey;
    }

    public void setAccountKey(String accountKey) {
        this.accountKey = accountKey;
    }

    public String getCsr() {
        return csr;
    }

    public void setCsr(String csr) {
        this.csr = csr;
    }

    public String getWellKnownDir() {
        return wellKnownDir;
    }

    public void setWellKnownDir(String wellKnownDir) {
        this.wellKnownDir = wellKnownDir;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    public String getWrkFolder() {
        return wrkFolder;
    }

    public void setWrkFolder(String wrkFolder) {
        this.wrkFolder = wrkFolder;
    }

    public String getDnsTxtRecord() {
        return dnsTxtRecord;
    }

    public void setDnsTxtRecord(String dnsTxtRecord) {
        this.dnsTxtRecord = dnsTxtRecord;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public Timestamp getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Timestamp updatedAt) {
        this.updatedAt = updatedAt;
    }
}
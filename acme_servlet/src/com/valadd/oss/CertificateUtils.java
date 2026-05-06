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

import com.ibm.as400.access.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.*;

/**
 * Utility class for certificate operations
 * Shared by CertificateListServlet and CertificateExpirationScheduler
 */
public class CertificateUtils {
    private static final String TEMP_KEYSTORE_PASSWORD = "temp_password_12345";

    /**
     * Certificate information holder
     */
    public static class CertInfo {
        private String alias;
        private String subject;
        private String issuer;
        private Date validFrom;
        private Date validUntil;
        private String signatureAlgorithm;
        private boolean isCA;
        private boolean isValid;
        private String status;

        // Getters and setters
        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public Date getValidFrom() {
            return validFrom;
        }

        public void setValidFrom(Date validFrom) {
            this.validFrom = validFrom;
        }

        public Date getValidUntil() {
            return validUntil;
        }

        public void setValidUntil(Date validUntil) {
            this.validUntil = validUntil;
        }

        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public void setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        public boolean isCA() {
            return isCA;
        }

        public void setCA(boolean isCA) {
            this.isCA = isCA;
        }

        public boolean isValid() {
            return isValid;
        }

        public void setValid(boolean isValid) {
            this.isValid = isValid;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        /**
         * Convenience method - alias for getValidUntil()
         * Used by CertificateExpirationScheduler
         */
        public LocalDate getExpirationDate() {
            if (validUntil == null) {
                return null;
            }
            return validUntil.toInstant()
                    .atZone(java.time.ZoneId.systemDefault())
                    .toLocalDate();
        }

        /**
         * Convenience method - alias for getAlias()
         * Used by CertificateExpirationScheduler
         */
        public String getLabel() {
            return alias;
        }

        /**
         * Convert to Map for JSON serialization
         */
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("alias", alias);
            map.put("subject", subject);
            map.put("issuer", issuer);
            map.put("commonName", extractCommonName(subject));

            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            map.put("validFrom", validFrom != null ? dateFormat.format(validFrom) : null);
            map.put("validUntil", validUntil != null ? dateFormat.format(validUntil) : null);

            map.put("signatureAlgorithm", signatureAlgorithm);
            map.put("isCA", isCA);
            map.put("isValid", isValid);
            map.put("status", status);

            return map;
        }

        private String extractCommonName(String dn) {
            if (dn == null)
                return null;
            String[] parts = dn.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (trimmed.startsWith("CN=")) {
                    return trimmed.substring(3);
                }
            }
            return null;
        }
    }

    /**
     * Get all certificates from DCM store
     * This is the main method that both servlets should use
     */
    public static List<CertInfo> getCertificates(AS400 as400, String storeName, String storePassword)
            throws Exception {

        Path tempFile = null;
        String ifsPath = null;

        try {
            // Convert *SYSTEM to actual IFS path
            String actualStoreName = storeName;
            if ("*SYSTEM".equalsIgnoreCase(storeName)) {
                actualStoreName = "/QIBM/UserData/ICSS/Cert/Server/DEFAULT.KDB";
            }

            // Create temporary file name for IFS
            String tempFileName = "dcm_export_" + System.currentTimeMillis() + ".p12";
            ifsPath = "/tmp/" + tempFileName;

            // Call IBM i API to export the keystore to IFS
            callQykmExportKeyStore(as400, actualStoreName, storePassword, ifsPath, TEMP_KEYSTORE_PASSWORD);

            // Download the file from IFS to local temp file
            tempFile = Files.createTempFile("dcm_local_", ".p12");
            downloadFromIFS(as400, ifsPath, tempFile.toFile());

            // Load the exported PKCS12 file
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(tempFile.toFile())) {
                keyStore.load(fis, TEMP_KEYSTORE_PASSWORD.toCharArray());
            }

            // Extract certificate information
            List<CertInfo> certificates = new ArrayList<>();
            Enumeration<String> aliases = keyStore.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                // Check if this is a private key entry (contains both key and cert)
                if (keyStore.isKeyEntry(alias)) {
                    // For private key entries, get the certificate chain
                    // The first certificate in the chain is the actual client/server certificate
                    Certificate[] chain = keyStore.getCertificateChain(alias);
                    if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate) {
                        // Remove "privatekey" suffix from alias for cleaner display
                        String cleanAlias = alias.toLowerCase().endsWith("privatekey")
                                ? alias.substring(0, alias.length() - 10)
                                : alias;
                        CertInfo certInfo = extractCertificateInfo(cleanAlias, (X509Certificate) chain[0]);
                        certificates.add(certInfo);
                    }
                } else {
                    // For certificate-only entries (CA certs, trusted certs)
                    Certificate cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        CertInfo certInfo = extractCertificateInfo(alias, (X509Certificate) cert);
                        certificates.add(certInfo);
                    }
                }
            }

            return certificates;

        } finally {
            // Clean up temporary files
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException e) {
                    SystemLogger.logError("Warning: Could not delete local temp file: " + e.getMessage());
                }
            }

            // Clean up IFS file
            if (ifsPath != null && as400 != null) {
                try {
                    deleteFromIFS(as400, ifsPath);
                } catch (Exception e) {
                    SystemLogger.logError("Warning: Could not delete IFS temp file: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Extract certificate information from X509Certificate
     */
    private static CertInfo extractCertificateInfo(String alias, X509Certificate cert) {
        CertInfo info = new CertInfo();
        info.setAlias(alias);
        info.setSubject(cert.getSubjectX500Principal().getName());
        info.setIssuer(cert.getIssuerX500Principal().getName());
        info.setValidFrom(cert.getNotBefore());
        info.setValidUntil(cert.getNotAfter());
        info.setSignatureAlgorithm(cert.getSigAlgName());

        // Check if it's a CA certificate
        // A certificate is a CA if:
        // 1. BasicConstraints extension exists AND is marked as CA (pathLen >= 0)
        // 2. Subject and Issuer are the same (self-signed CA)
        int basicConstraints = cert.getBasicConstraints();
        boolean isSelfSigned = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());

        // More robust CA detection:
        // - If basicConstraints >= 0, it's definitely a CA
        // - If basicConstraints == -1 but it's self-signed, it might be a CA
        // - Otherwise, it's an end-entity (client/server) certificate
        boolean isCA = (basicConstraints >= 0) || (basicConstraints == -1 && isSelfSigned);

        info.setCA(isCA);

        // Debug logging for troubleshooting
        SystemLogger.log("Certificate: " + alias +
                " | BasicConstraints: " + basicConstraints +
                " | SelfSigned: " + isSelfSigned +
                " | IsCA: " + isCA);

        // Check if certificate is currently valid
        Date now = new Date();
        boolean isValid = now.after(cert.getNotBefore()) && now.before(cert.getNotAfter());
        info.setValid(isValid);

        // Set status
        if (isValid) {
            info.setStatus("Valid");
        } else if (now.before(cert.getNotBefore())) {
            info.setStatus("Not yet valid");
        } else {
            info.setStatus("Expired");
        }

        return info;
    }

    /**
     * Call IBM i QYKMEXPK API to export keystore
     */
    private static void callQykmExportKeyStore(AS400 as400, String dcmStore, String dcmStorePw,
            String exportFile, String exportFilePw) throws Exception {

        ProgramCall program = new ProgramCall(as400);
        String programName = "/QSYS.LIB/QYKMEXPK.PGM";

        ProgramParameter[] parameterList = new ProgramParameter[14];

        // 1. Certificate store path and file name
        parameterList[0] = new ProgramParameter(new AS400Text(dcmStore.length()).toBytes(dcmStore));

        // 2. Length of certificate store path and file name
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(dcmStore.length()));

        // 3. Format of certificate store path and file name
        parameterList[2] = new ProgramParameter(new AS400Text(8).toBytes("OBJN0100"));

        // 4. Certificate store password
        parameterList[3] = new ProgramParameter(new AS400Text(dcmStorePw.length(), 1208).toBytes(dcmStorePw));

        // 5. Length of certificate store password
        parameterList[4] = new ProgramParameter(new AS400Bin4().toBytes(dcmStorePw.length()));

        // 6. CCSID of certificate store password
        parameterList[5] = new ProgramParameter(new AS400Bin4().toBytes(1208));

        // 7. Export path and file name
        parameterList[6] = new ProgramParameter(new AS400Text(exportFile.length()).toBytes(exportFile));

        // 8. Length of export path and file name
        parameterList[7] = new ProgramParameter(new AS400Bin4().toBytes(exportFile.length()));

        // 9. Format of export path and file name
        parameterList[8] = new ProgramParameter(new AS400Text(8).toBytes("OBJN0100"));

        // 10. Version of export file
        parameterList[9] = new ProgramParameter(new AS400Text(10).toBytes("*PKCS12V3 "));

        // 11. Export file password
        parameterList[10] = new ProgramParameter(new AS400Text(exportFilePw.length(), 1208).toBytes(exportFilePw));

        // 12. Length of export file password
        parameterList[11] = new ProgramParameter(new AS400Bin4().toBytes(exportFilePw.length()));

        // 13. CCSID of export file password
        parameterList[12] = new ProgramParameter(new AS400Bin4().toBytes(1208));

        // 14. Error code
        ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        parameterList[13] = ec;

        program.setProgram(programName, parameterList);

        // Run the program
        if (!program.run()) {
            AS400Message[] messageList = program.getMessageList();
            StringBuilder errorMsg = new StringBuilder("DCM API call failed: ");
            for (AS400Message msg : messageList) {
                errorMsg.append(msg.getText()).append(" ");
            }
            throw new IOException(errorMsg.toString());
        }

        // Check for error code
        String errorMessageId = ec.getMessageID();
        if (errorMessageId != null && !errorMessageId.trim().isEmpty()) {
            throw new IOException("API error: " + errorMessageId);
        }
    }

    /**
     * Download a file from IBM i IFS to local file system
     */
    private static void downloadFromIFS(AS400 as400, String ifsPath, File localFile) throws Exception {
        IFSFile ifsFile = new IFSFile(as400, ifsPath);

        if (!ifsFile.exists()) {
            throw new IOException("IFS file does not exist: " + ifsPath);
        }

        try (IFSFileInputStream ifsIn = new IFSFileInputStream(ifsFile);
                FileOutputStream localOut = new FileOutputStream(localFile)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = ifsIn.read(buffer)) != -1) {
                localOut.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Delete a file from IBM i IFS
     */
    private static void deleteFromIFS(AS400 as400, String ifsPath) throws Exception {
        IFSFile ifsFile = new IFSFile(as400, ifsPath);
        if (ifsFile.exists()) {
            ifsFile.delete();
        }
    }
}

// Made with Bob

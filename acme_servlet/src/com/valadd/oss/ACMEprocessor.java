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

import java.beans.PropertyVetoException;
import java.io.BufferedWriter;

/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeUnauthorizedException;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.as400.access.AS400;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.IFSFile;
import com.ibm.as400.access.IFSFileWriter;
import com.ibm.as400.access.ObjectDoesNotExistException;

/**
 * A simple client test tool.
 * <p>
 * Pass the names of the domains as parameters.
 */
public class ACMEprocessor {
    // File name of the User Key Pair
    private static File USER_KEY_FILE = null;
    // File name of the User Key Pair
    private static File USER_KEY_PAIR = null;

    // File name of the Domain Key Pair
    private static File DOMAIN_KEY_FILE = null;

    // File name of the CSR
    private static File DOMAIN_CSR_FILE = null;

    // ACME account key
    private static File ACCOUNT_KEY = null;

    // ACME domains to authorize
    private static Collection<String> DOMAINS = null;

    // File name of the signed certificate
    private static File DOMAIN_CHAIN_FILE = null;

    // Folder for temp files
    private static Path WORK_DIRECTORY = null;

    // Folder for certificate files
    private static Path CERTIFICATE_PATH = null;

    // Folder for well-known dir
    private static Path WELL_KNOWN_DIR = null;

    // Request type
    private static RequestType REQUEST_TYPE = RequestType.NEW;

    // Challenge type to be used
    private static ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP;

    // Timeout
    private static int CHALLENGE_TIMEOUT = 0;

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

    private static final Logger LOG = LoggerFactory.getLogger(ACMEprocessor.class);

    private enum RequestType {
        RENEW, NEW
    };

    private enum ChallengeType {
        HTTP, DNS
    }

    public static StringBuilder msg = new StringBuilder();

    private static String CRLF = "<br>";

    public ACMEprocessor() {

    }

    // The wellKnownDir for HTTP-01 and the acme_work_folder have very similar and
    // confusing variable names. Changed the acme_wk_dir, which is the
    // acme_work_folder to use acme_work_dir variable name instead

    public ACMEprocessor(Collection<String> acme_domain, String acme_challenge_type, String acme_timeout,
            String acme_type, String acme_account, String acme_csr_path_file,
            String acme_work_dir, String acme_cert_path, String acme_well_known_dir) {

        boolean constructed = true;

        USER_KEY_FILE = new File(acme_account);
        CHALLENGE_TYPE = acme_challenge_type.equalsIgnoreCase("http") ? ChallengeType.HTTP : ChallengeType.DNS;
        CHALLENGE_TIMEOUT = Integer.parseInt(acme_timeout);
        DOMAIN_CSR_FILE = new File(acme_csr_path_file);
        DOMAINS = acme_domain;
        REQUEST_TYPE = acme_type.equalsIgnoreCase("New") ? RequestType.NEW : RequestType.RENEW;

        Path wpath = Paths.get(acme_work_dir);
        Path acme_cp = Paths.get(acme_cert_path);
        Path acme_wkd = Paths.get(acme_well_known_dir);

        try {
            Files.createDirectories(wpath);
            WORK_DIRECTORY = wpath;

            Files.createDirectories(acme_wkd);
            WELL_KNOWN_DIR = acme_wkd;

            Files.createDirectories(acme_cp);
            CERTIFICATE_PATH = acme_cp;

            // TO-DO: determine a naming convention for the certificate file

            // Might need an IFS file write so we can set the CCSID

            String[] props = null;
            try {
                props = getProps("IBMi");
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            AS400 system = new AS400(props[0], props[1], props[2]);

            // 1. Create an IFSFile object
            IFSFile DOMAIN_CHAIN_FILE = new IFSFile(system, acme_cp + File.separator + "certificate.pem");

            // 2. Use the IFSFileWriter constructor that accepts a CCSID
            // The data written to the file will be converted to this CCSID.
            IFSFileWriter fw = new IFSFileWriter(DOMAIN_CHAIN_FILE, 850);

            // 4. Close the writer
            fw.close();

            // Original
            // DOMAIN_CHAIN_FILE = new File(acme_cp + File.separator + "certificate.pem");

        } catch (IOException | AS400SecurityException e) {
            // TODO Auto-generated catch block
            constructed = false;

            e.printStackTrace();
        }

    }

    /**
     * Generates a certificate for the given domains. Also takes care for the
     * registration
     * process.
     *
     * @param response
     *                 HttpServletResponse for sending SSE events to client, or null
     *                 when called
     *                 from scheduler (events will be logged to console instead)
     * @throws AcmeException
     */
    public void prepcert(HttpServletResponse response) throws IOException, AcmeException {

        PrintWriter writer = response != null ? response.getWriter() : null;

        boolean success = false;
        boolean skiporders = false;
        Certificate certificate = null;
        // in case it already exists - clear
        msg.delete(0, msg.length());
        // Load the user key file. If there is no key file, create a new one.
        KeyPair userKeyPair = loadUserKeyPair(writer);

        // Create a session for Let's Encrypt.
        // Use "acme://letsencrypt.org" for production server
        // Session session = new Session("acme://letsencrypt.org/staging");
        String[] props = getProps("LE");
        Session session = new Session(props[3]);
        // Get the Account.
        Account acct = findAccount(session, userKeyPair, writer);

        // Load or create a key pair for the domains. This should not be the
        // userKeyPair!
        // For signing the CSR NOT needed when CSR is created by DCM
        // KeyPair domainKeyPair = loadDomainKeyPair();

        Order order = acct.newOrder().domains(DOMAINS).create();

        List<Authorization> auths = order.getAuthorizations();

        for (Authorization auth : auths) {
            authorize(auth, writer);
        }

        InputStream in = null;

        try {
            in = new FileInputStream(DOMAIN_CSR_FILE);
        } catch (IOException ioe) {
            sendEvent(writer, "error", "Error: Cannot find CSR.");
            sendEvent(writer, "info", "Shutdown");

            msg.append("Cannot find CSR.").append(CRLF);
            msg.append("shutdown");

            ioe.printStackTrace();

        }
        // Make sure this has all the domains we are validating or it will fail
        PKCS10CertificationRequest csr = null;
        if (in != null)
            csr = CertificateUtils.readCSR(in);

        if (csr != null)
            // Wait for the order to complete
            try {

                // Order the certificate
                order.execute(csr.getEncoded());

                int attempts = 10;

                while (order.getStatus() != Status.VALID && attempts-- > 0) {
                    // Did the order fail?
                    if (order.getStatus() == Status.INVALID) {
                        sendEvent(writer, "error", "Error: Order failed... Giving up.");
                        sendEvent(writer, "info", "Shutdown");

                        msg.append("Order failed... Giving up.").append(CRLF);
                        msg.append("shutdown");
                        throw new AcmeException("Order failed... Giving up.");
                    }

                    // Wait for a few seconds
                    Thread.sleep(6000L);

                    // Then update the status
                    order.update();

                }

            } catch (InterruptedException ex) {

                msg.append("shutdown");
                sendEvent(writer, "info", "Shutdown");

                LOG.error("interrupted", ex);
                Thread.currentThread().interrupt();
            } catch (AcmeUnauthorizedException aue) {
                sendEvent(writer, "error", "CSR has incorrect or missing domain");
                sendEvent(writer, "info", "Shutdown");

                msg.append("CSR has incorrect or missing domain").append(CRLF);
                msg.append("shutdown");
                LOG.error("CSR has incorrect or missing domain");
            }

        if (order != null && order.getStatus() == Status.VALID)
            success = true;
        // if we have any errors, don't proceed

        if (success) {

            StringBuilder event = new StringBuilder();

            // Get the certificate
            certificate = order.getCertificate();

            event.append("Success! The certificate for domains ").append(DOMAINS).append(" has been generated!");

            sendEvent(writer, "success", event.toString());

            msg.append(event).append(CRLF);

            event.setLength(0);

            event.append("Certificate URL:").append(certificate.getLocation());

            sendEvent(writer, "success", event.toString());

            msg.append(event).append(CRLF);

            LOG.info("Success! The certificate for domains {} has been generated!", DOMAINS);
            LOG.info("Certificate URL: {}", certificate.getLocation());

            // Might need an IFS file write so we can set the CCSID
            // Need to switch to IBM i properties
            props = getProps("IBMi");

            AS400 system = new AS400(props[0], props[1], props[2]);

            // Write a combined file containing the certificate and chain.

            // 1. Create an IFSFile object
            IFSFile DOMAIN_CHAIN_FILE = new IFSFile(system, CERTIFICATE_PATH + File.separator + "certificate.pem");
            DOMAIN_CHAIN_FILE.setCCSID(850);

            // 2. Use the IFSFileWriter constructor that accepts a CCSID
            // The data written to the file will be converted to this CCSID.
            IFSFileWriter fw;

            try {
                fw = new IFSFileWriter(DOMAIN_CHAIN_FILE, 850);
                certificate.writeCertificate(fw);
                // 4. Close the writer
                fw.close();
            } catch (AS400SecurityException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } finally {
                system.disconnectAllServices();
            }

            // Write a combined file containing the certificate and chain.
            // Original
            // try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            // certificate.writeCertificate(fw);
            // }

            // Always dangerous to assume that all is well
            // Import the certificate into DCM

            ApiCaller ac = new ApiCaller();

            String certFile = "";

            certFile = DOMAIN_CHAIN_FILE.getAbsolutePath();

            try {
                boolean isNew = false;

                if (REQUEST_TYPE == RequestType.NEW)
                    isNew = true;

                success = ac.importCertificate(certFile, isNew);

            } catch (Exception ex) {

                LOG.info("ERROR! Certficate(s) for " + DOMAINS + " FAILED to import into DCM!");

                ex.printStackTrace();

                success = false;

            }

            if (success) {

                msg.append("Certficate(s) for " + DOMAINS + " imported into DCM!").append(CRLF);

                sendEvent(writer, "success", "Certficate(s) for " + DOMAINS + " imported into DCM!");

                LOG.info("Success! The certificate has been imported into DCM");
            } else {
                msg.append("Certficate(s) for " + DOMAINS + " FAILED to import into DCM!");
                sendEvent(writer, "error", "Certficate(s) for " + DOMAINS + " FAILED to import into DCM!");
            }
        }

        msg.append("shutdown");

        sendEvent(writer, "info", "Shutdown");

    }

    // 5. Helper method to send SSE events
    private void sendEvent(PrintWriter writer, String type, String message) {
        if (writer == null) {
            // When called from scheduler, log to console instead
            SystemLogger.log("ACME Event [" + type + "]: " + message);
            return;
        }
        try {
            JSONObject event = new JSONObject();
            event.put("type", type);
            event.put("message", message);
            event.put("timestamp", System.currentTimeMillis());

            writer.write("data: " + event.toString() + "\n\n");
            writer.flush();

            Thread.sleep(100); // Small delay to ensure delivery
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Loads a user key pair from {@link #USER_KEY_FILE}. If the file does not
     * exist, a
     * new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not
     * be
     * able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadUserKeyPair(PrintWriter writer) throws IOException {

        KeyPair kp = null;

        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                kp = KeyPairUtils.readKeyPair(fr);
                msg.append("Success! Account key found and loaded").append(CRLF);
                sendEvent(writer, "success", "Success! Account key found and loaded");

                LOG.info("Success! Account key found and loaded");
            } catch (Exception e) {
                msg.append("Error! Account key file NOT found!").append(CRLF);
                msg.append("shutdown");
                sendEvent(writer, "error", "Error! Account key file NOT found!");
                sendEvent(writer, "info", "Shutdown");

                LOG.error("Error! Account key file NOT found!");
            }
        }
        return kp;
    }

    /**
     * Loads a domain key pair from {@link #DOMAIN_KEY_FILE}.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadDomainKeyPair() throws IOException {
        KeyPair kp = null;

        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                kp = KeyPairUtils.readKeyPair(fr);
                msg.append("Success! Server key found and loaded").append(CRLF);
                LOG.info("Success! Server key found and loaded");
            } catch (Exception e) {
                msg.append("Error! Server key file NOT found!").append(CRLF);
                msg.append("shutdown");
                LOG.error("Error! Server key file NOT found!");
            }
        }

        return kp;

    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your
     * user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get
     * the
     * URL of your new account with {@link Account#getLocation()} and store it
     * somewhere.
     * If you need to get access to your account later, reconnect to it via {@link
     * Session#login(URL, KeyPair)} by using the stored location.
     *
     * @param session
     *                {@link Session} to bind with
     * @return {@link Account}
     */
    public Account findAccount(Session session, KeyPair accountKey, PrintWriter writer) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        URI tos = session.getMetadata().getTermsOfService();

        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
        StringBuilder event = new StringBuilder();
        event.append("Account found, URL: ").append(account.getLocation());

        sendEvent(writer, "success", event.toString());

        msg.append(event).append(CRLF);
        LOG.info("Account found, URL: {}", account.getLocation());

        return account;
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be
     * able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth
     *             {@link Authorization} to perform
     */
    public void authorize(Authorization auth, PrintWriter writer) throws AcmeException {
        StringBuilder event = new StringBuilder();
        event.append("Authorization for domain  ").append(auth.getIdentifier().getDomain());

        sendEvent(writer, "success", event.toString());

        LOG.info("Authorization for domain {}", auth.getIdentifier().getDomain());
        msg.append(event).append(CRLF);
        boolean deleteworked = false;

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = null;
        switch (CHALLENGE_TYPE) {
            case HTTP:
                challenge = httpChallenge(auth, writer);
                break;

            case DNS:
                challenge = dnsChallenge(auth, writer);
                break;
        }

        if (challenge == null) {
            event.setLength(0);
            event.append("Error! Server key file NOT found!");
            sendEvent(writer, "error", event.toString());
            sendEvent(writer, "info", "Shutdown");

            msg.append("No challenge found").append(CRLF);
            throw new AcmeException("No challenge found");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {

                    sendEvent(writer, "error", "Challenge failed... Giving up.");
                    sendEvent(writer, "info", "Shutdown.");

                    msg.append("Challenge failed... Giving up.");
                    msg.append("shutdown");
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(6000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            event.setLength(0);
            event.append("Failed to pass the challenge for domain").append(auth.getIdentifier().getDomain())
                    .append("... Giving up.");

            sendEvent(writer, "error", event.toString());
            sendEvent(writer, "info", "Shutdown");

            msg.append(event).append(CRLF);
            msg.append("shutdown");
            throw new AcmeException("Failed to pass the challenge for domain "
                    + auth.getIdentifier().getDomain() + ", ... Giving up.");
        }

        if (CHALLENGE_TYPE == ChallengeType.DNS)

            try {
                deleteworked = deleteDNSTXTRecord(auth);
                sendEvent(writer, "info", "TXT record successfully deleted.");

                LOG.info("TXT record successfully deleted.");
                msg.append("TXT record successfully deleted.").append(CRLF);

            } catch (IOException e) {
                // TODO Auto-generated catch block
                LOG.info("TXT record was not deleted.");
                msg.append("TXT record was not deleted.").append(CRLF);
                msg.append("shutdown");

                sendEvent(writer, "error", "TXT record was not deleted.");
                sendEvent(writer, "info", "Shutdown");

            }

        sendEvent(writer, "success", "Challenge has been completed.");

        LOG.info("Challenge has been completed.");
        msg.append("Challenge has been completed.").append(CRLF);

    }

    /**
     * Prepares a HTTP challenge.
     * <p>
     * The verification of this challenge expects a file with a certain content to
     * be
     * reachable at a given path under the domain to be tested.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather generate this file automatically, or
     * maybe
     * use a servlet that returns {@link Http01Challenge#getAuthorization()}.
     *
     * @param auth
     *             {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge httpChallenge(Authorization auth, PrintWriter writer) throws AcmeException {

        StringBuilder event = new StringBuilder();

        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.class);
        if (challenge == null) {
            event.append("Found no ").append(Http01Challenge.TYPE).append(" challenge, don't know what to do...");

            sendEvent(writer, "error", event.toString());
            sendEvent(writer, "info", "Shutdown");

            msg.append(event).append(CRLF);
            msg.append("shutdown");
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // I think the challenge has to be the FULL path in the IFS to the
        // .well-known/acme-challenge/ folder.
        // WE create the file and then ACME will read the file to verify

        event.setLength(0);
        event.append("Creating a file at: http://").append(auth.getIdentifier().getDomain())
                .append("/.well-known/acme-challenge/").append(challenge.getToken());

        msg.append(event).append(CRLF);

        LOG.info("Creating a file at: http://{}/.well-known/acme-challenge/{}",
                auth.getIdentifier().getDomain(), challenge.getToken());

        event.setLength(0);
        event.append("File name: ").append(challenge.getToken());

        sendEvent(writer, "success", event.toString());

        msg.append(event).append(CRLF);

        LOG.info("File name: {}", challenge.getToken());

        event.setLength(0);
        event.append("Content ").append(challenge.getAuthorization());

        sendEvent(writer, "success", event.toString());

        msg.append(event).append(CRLF);

        LOG.info("Content: {}", challenge.getAuthorization());

        // Create the file and write the contents

        boolean challengeOK = false;

        try {

            BufferedWriter cwriter = new BufferedWriter(
                    new FileWriter(WELL_KNOWN_DIR + File.separator + challenge.getToken()));

            cwriter.write(challenge.getAuthorization());

            cwriter.close();

            challengeOK = true;

        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (challengeOK) {

            msg.append("Authorization written to well-known dir...").append(CRLF);
            sendEvent(writer, "success", "Authorization written to well-known dir...");

            LOG.info("Authorization written to well-known dir...");
        } else {
            msg.append("ACME HTTP challenge file was not created.").append(CRLF);
            msg.append("shutdown");

            sendEvent(writer, "error", "ACME HTTP challenge file was not created.");
            sendEvent(writer, "info", "Shutdown");

            LOG.info("ACME HTTP challenge file was not created.");
        }

        return challenge;
    }

    /**
     * Prepares a DNS challenge.
     * <p>
     * The verification of this challenge expects a TXT record with a certain
     * content.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather configure your DNS automatically.
     *
     * @param auth
     *             {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge dnsChallenge(Authorization auth, PrintWriter writer) throws AcmeException {
        StringBuilder event = new StringBuilder();
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
        if (challenge == null) {
            event.append("Found no ").append(Dns01Challenge.TYPE).append(" challenge, don't know what to do...");
            msg.append(event).append(CRLF);
            msg.append("shutdown");

            sendEvent(writer, "error", event.toString());
            sendEvent(writer, "info", "Shutdown");

            throw new AcmeException("Found no " + Dns01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // Output the challenge, wait for acknowledge...
        msg.append("Creating a TXT record:").append(CRLF);
        sendEvent(writer, "info", "Creating a TXT record:");

        LOG.info("Creating a TXT record:");

        event.setLength(0);
        event.append("_acme-challenge.").append(auth.getIdentifier().getDomain()).append(". IN TXT ")
                .append(challenge.getDigest());

        msg.append(event).append(CRLF);

        sendEvent(writer, "info", event.toString());

        LOG.info("_acme-challenge.{}. IN TXT {}",
                auth.getIdentifier().getDomain(), challenge.getDigest());

        try {

            String domain = auth.getIdentifier().getDomain();
            String dot = "";
            String host = "";
            String apexDomain = domain;

            // Godaddy format for the acme-challenge by LE standards is _acme-challenge +
            // host ONLY
            long count = domain.chars().filter(ch -> ch == '.').count();

            if (count == 2 && domain.indexOf("*") == -1) // has a host name that is not a wildcard
            {
                dot = ".";
                int hlen = domain.indexOf(".");
                host = domain.substring(0, hlen);

                // if we have a host we need to reset the domain to JUST the apex

                apexDomain = domain.substring(hlen + 1);
            }

            String txtchallenge = "_acme-challenge" + dot + host;

            updateDNSTXTRecord(challenge.getDigest(), apexDomain, "TXT", txtchallenge);

            // The authorization may take a while if it is a DNS-01 type because the DNS
            // provider has to update
            // their DNS records. So park for maybe 15 seconds....hopefully that will be
            // enough time

            // Wait for a few seconds - milliseconds
            Long sleeptime = (long) (CHALLENGE_TIMEOUT * 1000);

            sendEvent(writer, "info", "Waiting for " + CHALLENGE_TIMEOUT + " seconds to complete TXT record update");

            Thread.sleep(sleeptime);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return challenge;
    }

    /**
     * Presents the instructions for preparing the challenge validation, and waits
     * for
     * dismissal. If the user cancelled the dialog, an exception is thrown.
     *
     * @param message
     *                Instructions to be shown in the dialog
     */
    public void acceptChallenge(String message) throws AcmeException {
        // int option = JOptionPane.showConfirmDialog(null,
        // message,
        // "Prepare Challenge",
        // JOptionPane.OK_CANCEL_OPTION);
        // if (option == JOptionPane.CANCEL_OPTION) {
        // throw new AcmeException("User cancelled the challenge");
        // }
    }

    /**
     * calls an external API (GoDaddy)
     * Updates the TXT record and waits a bit before continuing
     * 
     * @param txtContent (string returned by LE API for TXT record)
     */
    private boolean updateDNSTXTRecord(String txtContent, String domain, String type, String name) throws IOException {

        String[] props = getProps("LE");
        boolean status = true;
        // Build the RESTful string for the GoDaddy call

        StringBuilder gdPatchURL = new StringBuilder();
        StringBuilder gdHDR = new StringBuilder();

        // We may need to have multiple calls to Godaddy in order to take care of the
        // acme requirements

        // 1) Check to see if there IS an _acme-challenge TXT record that we need. The
        // construction of the
        // the TXT record is _acme-challenge + host name OR without the host for a
        // wildcard

        gdPatchURL.append(props[2]).append("/v1/domains/").append(domain).append("/records");

        gdHDR.append("sso-key ").append(props[1]).append(":").append(props[0]);

        CloseableHttpClient httpClient = HttpClients.createDefault();

        try {

            // Build the data payload for PATCH (add)

            StringBuilder jss = new StringBuilder();

            JSONArray array = new JSONArray();

            JSONObject json = new JSONObject();

            json.put("data", txtContent);
            // array.add(json);

            json.put("type", type);
            // array.add(json);

            json.put("ttl", 600);
            // array.add(json);
            json.put("name", name);

            array.add(json);

            String pay = array.toString();

            StringEntity payload = new StringEntity(pay);

            HttpPatch httpPatch = new HttpPatch(gdPatchURL.toString());

            // add request headers
            httpPatch.addHeader("Authorization", gdHDR.toString());
            httpPatch.addHeader("Content-Type", "application/json");

            httpPatch.setEntity(payload);

            // First step is to delete the record(s)
            CloseableHttpResponse localresponse = null;
            HttpEntity entity = null;

            try {

                // We do want run Patch next, to add the record

                localresponse = httpClient.execute(httpPatch);

                entity = localresponse.getEntity();

                if (localresponse.getStatusLine().getStatusCode() != 200)
                    status = false;

                if (entity != null) {
                    // return it as a String
                    String result = EntityUtils.toString(entity);
                    System.out.println(result);
                }

            } finally {
                localresponse.close();
            }

        } finally {
            httpClient.close();
        }

        return status;

    }

    /**
     * calls an external API (GoDaddy)
     * Deletes the TXT record and waits a bit before continuing
     * 
     * @param txtContent (string returned by LE API for TXT record)
     * @throws IOException
     */
    private boolean deleteDNSTXTRecord(Authorization auth) throws IOException {

        boolean success = true;
        String[] props = getProps("LE");

        // Build the RESTful string for the GoDaddy call

        StringBuilder gdPatchURL = new StringBuilder();
        StringBuilder gdDeleteURL = new StringBuilder();
        StringBuilder gdHDR = new StringBuilder();

        String domain = auth.getIdentifier().getDomain();
        String dot = "";
        String host = "";
        String apexDomain = domain;

        // Godaddy format for the acme-challenge by LE standards is _acme-challenge +
        // host ONLY
        long count = domain.chars().filter(ch -> ch == '.').count();

        if (count == 2 && domain.indexOf("*") == -1) // has a host name that is not a wildcard
        {
            dot = ".";
            int hlen = domain.indexOf(".");
            host = domain.substring(0, hlen);

            // if we have a host we need to reset the domain to JUST the apex

            apexDomain = domain.substring(hlen + 1);
        }

        String txtchallenge = "_acme-challenge" + dot + host;

        // We may need to have multiple calls to Godaddy in order to take care of the
        // acme requirements
        // 1) Delete any TXT records with the name _acme-challenge

        gdPatchURL.append(props[2]).append("/v1/domains/").append(domain).append("/records");

        gdDeleteURL.append(gdPatchURL).append("/").append("TXT").append("/").append(txtchallenge);

        gdHDR.append("sso-key ").append(props[1]).append(":").append(props[0]);

        CloseableHttpClient httpClient = HttpClients.createDefault();

        HttpDelete httpDelete = new HttpDelete(gdDeleteURL.toString());
        // add request headers
        httpDelete.addHeader("Authorization", gdHDR.toString());

        CloseableHttpResponse localresponse = httpClient.execute(httpDelete);

        if (localresponse.getStatusLine().getStatusCode() != 200 &&
                localresponse.getStatusLine().getStatusCode() != 204 &&
                localresponse.getStatusLine().getStatusCode() != 404)
            success = false; // Failed somehow

        HttpEntity entity = localresponse.getEntity();

        // Consume so that the client is released (really not interesting in reading it)
        if (entity != null)
            EntityUtils.consumeQuietly(entity);

        return success;

    }

    private String[] getProps(String type) throws IOException {

        // we'll need to pull properties from the conf folder so we have the secret and
        // key
        // for GoDaddy API call

        String[] props = new String[4];

        boolean success = false;

        FileInputStream fis = null;

        Properties prop = null;

        try {

            fis = new FileInputStream("/etc/acmedcm/conf/acmedcm.properties");

            prop = new Properties();

            prop.load(fis);

            success = true;

        } catch (FileNotFoundException fnfe) {
            msg.append("Check to make sure that you created an acmedcm.properties file with the correct credentials .")
                    .append(CRLF);
            msg.append("shutdown");
            LOG.info("Check to make sure that you created an acmedcm.properties file with the correct credentials .");
            fnfe.printStackTrace();

        } catch (IOException ioe) {

            ioe.printStackTrace();

        } finally {

            fis.close();
        }

        // If we were successful in getting what we need, continue

        if (success && type == "LE") {
            String secret = prop.getProperty("secret");
            String key = prop.getProperty("key");
            String baseURL = prop.getProperty("baseURL", "https://api.godaddy.com");
            String acmeURL = prop.getProperty("acmeURL");

            props[0] = secret;
            props[1] = key;
            props[2] = baseURL;
            props[3] = acmeURL;

        }

        if (success && type == "IBMi") {
            String ip = prop.getProperty("os400IP");
            String user = prop.getProperty("os400User");
            String password = prop.getProperty("os400PW");

            props[0] = ip;
            props[1] = user;
            props[2] = password;

        }

        return props;
    }

}
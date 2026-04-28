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

import com.ibm.as400.data.ProgramCallDocument;
import com.ibm.as400.data.PcmlException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.as400.access.AS400;
import com.ibm.as400.access.AS400Message;
import com.ibm.as400.access.IFSFile;
import com.ibm.as400.access.Trace;

public class Qycdrnwc {

    private static final Logger LOG = LoggerFactory.getLogger(Qycdrnwc.class);

    private AS400 as400System; // com.ibm.as400.access.AS400

    public Qycdrnwc() {
    }

    public boolean importCertificate(String certificate_path, boolean isNew) {

        boolean success = false;

        ProgramCallDocument pcml; // com.ibm.as400.data.ProgramCallDocument
        boolean rc = false; // Return code from ProgramCallDocument.callProgram()
        String msgId, msgText; // Messages returned from the server
        Object value; // Return value from ProgramCallDocument.getValue()

        System.setErr(System.out);

        Trace.setTraceOn(true); // Turn on tracing function.
        Trace.setTracePCMLOn(true); // Turn on PCML tracing.

        // IBM i connection stuff

        String[] props = null;

        try {
            props = getProps();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        String osName = System.getProperty("os.name", "");
        // if (osName.equalsIgnoreCase("OS/400")) { // Running on IBM i, using JV1
        // as400System = new AS400("localhost", "*CURRENT", "*CURRENT");
        // }
        // else
        // {
        // Parms are in the properties file

        as400System = new AS400(props[0], props[1], props[2]);
        // }

        try {
            // Uncomment the following to get debugging information
            com.ibm.as400.data.PcmlMessageLog.setTraceEnabled(true);

            SystemLogger.log("Beginning PCML API call..");
            SystemLogger.log("    Constructing ProgramCallDocument for QYCDRNWC API...");

            // Construct ProgramCallDocument
            // First parameter is system to connect to
            // Second parameter is pcml resource name. In this example,
            // serialized PCML file "qycdrnwc.pcml.ser" or
            // PCML source file "qycdrnwc.pcml" must be found in the classpath.

            // The only difference between the two files is that qycdrnwc2.pcml references
            // RNWC0200 instead of RNWC0300
            if (isNew)
                pcml = new ProgramCallDocument(as400System, "qycdrnwc2.pcml");
            else
                pcml = new ProgramCallDocument(as400System, "qycdrnwc.pcml");

            // Set input parameters. Several parameters have default values
            // specified in the PCML source. Do not need to set them using Java code.
            SystemLogger.log("    Setting input parameters...");
            int pathlen = certificate_path.length();

            pcml.setValue("qycdrnwc.certreqdata.offsettofile", 8);
            pcml.setValue("qycdrnwc.certreqdata.lengthoffilename", pathlen);
            pcml.setValue("qycdrnwc.certreqdata.certfile", certificate_path);

            // try adding them together?
            int structlength = 8 + pathlen + 4;

            pcml.setValue("qycdrnwc.reqdataLength", structlength);

            // Request to call the API
            // User will be prompted to sign on to the system
            SystemLogger.log("    Calling QYCDRNWC API importing certificate file");
            rc = pcml.callProgram("qycdrnwc");

            // If return code is false, we received messages from the server
            if (rc == false) {
                // Retrieve list of server messages
                AS400Message[] msgs = pcml.getMessageList("qycdrnwc");

                // Iterate through messages and write them to standard output
                for (int m = 0; m < msgs.length; m++) {
                    msgId = msgs[m].getID();
                    msgText = msgs[m].getText();
                    SystemLogger.log("    " + msgId + " - " + msgText);
                }
                SystemLogger.log("** Call to QYCDRNWC failed. See messages above **");
                success = false;
            } else
                success = true;

        } catch (PcmlException e) {
            SystemLogger.logError(e.getLocalizedMessage(), e);
            SystemLogger.logError("*** Call to QYCDRNWC failed. ***");
            as400System.disconnectAllServices();
            success = false;
        }

        // if(success) {
        // try {
        // // Create IFSFile object
        // IFSFile file = new IFSFile(as400System, certificate_path);
        //
        // // Change CCSID to 850 which seems to be needed..
        // file.setCCSID(850);
        // System.out.println("CCSID changed successfully.");
        // } catch (Exception e) {
        // e.printStackTrace();
        // } finally {
        // as400System.disconnectAllServices();
        // }
        // }

        return success;

    }

    private String[] getProps() throws IOException {

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

            LOG.info("Check to make sure that you created an acmedcm.properties file with the correct credentials .");

            fnfe.printStackTrace();

        } catch (IOException ioe) {

            ioe.printStackTrace();

        } finally {

            fis.close();
        }

        // If we were successful in getting what we need, continue

        if (success) {
            props[0] = prop.getProperty("os400IP");
            props[1] = prop.getProperty("os400User");
            props[2] = prop.getProperty("os400PW");

        }

        return props;
    }
}

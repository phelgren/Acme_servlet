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

// Wll Call IBM i API's  currently just the QycdRenewCertificate API format RNWC0300
import java.beans.PropertyVetoException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.as400.access.AS400;
import com.ibm.as400.access.AS400Bin4;
import com.ibm.as400.access.AS400DataType;
import com.ibm.as400.access.AS400Message;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.AS400Structure;
import com.ibm.as400.access.AS400Text;
import com.ibm.as400.access.ErrorCodeParameter;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.ObjectDoesNotExistException;
import com.ibm.as400.access.ProgramCall;
import com.ibm.as400.access.ProgramParameter;
import com.ibm.as400.access.ServiceProgramCall;

public class ApiCaller {

    private static final Logger LOG = LoggerFactory.getLogger(ApiCaller.class);

    private AS400 m_conn;

    public boolean importCertificate(String certificate_path, boolean isNew) {

        Qycdrnwc q = new Qycdrnwc();

        boolean success = q.importCertificate(certificate_path, isNew);

        return success;

    }

    public boolean importCertificatexx(String certificate_path, boolean isNew) {

        boolean success = false;

        String[] props = null;

        try {
            props = getProps();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        m_conn = new AS400(props[0], props[1], props[2]);

        final ServiceProgramCall program = new ServiceProgramCall(m_conn);

        // Initialize the name of the program to run.
        final String programName = "/QSYS.LIB/QICSS.LIB/QYCDRNWC.SRVPGM";

        String apiFormat = "RNWC0300";

        if (isNew)
            apiFormat = "RNWC0200";

        final AS400Structure arg0 = new AS400Structure(new AS400DataType[] {
                // 0 0 Binary (4) Offset to certificate path and file name
                new AS400Bin4(),
                // 4 4 Binary (4) Length of certificate path and file name
                new AS400Bin4(),
                // Char (*) Certificate path and file name
                new AS400Text(certificate_path.length()) }); // TODO

        // Set up the parms
        final ProgramParameter[] parameterList = new ProgramParameter[4];

        // 1 Certificate request data Input Char(*)
        parameterList[0] = new ProgramParameter(
                arg0.toBytes(new Object[] { 8, certificate_path.length(), certificate_path }));
        // 2 Length of certificate request data Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(arg0.getByteLength()));
        // 3 Format name Input Char(8)
        parameterList[2] = new ProgramParameter(new AS400Text(8).toBytes(apiFormat));
        // 4 Error Code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        parameterList[3] = ec;

        try {
            program.setProgram(programName, parameterList);
            program.setProcedureName("QycdRenewCertificate");
            // Run the program.
            runProgram(program, ec);
            success = true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            m_conn.disconnectAllServices();
        }

        return success;
    }

    private void runProgram(ProgramCall _program, ErrorCodeParameter _ec) throws AS400SecurityException,
            ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        if (!_program.run()) {
            // Get the error messages when the call fails.
            AS400Message[] messageList = _program.getMessageList();

            String returnMessage = "";

            for (int i = 0; i < messageList.length; ++i) {
                SystemLogger.log(messageList[i].getText());
                returnMessage = messageList[i].getText();
            }

            String errorMessageId = _ec.getMessageID();
            SystemLogger.log("Error ID:" + errorMessageId);

            throw new IOException("DCM API call failure :" + returnMessage);
        }
        for (AS400Message msg : _program.getMessageList()) {
            // Show each message.
            SystemLogger.log("" + msg);
        }
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

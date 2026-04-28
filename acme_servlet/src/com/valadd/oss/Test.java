package com.valadd.oss;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Test extends HttpServlet {
	
	public Test() {
		
		super();
		
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
        ApiCaller ac = new ApiCaller();
        
        String certFile = "";
        
        String msg = "";
        
        boolean success = false;
        
        certFile = "/etc/certificates/letsencrypt/asaap/certificate.pem";
        
        try {
        	
        	success = ac.importCertificate(certFile,true);
        	
        	// try pcml option
        	
//            Qycdrnwc q = new Qycdrnwc();
//        	
//            success = q.importCertificate(certFile);
   	
        	System.out.println("Success is : " + success);
        	
        	if (success)
	             
        		msg = "Success! The certificate has been imported into DCM";
        	
        	
        }
        catch(Exception ex) {
        	
	       // msg.append("Certficate FAILED to import into DCM!").append(CRLF);
	        
	        // LOG.info("ERROR! The certificate has been imported into DCM");
	        
	        ex.printStackTrace();
	        
        }

//        if(!success) {
//        	
//        	Qycdrnwc q = new Qycdrnwc();
//        	
//        	q.importCertificate(certFile);
//        	
//        }
	}
	
}

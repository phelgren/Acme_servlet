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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Servlet implementation class ACMEprocessing
 */
@WebServlet("/ACMEprocessing/*")
public class ACMEprocessing extends HttpServlet {
	private static final long serialVersionUID = 1L;

    private static final Logger LOG = LoggerFactory.getLogger(ACMEprocessing.class);
    
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ACMEprocessing() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    // CORS issues
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        setCorsHeaders(response);
        response.setStatus(HttpServletResponse.SC_OK);
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		String pathinfo = request.getPathInfo();
		String servetletpath = request.getServletPath();
		
		 if(pathinfo != null && pathinfo.startsWith("/api"))
			 api(request,response);
		 else if(pathinfo != null && pathinfo.startsWith("/configlist"))
				 getconfiglist(response);
		 else if(pathinfo != null && pathinfo.startsWith("/saveconfig"))
			 saveconfig(request,response);
		 else if(pathinfo != null && pathinfo.startsWith("/getconfig"))
			 getconfig(request,response);
		 else if(pathinfo != null && pathinfo.startsWith("/getmessages"))
			 writemsg(request,response);
		 else
			request.getRequestDispatcher("/index.html").forward(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		setCorsHeaders(response);
		
		 if(request.getPathInfo() != null && request.getPathInfo().startsWith("/api"))
			 api(request,response);
		 
	}
	
    private void setCorsHeaders(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
        response.setHeader("Access-Control-Max-Age", "3600");
    }
    
	// 5. Helper method to send SSE events
    private void sendEvent(PrintWriter writer, String type, String message) {
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
    
	public void api(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
//        // 2. Parse JSON config from request body
        BufferedReader reader = request.getReader();
        String jsonString = reader.lines().collect(Collectors.joining());
        JSONObject config = new JSONObject();
        JSONParser parser = new JSONParser();
//        
        Object obj = null;
        
        try{
        	obj = parser.parse(jsonString);
        }
        catch (Exception e)
        {
        	e.printStackTrace();
        }
       config = (JSONObject) obj;
//       
//        
        // 3. Extract config values (use camelCase names)

        String acme_challenge_type = (String) config.get("challengeType");
        Long timeout  = (Long) config.get("timeout");
        String dns_challenge_timeout = String.valueOf(timeout);
        String acme_request_type = (String) config.get("requestType");
        String domain_list = (String) config.get("domain");
        String acme_account = (String) config.get("accountKey");
        String acme_returned_cert_path_file = (String) config.get("certificatePath");
        String acme_wk_dir = (String) config.get("wellKnownDir");
        String acme_csr_path_file = (String) config.get("csr");
        String acme_work_folder = (String) config.get("wrkFolder");
        String action = (String) config.get("action");

		 String jsonreturned = "";
		 boolean result = false;
		 ACMEprocessor acmep = null;
		 
		 Collection<String> acme_domains = Arrays.asList(domain_list.split(",",-1));
		 
		HttpSession httpsess = request.getSession(true);
		
        // 1. Set up SSE response headers
        response.setContentType("text/event-stream");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-cache");
        response.setHeader("Connection", "keep-alive");
        
        PrintWriter writer = response.getWriter();
        
		
		// handling this all piecemeal.  This is subject to change but the ACME steps are:
		//	1) Create the processing object, storing all the parameters in the constructor
		//	2) Create a user key pair (from file)
		//	3) Create an ACME Session
		//	4) Find the account for ACME (from file)
		//	6) Create the certificate order
		//	7) Verify/authorize the domain (challenge)
		//	8) Wait for the order to complete
		//	9) on success, download the certificate (to file)
		
     // ADD THIS NULL CHECK
        if (acme_wk_dir == null || acme_wk_dir.trim().isEmpty()) {
            acme_wk_dir = acme_work_folder;
        }

		if(action.equals("reset"))
		{
			
			httpsess.setAttribute("acmep", null); //add the processing object to the session for future access
			
			result = true;
			
			jsonreturned = "{\"action\":\""+action+",\"result\":\""+result+"\"}";
		}
		
		if(action.equals("init"))
		{
			acmep = null;
			
			acmep = new ACMEprocessor(acme_domains, acme_challenge_type, dns_challenge_timeout, acme_request_type, acme_account, acme_csr_path_file,
					acme_work_folder, acme_returned_cert_path_file, acme_wk_dir);
			
			if(acmep!=null)
				httpsess.setAttribute("acmep", acmep);
			
			result = true;
			
			jsonreturned = "{\"action\":\""+action+",\"result\":\""+result+"\"}";
		}
		
		if(acmep!=null) {
			
			// if we have an object, act on it

			try {
				
				acmep.prepcert(response);  // builds the whole thing...
			
				
			} catch (IOException | AcmeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
        
        response.setContentType("application/json");
        
        // Get the printwriter object from response to write the required json object to the output stream      
        PrintWriter out = response.getWriter();  
    
        out.print(jsonreturned);
     
        out.flush();
     
	}
	
	@Deprecated //Configs are in DB now
	private void getconfiglist( HttpServletResponse response) throws IOException {
		
		String configlist = "";
		
		// We are configuring the location.  Make make it a configurable location
		// /etc/acmedcm/data
        File file = new File("/etc/acmedcm/data/");
        File[] files = file.listFiles();
        
        JSONObject jsoncontainer = new JSONObject();
        JSONArray array = new JSONArray();
        
        for(File f: files){
        	
        	JSONObject json = new JSONObject();
        	
        	// The file name will have json appended to it 
        	String noExt = removeFileExtension(f.getName(),false);
        	
        	json.put("configname",noExt);
        	
        	json.put("configpath", f.getAbsolutePath());
        	
        	array.add(json);
      
        }
        
        jsoncontainer.put("configs",array);
        
        configlist = jsoncontainer.toString();
        
        response.setContentType("application/json");
        
        // Get the printwriter object from response to write the required json object to the output stream      
        PrintWriter out = response.getWriter();  
    
        out.print(configlist);
     
        out.flush();
		
	}
	
	@Deprecated // Saved to DB now
	public void saveconfig(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		 String acme_challenge_type = request.getParameter("challenge_type");
		 String dns_challenge_timeout = request.getParameter("timeout");
		 String acme_request_type = request.getParameter("request_type");
		 String domain_list = request.getParameter("domain");
		 String acme_account = request.getParameter("account_key");
		 String acme_returned_cert_path_file = request.getParameter("certificate_path");
		 String acme_wk_dir = request.getParameter("well_known_dir"); // for HTTP01
		 String acme_csr_path_file = request.getParameter("csr");  // path and file
		 String acme_work_folder = request.getParameter("wrk_folder");  // path and file
		 String configname = request.getParameter("settings_text");
		 
		 String jsonreturned = "";
		 
		 String[] acme_domains = domain_list.split(",");
		 
		 // Save the contents in a json-formatted file - overwrite current values
		 
         JSONObject jsoncontainer = new JSONObject();
         
         JSONArray array = new JSONArray();
         
         if(configname!=null && configname.length()>0 && configname.indexOf("NEW")<0) {
        	 
        	 File dir = new File("/etc/acmecm/data");
        	 dir.mkdirs();
        	 
        	 File outputFile = new File("/etc/acmecm/data/"+configname + ".json");
        	 
        	 JSONObject json = new JSONObject();
        	 json.put("challenge_type", acme_challenge_type);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("timeout", dns_challenge_timeout);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("request_type", acme_request_type);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("domain", domain_list);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("account_key", acme_account);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("certificate_path", acme_returned_cert_path_file);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("well_known_dir", acme_wk_dir);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("csr", acme_csr_path_file);
        	 array.add(json);
        	 
        	 json = new JSONObject();
        	 json.put("wrk_folder", acme_work_folder);
        	 array.add(json);
        	 
      		// build the json file just a big string
             jsonreturned = array.toString();
             
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile));
             
             writer.write(jsonreturned);
             
             writer.close();

         }

	}
	
	@Deprecated  //I/O through DB now
	
	public void getconfig(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		String config_path = request.getParameter("configpath");

		Scanner in = new Scanner(new FileReader(config_path));
		
		StringBuilder sb = new StringBuilder();
		while(in.hasNext()) {
		    sb.append(in.next());
		}
		in.close();
		
		String outString = sb.toString();
		
        response.setContentType("application/json");
      
        PrintWriter out = response.getWriter();  
    
        out.print(outString);
     
        out.flush();
		
	}
	
	public static String removeFileExtension(String filename, boolean removeAllExtensions) {
	    if (filename == null || filename.isEmpty()) {
	        return filename;
	    }

	    String extPattern = "(?<!^)[.]" + (removeAllExtensions ? ".*" : "[^.]*$");
	    return filename.replaceAll(extPattern, "");
	}
	
	private void writemsg(HttpServletRequest request,HttpServletResponse response) {
		
        response.setContentType("text/event-stream");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        
		HttpSession httpsess = request.getSession(true);
		
		ACMEprocessor acmep = (ACMEprocessor) httpsess.getAttribute("acmep");
		
		if(acmep.msg != null && acmep.msg.length()==0)
			acmep.msg.append("Starting <br>");

		if(acmep != null) {
			
	        PrintWriter writer;
	        
			try {
				writer = response.getWriter();
				
		        if(acmep.msg.toString().indexOf("shutdown") < 0) {
		        	writer.write("data: " + acmep.msg.toString() + "\n\n");
			        writer.flush();
		        }
		        else
		        {
		        	acmep.msg.append("\r\n").append("Close ");
		        	writer.write("data: " + acmep.msg.toString() + "\n\n");
			        writer.flush();
		        }
			        writer.close();

		        
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		
	}
}

package com.lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.*;
import java.net.*;
import java.util.*;

public class SimpleVulnerable {
    private static final Logger logger = LogManager.getLogger(SimpleVulnerable.class);
    
    public static void main(String[] args) throws Exception {
        int port = 8080;
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("[*] Vulnerable Log4j server listening on port " + port);
        
        while (true) {
            Socket clientSocket = serverSocket.accept();
            handleRequest(clientSocket);
        }
    }
    
    private static void handleRequest(Socket clientSocket) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream());
        
        String line;
        Map<String, String> headers = new HashMap<>();
        String requestLine = in.readLine();
        
        // Read headers
        while ((line = in.readLine()) != null && !line.isEmpty()) {
            String[] parts = line.split(": ", 2);
            if (parts.length == 2) {
                headers.put(parts[0], parts[1]);
            }
        }
        
        // Read body if POST
        StringBuilder body = new StringBuilder();
        if (requestLine != null && requestLine.startsWith("POST")) {
            String contentLength = headers.get("Content-Length");
            if (contentLength != null) {
                int length = Integer.parseInt(contentLength);
                char[] buffer = new char[length];
                in.read(buffer, 0, length);
                body.append(buffer);
            }
        }
        
        // Log everything with vulnerable Log4j
        System.out.println("[+] Request: " + requestLine);
        
        // Log User-Agent (common injection point)
        String userAgent = headers.get("User-Agent");
        if (userAgent != null) {
            logger.info("User-Agent: " + userAgent);
            System.out.println("[*] Logged User-Agent: " + userAgent);
        }
        
        // Log custom headers
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (header.getKey().startsWith("X-")) {
                logger.info(header.getKey() + ": " + header.getValue());
                System.out.println("[*] Logged " + header.getKey() + ": " + header.getValue());
            }
        }
        
        // Log POST data
        if (body.length() > 0) {
            String bodyStr = body.toString();
            logger.info("Body: " + bodyStr);
            System.out.println("[*] Logged Body: " + bodyStr);
            
            // Parse URL encoded data
            if (bodyStr.contains("=")) {
                String[] params = bodyStr.split("&");
                for (String param : params) {
                    String[] kv = param.split("=", 2);
                    if (kv.length == 2) {
                        String key = URLDecoder.decode(kv[0], "UTF-8");
                        String value = URLDecoder.decode(kv[1], "UTF-8");
                        logger.info("Parameter " + key + " = " + value);
                        System.out.println("[*] Logged Parameter " + key + " = " + value);
                    }
                }
            }
        }
        
        // Send response
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: text/html");
        out.println();
        out.println("<h1>Log4Shell Test Server</h1>");
        out.println("<p>Your request has been logged.</p>");
        out.flush();
        
        clientSocket.close();
    }
}
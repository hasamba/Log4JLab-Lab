package com.lab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@SpringBootApplication
@RestController
public class VulnerableApp {
    
    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);
    
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }
    
    @GetMapping("/")
    public String home() {
        return "<h1>Log4Shell Vulnerable Application</h1>" +
               "<form action='/login' method='POST'>" +
               "Username: <input type='text' name='username'><br>" +
               "Password: <input type='password' name='password'><br>" +
               "<input type='submit' value='Login'>" +
               "</form>";
    }
    
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, 
                       HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String xApiVersion = request.getHeader("X-Api-Version");
        
        logger.info("Login attempt from user: " + username);
        logger.info("User-Agent: " + userAgent);
        
        if (xApiVersion != null) {
            logger.info("API Version: " + xApiVersion);
        }
        
        if ("admin".equals(username) && "password".equals(password)) {
            return "Login successful for user: " + username;
        } else {
            logger.error("Failed login for user: " + username);
            return "Login failed for user: " + username;
        }
    }
    
    @GetMapping("/api/v1/search")
    public String search(@RequestParam String query) {
        logger.info("Search query received: " + query);
        return "Search results for: " + query;
    }
    
    @PostMapping("/api/v1/callback")
    public String callback(@RequestBody Map<String, String> data) {
        String callback = data.get("callback");
        logger.info("Callback received: " + callback);
        return "Callback processed: " + callback;
    }
}
import java.io.*;
import java.net.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SimpleVulnerable {
    private static final Logger logger = LogManager.getLogger(SimpleVulnerable.class);

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8080, 50, InetAddress.getByName("0.0.0.0"));
        System.out.println("Log4Shell Test Server running on port 8080");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            handleRequest(clientSocket);
        }
    }

    private static void handleRequest(Socket clientSocket) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

        String inputLine;
        String userAgent = "";
        String requestLine = "";

        while ((inputLine = in.readLine()) != null) {
            if (inputLine.startsWith("GET") || inputLine.startsWith("POST")) {
                requestLine = inputLine;
            }
            if (inputLine.toLowerCase().startsWith("user-agent:")) {
                userAgent = inputLine.substring(12).trim();
            }
            if (inputLine.isEmpty()) break;
        }

        // Vulnerable logging - logs user input directly
        logger.info("Request: " + requestLine);
        logger.info("User-Agent: " + userAgent);

        // Send HTTP response
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: text/html");
        out.println();
        out.println("<h1>Log4Shell Test Server</h1>");
        out.println("<p>Your request has been logged.</p>");

        clientSocket.close();
    }
}
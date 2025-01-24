package com.cevher.keycloak;

import org.jboss.logging.Logger;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Client {
    private static final Logger log = Logger.getLogger(Client.class);
    private static final String WEBHOOK_URL = "KC_SPI_EVENT_LISTENER_KEYCLOAK_EVENTS_WEBHOOK_URL";

    private static final String WEBHOOK_KEYCLOAK_ISSUER = "KC_SPI_EVENT_LISTENER_KEYCLOAK_EVENTS_WEBHOOK_KEYCLOAK_ISSUER";
    private static final String WEBHOOK_KEYCLOAK_CLIENT_ID= "KC_SPI_EVENT_LISTENER_KEYCLOAK_EVENTS_WEBHOOK_KEYCLOAK_CLIENT_ID";
    private static final String WEBHOOK_KEYCLOAK_CLIENT_SECRET= "KC_SPI_EVENT_LISTENER_KEYCLOAK_EVENTS_WEBHOOK_KEYCLOAK_CLIENT_SECRET";
    private static final String WEBHOOK_KEYCLOAK_REALM= "KC_SPI_EVENT_LISTENER_KEYCLOAK_EVENTS_WEBHOOK_KEYCLOAK_REALM";
//     KEYCLOAK_ISSUER=https://infrapal.serverlesssalad.com/auth
// KEYCLOAK_CLIENT_ID=ss-backend
// KEYCLOAK_CLIENT_SECRET=lx2kfVGrqRJgwxqpFEc4ot5MTSYyh8A4



    public static void postService(String data) throws IOException {
        try {
            final String urlString = System.getenv(WEBHOOK_URL);
            log.debugf("WEBHOOK_URL: %s", urlString);

            if (urlString == null || urlString.isEmpty()) {
                throw new IllegalArgumentException("Environment variable WEBHOOK_URL is not set or is empty.");
            }

            String token = getAuthToken(); 
                        
            URL url = URI.create(urlString).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + token); // Add token to header
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");

            OutputStream os = conn.getOutputStream();
            os.write(data.getBytes());
            os.flush();

            final int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_CREATED && responseCode != HttpURLConnection.HTTP_OK) {
                throw new RuntimeException("Failed : HTTP error code : " + responseCode);
            }

            final BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String output;
            log.debugf("Output from Server .... \n");
            while ((output = br.readLine()) != null) {
                System.out.println(output);
                log.debugf("Input from Server: %s", output);
            }
            conn.disconnect();
        } catch (IOException e) {
            throw new IOException("Failed to post service: " + e.getMessage(), e);
        }
    }

    private static String getAuthToken() {
        // Example: Use Keycloak's Admin Client API to get a token
        String issuer = System.getenv(WEBHOOK_KEYCLOAK_ISSUER);
        String clientId = System.getenv(WEBHOOK_KEYCLOAK_CLIENT_ID);
        String clientSecret = System.getenv(WEBHOOK_KEYCLOAK_CLIENT_SECRET);
        String realm = System.getenv(WEBHOOK_KEYCLOAK_REALM);

        if (issuer == null || issuer.isEmpty() || clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty() || realm == null || realm.isEmpty()) {
            throw new IllegalArgumentException("Environment variable WEBHOOK_KEYCLOAK_ISSUER or WEBHOOK_KEYCLOAK_CLIENT_ID or WEBHOOK_KEYCLOAK_CLIENT_SECRET or WEBHOOK_KEYCLOAK_REALM is not set or is empty.");
        }
        
        String authUrl = issuer + "/realms/" + realm + "/protocol/openid-connect/token";
        try {
            URL url = new URL(authUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    
            String body = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret;
            try (OutputStream os = connection.getOutputStream()) {
                os.write(body.getBytes("utf-8"));
            }
    
            if (connection.getResponseCode() == 200) {
                try (InputStream is = connection.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
    
                    // Parse the token from the response
                    String responseBody = response.toString();
                    JsonObject jsonResponse = JsonParser.parseString(responseBody).getAsJsonObject();
                    return jsonResponse.get("access_token").getAsString();
                }
            } else {
                throw new RuntimeException("Failed to get token: " + connection.getResponseCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while obtaining auth token", e);
        }
    }
}

package com.securitytester.service;

import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
// CloseableHttpResponse no longer used after refactor to response-handler API
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Simple HTTP proxy utility used by the UI to send outgoing HTTP requests.
 *
 * <p>This class centralizes request creation, header handling and body extraction
 * so the UI code can remain focused on presentation. It uses Apache HttpClient
 * with a response handler to safely read entity bodies.</p>
 */
public class ProxyService {
    private static final Logger logger = LoggerFactory.getLogger(ProxyService.class);

    /**
     * Send an HTTP request and return a simple response wrapper.
     *
     * @param url full request URL
     * @param method HTTP method (GET, POST, PUT, ...)
     * @param headers optional headers map
     * @param body optional request body for POST/PUT
     * @return HttpResponse containing status code and body as string
     */
    public HttpResponse sendRequest(String url, String method, Map<String, String> headers, String body) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }
        if (method == null) {
            throw new IllegalArgumentException("HTTP method cannot be null");
        }

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            // Sanitize URL
            String sanitizedUrl = url.trim();
            if (!sanitizedUrl.startsWith("http://") && !sanitizedUrl.startsWith("https://")) {
                sanitizedUrl = "http://" + sanitizedUrl;
            }
            logger.debug("Sending {} request to URL: {}", method, sanitizedUrl);

            // Create request
            HttpUriRequestBase request = createRequest(sanitizedUrl, method);

            // Add headers
            if (headers != null) {
                headers.forEach((key, value) -> {
                    if (key != null && value != null) {
                        request.addHeader(key, value);
                    }
                });
            }

            // Add body for POST/PUT
            if (("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) && body != null) {
                if (request instanceof HttpPost) {
                    ((HttpPost) request).setEntity(new StringEntity(body));
                } else if (request instanceof HttpPut) {
                    ((HttpPut) request).setEntity(new StringEntity(body));
                }
            }

            // Send request using response handler (non-deprecated API)
            HttpResponse result = client.execute(request, response -> {
                String responseContent = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                logger.debug("Received response with status: {}", response.getCode());
                return new HttpResponse(response.getCode(), responseContent);
            });

            return result;

        } catch (Exception e) {
            logger.error("Failed to send request to {}: {}", url, e.getMessage(), e);
            throw new RuntimeException("Failed to send request: " + e.getMessage(), e);
        }
    }

    private HttpUriRequestBase createRequest(String url, String method) {
        return switch (method.toUpperCase()) {
            case "GET" -> new HttpGet(url);
            case "POST" -> new HttpPost(url);
            case "PUT" -> new HttpPut(url);
            case "DELETE" -> new HttpDelete(url);
            case "HEAD" -> new HttpHead(url);
            case "OPTIONS" -> new HttpOptions(url);
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        };
    }

    public static class HttpResponse {
        /**
         * A lightweight response container used by the UI layer.
         */
        private final int statusCode;
        private final String body;

        public HttpResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getBody() {
            return body;
        }
    }
}
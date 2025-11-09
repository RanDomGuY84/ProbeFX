package com.securitytester.model;

import java.time.LocalDateTime;

/**
 * Simple POJO used to keep a record of a performed request. This replaced
 * the original persistence entity to avoid Spring/JPA complexity in the
 * desktop application rewrite.
 */
public class RequestRecord {
    private Long id;
    private String method;
    private String url;
    private String headers;
    private String requestBody;
    private String responseBody;
    private int statusCode;
    private String scanResults;
    private LocalDateTime timestamp;

    public RequestRecord() {
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getHeaders() { return headers; }
    public void setHeaders(String headers) { this.headers = headers; }

    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public String getScanResults() { return scanResults; }
    public void setScanResults(String scanResults) { this.scanResults = scanResults; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}

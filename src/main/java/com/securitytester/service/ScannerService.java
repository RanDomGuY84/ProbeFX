package com.securitytester.service;


import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.net.URI;
import java.net.URISyntaxException;
/**
 * Lightweight heuristic scanner that looks for common classes of vulnerabilities
 * in HTTP requests/responses. It is intentionally conservative and returns human-
 * readable findings which can be refined later.
 */
public class ScannerService {
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|'--|;--|/\\*|\\*/|@@|@\\w+)\\b.*\\b(FROM|INTO|WHERE|TABLE|DATABASE|INFORMATION_SCHEMA)\\b)");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i)(<script|javascript:|data:|vbscript:|\\\\u|\\\\x|onerror=|onload=|onfocus=|onmouseover=|eval\\(|String\\.fromCharCode|\\bdocument\\.|\\bwindow\\.|alert\\(|confirm\\(|prompt\\()");
    private static final Pattern SSRF_PATTERN = Pattern.compile("(?i)(file:|gopher:|dict:|ldap:|ssh2:|tcp:|telnet:|ftp:|jar:)");
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile("(?i)(\\.\\./|%2e%2e/|%252e%252e/)");
    private static final Pattern SENSITIVE_DATA_PATTERN = Pattern.compile("(?i)(password|passwd|pwd|secret|token|api[_-]?key|auth|credential)");
    private static final Pattern RCE_PATTERN = Pattern.compile("(?i)(\\b(exec|system|popen|pcntl_exec|shell_exec|passthru|eval|assert)\\b)");
    private static final Pattern NOSQL_INJECTION_PATTERN = Pattern.compile("(?i)(\\$where|\\$regex|\\$gt|\\$lt|\\$ne|\\$in|\\$nin)");
    
    public List<String> scanForVulnerabilities(String url, Map<String, String> headers, String requestBody, String responseBody) {
        List<String> findings = new ArrayList<>();
        
        // Transport Security Checks
        checkTransportSecurity(url, headers, findings);
        
        // Header Security Checks
        checkSecurityHeaders(headers, findings);
        
        // Content Security Checks
        if (responseBody != null) {
            checkContentSecurity(responseBody, findings);
        }
        
        // Request Analysis
        if (requestBody != null) {
            checkRequestSecurity(requestBody, findings);
        }
        
        return findings;
    }

    /**
     * Check transport-level properties such as HTTPS/HSTS presence.
     */
    private void checkTransportSecurity(String url, Map<String, String> headers, List<String> findings) {
        try {
            URI uri = new URI(url);
            if (!uri.getScheme().equals("https")) {
                findings.add("OWASP A02:2021 - Cryptographic Failures: Not using HTTPS");
            }
            
            String hsts = headers.get("Strict-Transport-Security");
            if (hsts == null || hsts.isEmpty()) {
                findings.add("OWASP A02:2021 - Cryptographic Failures: Missing HSTS header");
            }
        } catch (URISyntaxException e) {
            findings.add("Invalid URL format: " + e.getMessage());
        }
    }

    /**
     * Check for common security-related headers and misconfigurations.
     */
    private void checkSecurityHeaders(Map<String, String> headers, List<String> findings) {
        // CSP Check
        if (!headers.containsKey("Content-Security-Policy")) {
            findings.add("OWASP A05:2021 - Security Misconfiguration: Missing Content Security Policy");
        }
        
        // X-Frame-Options Check
        String xframe = headers.get("X-Frame-Options");
        if (xframe == null || (!xframe.equals("DENY") && !xframe.equals("SAMEORIGIN"))) {
            findings.add("OWASP A05:2021 - Security Misconfiguration: Missing or weak X-Frame-Options");
        }
        
        // CORS Check
        String cors = headers.get("Access-Control-Allow-Origin");
        if (cors != null && cors.equals("*")) {
            findings.add("OWASP A05:2021 - Security Misconfiguration: Overly permissive CORS policy");
        }

        // Cache Control
        if (!headers.containsKey("Cache-Control") || !headers.containsKey("Pragma")) {
            findings.add("OWASP A01:2021 - Broken Access Control: Missing cache control headers");
        }

        // Security Headers
        checkMissingSecurityHeaders(headers, findings);
    }

    private void checkMissingSecurityHeaders(Map<String, String> headers, List<String> findings) {
        String[] securityHeaders = {
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Embedder-Policy"
        };

        for (String header : securityHeaders) {
            if (!headers.containsKey(header)) {
                findings.add("OWASP A05:2021 - Security Misconfiguration: Missing " + header);
            }
        }
    }

    /**
     * Scan response content for heuristic indicators of vulnerabilities
     * (XSS, SQLi, SSRF, path traversal, sensitive data, etc.).
     */
    private void checkContentSecurity(String content, List<String> findings) {
        // XSS Detection
        if (XSS_PATTERN.matcher(content).find()) {
            findings.add("OWASP A03:2021 - Injection: Potential XSS vulnerability detected");
        }
        
        // SQL Injection Detection
        if (SQL_INJECTION_PATTERN.matcher(content).find()) {
            findings.add("OWASP A03:2021 - Injection: Potential SQL injection vulnerability detected");
        }
        
        // NoSQL Injection Detection
        if (NOSQL_INJECTION_PATTERN.matcher(content).find()) {
            findings.add("OWASP A03:2021 - Injection: Potential NoSQL injection detected");
        }

        // SSRF Detection
        if (SSRF_PATTERN.matcher(content).find()) {
            findings.add("OWASP A10:2021 - Server-Side Request Forgery: Potential SSRF vulnerability detected");
        }

        // Path Traversal Detection
        if (PATH_TRAVERSAL_PATTERN.matcher(content).find()) {
            findings.add("OWASP A01:2021 - Broken Access Control: Potential path traversal detected");
        }

        // Sensitive Data Exposure
        if (SENSITIVE_DATA_PATTERN.matcher(content).find()) {
            findings.add("OWASP A02:2021 - Cryptographic Failures: Potential sensitive data exposure");
        }

        // Remote Code Execution
        if (RCE_PATTERN.matcher(content).find()) {
            findings.add("OWASP A08:2021 - Software and Data Integrity Failures: Potential RCE vulnerability");
        }
    }

    /**
     * Analyze the request body for missing CSRF tokens and potential sensitive data.
     */
    private void checkRequestSecurity(String requestBody, List<String> findings) {
        // Check for potential CSRF tokens
        if (!requestBody.contains("csrf") && !requestBody.contains("_token")) {
            findings.add("OWASP A01:2021 - Broken Access Control: Missing CSRF token");
        }
        
        // Check for sensitive data in request
        if (SENSITIVE_DATA_PATTERN.matcher(requestBody).find()) {
            findings.add("OWASP A02:2021 - Cryptographic Failures: Sensitive data in request body");
        }
    }
}
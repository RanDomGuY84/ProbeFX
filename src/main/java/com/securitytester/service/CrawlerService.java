package com.securitytester.service;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Improved crawler using BFS with timeout, same-host filtering and a max-pages limit.
 *
 * <p>This service performs a breadth-first crawl starting from a base URL. It keeps
 * results deterministic (insertion order) by returning a {@link java.util.LinkedHashSet}.
 * The crawler is intentionally conservative: it limits pages, enforces same-host
 * crawling, strips URL fragments and normalizes trailing slashes.</p>
 */
public class CrawlerService {
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final String USER_AGENT = "ProbeFX/1.0";
    private static final int MAX_PAGES = 500; // hard cap to avoid runaway crawls

    /**
     * Crawl the site starting at {@code baseUrl} up to {@code maxDepth} levels.
     *
     * @param baseUrl starting URL (scheme required or will default to http)
     * @param maxDepth maximum link-depth to follow (root = 0)
     * @return ordered set of visited URLs (may be empty on error)
     * @throws IOException when Jsoup fails to fetch a page
     */
    public Set<String> crawl(String baseUrl, int maxDepth) throws IOException {
        Set<String> visited = new LinkedHashSet<>();
        if (baseUrl == null || baseUrl.isBlank()) return visited;

        String normalizedBase = normalizeUrl(baseUrl);
        String baseHost = getHost(normalizedBase);
        if (baseHost == null) return visited;

        ArrayDeque<UrlDepth> queue = new ArrayDeque<>();
        queue.add(new UrlDepth(normalizedBase, 0));

        while (!queue.isEmpty() && visited.size() < MAX_PAGES) {
            UrlDepth current = queue.poll();
            if (current.depth > maxDepth) continue;
            String url = current.url;
            if (visited.contains(url)) continue;

            String host = getHost(url);
            if (host == null || !host.equalsIgnoreCase(baseHost)) continue;

            visited.add(url);

            try {
                Document doc = Jsoup.connect(url)
                        .userAgent(USER_AGENT)
                        .timeout(DEFAULT_TIMEOUT_MS)
                        .followRedirects(true)
                        .maxBodySize(0)
                        .get();

                for (Element link : doc.select("a[href]")) {
                    String next = link.absUrl("href");
                    next = normalizeUrl(next);
                    if (next.isEmpty()) continue;
                    if (visited.contains(next)) continue;
                    if (queue.size() + visited.size() >= MAX_PAGES) break;
                    queue.add(new UrlDepth(next, current.depth + 1));
                }
            } catch (IOException e) {
                // ignore and continue
            }
        }

        return visited;
    }

    private String normalizeUrl(String url) {
        if (url == null) return "";
        url = url.trim();
        if (url.isEmpty()) return "";
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }
        // Remove fragment
        int hash = url.indexOf('#');
        if (hash >= 0) url = url.substring(0, hash);
        // Remove trailing slash for consistency
        if (url.endsWith("/")) url = url.substring(0, url.length()-1);
        return url;
    }

    private String getHost(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return null;
            return host.startsWith("www.") ? host.substring(4) : host;
        } catch (URISyntaxException e) {
            // Invalid URL; caller will skip this entry
            return null;
        }
    }

    private static class UrlDepth {
        final String url;
        final int depth;
        UrlDepth(String url, int depth) { this.url = url; this.depth = depth; }
    }
}
package io.scamshield.api;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** In-memory token bucket per client IP for POST /api/v1/analyze, so a public demo cannot be flooded. */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final int perMinute;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitFilter(@Value("${scamshield.rate-limit.per-minute:20}") int perMinute) {
        this.perMinute = perMinute;
    }

    static final class Bucket {
        private double tokens;
        private long last;

        Bucket(double tokens, long now) {
            this.tokens = tokens;
            this.last = now;
        }

        synchronized boolean take(int capacity, long now) {
            tokens = Math.min(capacity, tokens + (now - last) * capacity / 60_000.0);
            last = now;
            if (tokens >= 1) {
                tokens -= 1;
                return true;
            }
            return false;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        return !("POST".equals(req.getMethod()) && req.getRequestURI().startsWith("/api/v1/analyze"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        long now = System.currentTimeMillis();
        String fwd = req.getHeader("X-Forwarded-For");
        String ip = fwd != null && !fwd.isBlank() ? fwd.split(",")[0].strip() : req.getRemoteAddr();
        if (buckets.size() > 10_000) {
            buckets.clear();
        }
        Bucket b = buckets.computeIfAbsent(ip, k -> new Bucket(perMinute, now));
        if (!b.take(perMinute, now)) {
            res.setStatus(429);
            res.setContentType("application/json");
            res.getWriter().write("{\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Rate limit reached, try again in a minute.\"}");
            return;
        }
        chain.doFilter(req, res);
    }
}

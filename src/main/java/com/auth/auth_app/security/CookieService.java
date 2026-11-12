
package com.auth.auth_app.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Getter
public class CookieService {

    private static final Logger logger =
            LoggerFactory.getLogger(CookieService.class);

    private final String accessTokenCookieName;
    private final String refreshTokenCookieName;

    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(
            @Value("${security.jwt.access-cookie-name}") String accessTokenCookieName,
            @Value("${security.jwt.refresh-cookie-name}") String refreshTokenCookieName,
            @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
            @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
            @Value("${security.jwt.cookie-same-site}") String cookieSameSite,
            @Value("${security.jwt.cookie-domain:}") String cookieDomain
    ) {
        this.accessTokenCookieName = accessTokenCookieName;
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieSameSite = cookieSameSite;
        this.cookieDomain = cookieDomain;
    }

    public void attachAccessCookie(
            HttpServletResponse response,
            String value,
            int maxAge
    ) {
        attachCookie(response, accessTokenCookieName, value, maxAge);
    }

    public void attachRefreshCookie(
            HttpServletResponse response,
            String value,
            int maxAge
    ) {
        attachCookie(response, refreshTokenCookieName, value, maxAge);
    }

    private void attachCookie(
            HttpServletResponse response,
            String cookieName,
            String value,
            int maxAge
    ) {
        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(cookieName, value)
                        .httpOnly(cookieHttpOnly)
                        .secure(cookieSecure)
                        .path("/")
                        .maxAge(maxAge)
                        .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        response.addHeader(
                HttpHeaders.SET_COOKIE,
                builder.build().toString()
        );

        // Never log the actual token value.
        logger.info("Cookie attached: {}", cookieName);
    }

    public void clearAccessCookie(HttpServletResponse response) {
        clearCookie(response, accessTokenCookieName);
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        clearCookie(response, refreshTokenCookieName);
    }

    private void clearCookie(
            HttpServletResponse response,
            String cookieName
    ) {
        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(cookieName, "")
                        .httpOnly(cookieHttpOnly)
                        .secure(cookieSecure)
                        .path("/")
                        .maxAge(0)
                        .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        response.addHeader(
                HttpHeaders.SET_COOKIE,
                builder.build().toString()
        );
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        response.setHeader(
                "Cache-Control",
                "no-store, no-cache, must-revalidate, max-age=0"
        );
        response.setHeader("Pragma", "no-cache");
    }
}

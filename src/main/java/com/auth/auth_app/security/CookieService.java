package com.auth.auth_app.security;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Getter
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String  cookieDomain;
    private final String cookieSameSite;

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(CookieService.class);

    public CookieService(
            @Value("${security.jwt.refresh-cookie-name}") String refreshTokenCookieName,
            @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
            @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
            @Value("${security.jwt.cookie-same-site}") String cookieSameSite,
            @Value("${security.jwt.cookie-domain:}") String cookieDomain
    ) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieSameSite = cookieSameSite;
        this.cookieDomain = cookieDomain;
    }

    public void attachRefreshCookie(HttpServletResponse response,String value,int maxAge){

        logger.info("Attaching Cookie with name: {} and value: {}",refreshTokenCookieName,value);
     var responseCookieBuilder =  ResponseCookie.from(refreshTokenCookieName,value)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookieSameSite);

     if (cookieDomain != null && !cookieDomain.isBlank()){
         responseCookieBuilder.domain(cookieDomain);

        }
    ResponseCookie  responseCookie= responseCookieBuilder.build();
     response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
    }

    public void clearRefreshCookie(HttpServletResponse response){
     var  builder = ResponseCookie.from(refreshTokenCookieName,"")
                .maxAge(0)
                .httpOnly(cookieHttpOnly)
                .path("/")
                .sameSite(cookieSameSite)
                .secure(cookieSecure);


        if (cookieDomain != null && !cookieDomain.isBlank()){
            builder.domain(cookieDomain);

        }
        ResponseCookie  responseCookie= builder.build();
        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
    }
}
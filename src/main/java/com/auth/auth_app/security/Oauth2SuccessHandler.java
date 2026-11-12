
package com.auth.auth_app.security;

import com.auth.auth_app.entity.Provider;
import com.auth.auth_app.entity.RefreshToken;
import com.auth.auth_app.entity.User;
import com.auth.auth_app.repositary.RefreshRepositary;
import com.auth.auth_app.repositary.UserRepositary;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger =
            LoggerFactory.getLogger(Oauth2SuccessHandler.class);

    private final UserRepositary userRepositary;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshRepositary refreshRepositary;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        logger.info("Google OAuth2 authentication successful");

        OAuth2User oauth2User =
                (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";

        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        User user;

        if (registrationId.equals("google")) {
            assert oauth2User != null;
            String googleId =
                    oauth2User.getAttribute("sub");

            String email =
                    oauth2User.getAttribute("email");

            String name =
                    oauth2User.getAttribute("name");

            String picture =
                    oauth2User.getAttribute("picture");

            if (email == null || email.isBlank()) {
                throw new IllegalStateException(
                        "Google account email is missing"
                );
            }

            User newUser = User.builder()
                    .email(email)
                    .name(name)
                    .image(picture)
                    .provider(Provider.GOOGLE)
                    .build();

            // Find existing user or create a new one.
            user = userRepositary.findByEmail(email)
                    .orElseGet(() -> userRepositary.save(newUser));

            logger.info("Google user resolved successfully");
        } else {
            throw new IllegalStateException(
                    "Invalid OAuth2 registration ID: " + registrationId
            );
        }

        // Generate a unique JTI for the refresh token.
        String jti = UUID.randomUUID().toString();

        // Save refresh token information in the database.
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(
                        Instant.now().plusSeconds(
                                jwtService.getRefreshTtlSeconds()
                        )
                )
                .build();

        refreshRepositary.save(refreshTokenEntity);

        // Generate JWT tokens.
        String accessToken =
                jwtService.generateAccessToken(user);

        String refreshToken =
                jwtService.generateRefreshToken(user, jti);

        // Attach both cookies to the response.
        cookieService.attachAccessCookie(
                response,
                accessToken,
                (int) jwtService.getAccessTtlSeconds()
        );

        cookieService.attachRefreshCookie(
                response,
                refreshToken,
                (int) jwtService.getRefreshTtlSeconds()
        );

        cookieService.addNoStoreHeader(response);

        logger.info("JWT cookies attached successfully");

        // Redirect to frontend.

    }
}


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

        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            throw new IllegalStateException("Invalid OAuth2 authentication");
        }

        String registrationId = token.getAuthorizedClientRegistrationId();
        OAuth2User oauth2User = token.getPrincipal();

        logger.info("OAuth2 login successful with provider: {}", registrationId);

        User user;

        if ("google".equals(registrationId)) {

            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name");
            String picture = oauth2User.getAttribute("picture");

            if (email == null || email.isBlank()) {
                throw new IllegalStateException("Google email is missing");
            }

            User newUser = User.builder()
                    .email(email)
                    .name(name)
                    .image(picture)
                    .enable(true)
                    .provider(Provider.GOOGLE)
                    .build();

            user = userRepositary.findByEmail(email)
                    .orElseGet(() -> userRepositary.save(newUser));

            logger.info("Google user resolved successfully");

        } else if ("github".equals(registrationId)) {

            String githubId = String.valueOf(oauth2User.getAttribute("id"));
            String username = oauth2User.getAttribute("login");
            String name = oauth2User.getAttribute("name");
            String picture = oauth2User.getAttribute("avatar_url");
            String email = oauth2User.getAttribute("email");

            if (email == null || email.isBlank()) {
                throw new IllegalStateException(
                        "GitHub email is private or unavailable. Configure GitHub email retrieval."
                );
            }

            if (name == null || name.isBlank()) {
                name = username;
            }

            User newUser = User.builder()
                    .email(email)
                    .name(name)
                    .image(picture)
                    .provider(Provider.GITHUB)
                    .build();

            user = userRepositary.findByEmail(email)
                    .orElseGet(() -> userRepositary.save(newUser));

            logger.info("GitHub user resolved successfully: {}", username);

        } else {
            throw new IllegalStateException(
                    "Unsupported OAuth2 registration ID: " + registrationId
            );
        }

        String jti = UUID.randomUUID().toString();

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

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, jti);

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

        logger.info("{} JWT cookies attached successfully", registrationId);

        // Redirect to your frontend after successful login.
        response.sendRedirect("http://localhost:3000");
    }
}

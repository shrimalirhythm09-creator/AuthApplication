
package com.auth.auth_app.security;

import com.auth.auth_app.helper.UserHelper;
import com.auth.auth_app.repositary.UserRepositary;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger =
            LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtService jwtService;
    private final UserRepositary userRepositary;
    private final CookieService cookieService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            String token = null;

            // 1. Extract JWT from Authorization header
            String header = request.getHeader("Authorization");

            if (header != null && header.startsWith("Bearer ")) {
                token = header.substring(7);
            }

            // 2. Extract JWT from access_token cookie
            if ((token == null || token.isBlank())
                    && request.getCookies() != null) {

                for (Cookie cookie : request.getCookies()) {

                    if (cookieService.getAccessTokenCookieName()
                            .equals(cookie.getName())) {

                        token = cookie.getValue();
                        break;
                    }
                }
            }

            logger.info("JWT token present: {}",
                    token != null && !token.isBlank());

            // 3. No token: continue without authentication
            if (token == null || token.isBlank()) {
                filterChain.doFilter(request, response);
                return;
            }

            // 4. Validate and parse JWT
            Claims claims = jwtService.parseToken(token);

            // 5. Only accept access tokens
            String tokenType = claims.get("typ", String.class);

            if (!"access".equals(tokenType)) {
                logger.warn("Invalid JWT token type: {}", tokenType);
                request.setAttribute("error", "Invalid Access Token");

                filterChain.doFilter(request, response);
                return;
            }

            // 6. Extract user UUID from JWT subject
            UUID userUuid = UserHelper.parseUUID(claims.getSubject());

            // 7. Fetch user from database
            var optionalUser = userRepositary.findById(userUuid);

            logger.info("User exists in database: {}",
                    optionalUser.isPresent());

            if (optionalUser.isEmpty()) {
                request.setAttribute("error", "User Not Found");
                logger.warn("JWT user not found: {}", userUuid);

                filterChain.doFilter(request, response);
                return;
            }

            var user = optionalUser.get();

            // 8. Check whether user is enabled
            if (!user.isEnable()) {
                request.setAttribute("error", "User Disabled");
                logger.warn("JWT user is disabled: {}", user.getEmail());

                filterChain.doFilter(request, response);
                return;
            }

            logger.info("JWT user found: {}", user.getEmail());

            // 9. Set authentication only if not already authenticated
            if (SecurityContextHolder.getContext().getAuthentication() == null
                    || !SecurityContextHolder.getContext()
                    .getAuthentication().isAuthenticated()) {

                // 10. Get user authorities
                List<GrantedAuthority> authorities =
                        user.getRoles() == null
                                ? List.of()
                                : user.getRoles().stream()
                                .map(role -> (GrantedAuthority)
                                        new SimpleGrantedAuthority(
                                                role.getName().startsWith("ROLE_")
                                                        ? role.getName()
                                                        : "ROLE_" + role.getName()
                                        ))
                                .toList();

                // 11. Create authenticated object
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                user.getEmail(),
                                null,
                                authorities
                        );

                authentication.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                );

                // 12. Store authentication in SecurityContext
                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);

                logger.info("JWT authentication successful for: {}",
                        user.getEmail());

                logger.info("Is authenticated: {}",
                        authentication.isAuthenticated());

                logger.info("Authorities: {}", authorities);
            }

        } catch (ExpiredJwtException e) {

            request.setAttribute("error", "Token Expired");
            logger.warn("JWT token expired");

        } catch (Exception e) {

            request.setAttribute("error", "Invalid Token");
            logger.error("JWT validation failed: {}", e.getMessage(), e);
        }

        // 13. Continue filter chain
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();

        return path.equals("/api/v1/auth/register")
                || path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/refresh");
    }
}

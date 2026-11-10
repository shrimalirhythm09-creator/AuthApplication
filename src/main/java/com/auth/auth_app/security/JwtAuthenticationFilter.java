
package com.auth.auth_app.security;

import com.auth.auth_app.helper.UserHelper;
import com.auth.auth_app.repositary.UserRepositary;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepositary userRepositary;
    private  Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        logger.info("Authentication header : {}",header);
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        try {

            Claims payload = jwtService.parseToken(token);

            // Check token type
            if (!"access".equals(payload.get("typ", String.class))) {
                filterChain.doFilter(request, response);
                return;
            }

            // Extract user ID
            UUID userUuid = UserHelper.parseUUID(payload.getSubject());

            // Find user
            userRepositary.findById(userUuid)
                    .filter(user -> user.isEnable())
                    .ifPresent(user -> {

                        // Extract authorities
                        List<GrantedAuthority> authorities =
                                user.getRoles() == null
                                        ? List.of()
                                        : user.getRoles().stream()
                                        .map(role -> new SimpleGrantedAuthority(
                                                role.getName()
                                        ))
                                        .collect(Collectors.toList());

                        // Create authentication
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

                        // Set authentication
                        if (SecurityContextHolder.getContext()
                                .getAuthentication() == null) {

                            SecurityContextHolder.getContext()
                                    .setAuthentication(authentication);
                        }
                    });

        } catch (ExpiredJwtException e) {
            request.setAttribute("error", "Token Expired");

        } catch (Exception e) {
            request.setAttribute("error", "Invalid Token");
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().startsWith("/api/v1/auth/");
    }
}

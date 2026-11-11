package com.auth.auth_app.controllers;

import com.auth.auth_app.dto.LoginRequest;
import com.auth.auth_app.dto.RefreshTokenRequest;
import com.auth.auth_app.dto.TokenResponse;
import com.auth.auth_app.dto.UserDto;
import com.auth.auth_app.entity.RefreshToken;
import com.auth.auth_app.entity.User;
import com.auth.auth_app.repositary.RefreshRepositary;
import com.auth.auth_app.repositary.UserRepositary;
import com.auth.auth_app.security.CookieService;
import com.auth.auth_app.security.JwtService;
import com.auth.auth_app.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@AllArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService  authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepositary userRepositary;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final RefreshRepositary refreshRepositary;
    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse>login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ){
          Authentication authenticate =  authenticate(loginRequest);
          User user = userRepositary.findByEmail(loginRequest.email()).orElseThrow(()
                  -> new BadCredentialsException("Invalid username or password"));
          if (!user.isEnable()){
              throw new DisabledException("User is disabled");
          }

        String jti = UUID.randomUUID().toString();

        var refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.generateRefreshTokenExpiry()))
                .revoked(false)
                .build();

        refreshRepositary.save(refreshTokenOb);

          String accessToken = jwtService.generateAccessToken(user);
          String refreshToken = jwtService.generateRefreshToken(user,refreshTokenOb.getJti());


          cookieService.attachRefreshCookie(response,refreshToken, (int) jwtService.getRefreshTtlSeconds());
          cookieService.addNoStoreHeader(response);

             TokenResponse tokenResponse = TokenResponse.of
                                (accessToken,
                                  refreshToken,
                                  jwtService.getAccessTtlSeconds(),
                                  modelMapper.map(user,UserDto.class));


                  return ResponseEntity.ok(tokenResponse);

    }
    private Authentication authenticate(LoginRequest loginRequest) {

        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.email(),
                        loginRequest.password()
                )
        );
    }

     @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto){
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerDto(userDto));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
          @RequestBody(required = false) RefreshTokenRequest body,
          HttpServletResponse response,
          HttpServletRequest request
    ){

        String refreshToken = readRefreshTokenFromRequest(body,request).orElseThrow(()
                -> new BadCredentialsException("Invalid Refresh Token"));
          if(!jwtService.isRefreshToken(refreshToken)){
              throw  new BadCredentialsException("Invalid Refresh Token Type");
          }
          String jti = jwtService.getJti(refreshToken);
          UUID userId = jwtService.getUserId(refreshToken);
      RefreshToken storedRefreshToken =  refreshRepositary.findByJti(jti).orElseThrow(()
              -> new BadCredentialsException("Invalid Refresh Token"));

      if (storedRefreshToken.isRevoked()){
          throw new BadCredentialsException("Invalid Refresh Token");
      }

      if (storedRefreshToken.getExpiresAt().isBefore(Instant.now())){
        throw  new BadCredentialsException("Invalid Refresh Token");
      }
      if (storedRefreshToken.getUser().getId().equals(userId)){
          throw new BadCredentialsException("Invalid Refresh Token");
      }

      storedRefreshToken.setRevoked(true);
      String newJti = UUID.randomUUID().toString();
      refreshRepositary.save(storedRefreshToken);

     User user = storedRefreshToken.getUser();

     var newRefreshTokenOb = RefreshToken.builder()
             .jti(newJti)
             .user(user)
             .createdAt(Instant.now())
             .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
             .revoked(false)
             .build();


     refreshRepositary.save(newRefreshTokenOb);


     String newAccessToken = jwtService.generateAccessToken(user);
     String newRefreshToken = jwtService.generateRefreshToken(user,newRefreshTokenOb.getJti());


     cookieService.attachRefreshCookie(response,newRefreshToken,(int) jwtService.getRefreshTtlSeconds());
     cookieService.addNoStoreHeader(response);
     return ResponseEntity.ok(TokenResponse.of(newAccessToken,newRefreshToken,
             jwtService.getAccessTtlSeconds(),modelMapper.map(user,UserDto.class)));

    }

    private Optional<String>  readRefreshTokenFromRequest(RefreshTokenRequest body,
                                                          HttpServletRequest request) {
        if (request.getCookies() != null){
         Optional<String> fromCoookie =  Arrays.stream(
                    request.getCookies()
            ).filter(c-> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();


         if (fromCoookie.isPresent()){
             return fromCoookie;
         }

        }
       if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()){
           return Optional.of(body.refreshToken());
       }

       String refreshHeader = request.getHeader("X-Refresh-Token");
      if (refreshHeader != null && !refreshHeader.isBlank()){
          return Optional.of(refreshHeader.trim());
      }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();

            if (!token.isEmpty()){
                try{
                    if (jwtService.isRefreshToken(token)){
                        return Optional.of(token);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
       return Optional.empty();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        Optional<String> refreshTokenOptional =
                readRefreshTokenFromRequest(body, request);

        if (refreshTokenOptional.isPresent()) {
            String refreshToken = refreshTokenOptional.get();
            try {
                if (jwtService.isRefreshToken(refreshToken)) {
                    String jti = jwtService.getJti(refreshToken);
                    refreshRepositary.findByJti(jti).ifPresent(storedToken -> {
                        if (!storedToken.isRevoked()) {
                            storedToken.setRevoked(true);
                            refreshRepositary.save(storedToken);
                        }
                    });
                }
            } catch (RuntimeException e) {
                // Invalid or expired token.
                // Continue with cookie clearing.
            }
        }
        // Clear refresh token cookie
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        return ResponseEntity.noContent().build();
    }
}

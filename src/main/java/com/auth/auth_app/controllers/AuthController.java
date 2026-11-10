package com.auth.auth_app.controllers;

import com.auth.auth_app.dto.LoginRequest;
import com.auth.auth_app.dto.TokenResponse;
import com.auth.auth_app.dto.UserDto;
import com.auth.auth_app.entity.User;
import com.auth.auth_app.repositary.UserRepositary;
import com.auth.auth_app.security.JwtService;
import com.auth.auth_app.service.AuthService;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService  authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepositary userRepositary;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse>login(
            @RequestBody LoginRequest loginRequest
    ){
          Authentication authenticate =  authenticate(loginRequest);
          User user = userRepositary.findByEmail(loginRequest.email()).orElseThrow(()
                  -> new BadCredentialsException("Invalid username or password"));
          if (!user.isEnable()){
              throw new DisabledException("User is disabled");
          }

          String accessToken = jwtService.generateAccessToken(user);
             TokenResponse tokenResponse = TokenResponse.of
                                (accessToken,
                                  "",
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


}

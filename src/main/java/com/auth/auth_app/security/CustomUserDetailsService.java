package com.auth.auth_app.security;

import com.auth.auth_app.entity.User;
import com.auth.auth_app.exception.ResourceNotFoundException;
import com.auth.auth_app.repositary.UserRepositary;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepositary userRepositary;

    @Override
    public UserDetails loadUserByUsername(String username)
             throws UsernameNotFoundException {
     User user = userRepositary.findByEmail(username).
                orElseThrow(() -> new RuntimeException("Invalid email or Password !!"));
        return user;

    }

}



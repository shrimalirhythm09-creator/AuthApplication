package com.auth.auth_app.dto;

import com.auth.auth_app.entity.Provider;
import com.auth.auth_app.entity.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class UserDto {

    private UUID id;
    private String email;
    private String name;
    private String password;
    private String image;
    private boolean enable = true;
    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();
    private String gender;
    private Provider provider = Provider.LOCAL;
    private Set<RoleDto> roles = new HashSet<>();

}

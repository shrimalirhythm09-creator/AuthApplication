package com.auth.auth_app.repositary;

import com.auth.auth_app.entity.RefreshToken;
import com.fasterxml.jackson.annotation.OptBoolean;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.swing.text.html.Option;
import java.util.Optional;
import java.util.UUID;

public interface RefreshRepositary extends JpaRepository<RefreshToken, UUID> {

    Optional <RefreshToken> findByJti(String jti);

}

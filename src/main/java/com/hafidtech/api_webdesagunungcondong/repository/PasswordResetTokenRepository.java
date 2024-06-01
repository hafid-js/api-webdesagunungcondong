package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    PasswordResetToken findByToken(String theToken);
}

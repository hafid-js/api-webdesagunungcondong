package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.PasswordResetToken;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    PasswordResetToken findByToken(String theToken);
    @Modifying
    @Query("delete from PasswordResetToken p where p.token = ?1")
    void deleteByToken(@Param("token") String token);

    void deleteByUserId(Integer userId);
}

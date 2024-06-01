package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.token.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    VerificationToken findByToken(String token);

    VerificationToken deleteByToken(String token);
}

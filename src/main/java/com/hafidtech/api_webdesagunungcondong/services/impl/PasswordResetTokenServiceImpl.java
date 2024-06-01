package com.hafidtech.api_webdesagunungcondong.services.impl;

import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.repository.PasswordResetTokenRepository;
import com.hafidtech.api_webdesagunungcondong.entities.PasswordResetToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PasswordResetTokenServiceImpl {

    private final PasswordResetTokenRepository passwordResetTokenRepository;

    public void createPasswordResetTokenForUser(User user, String passwordToken){
        PasswordResetToken passwordResetToken = new PasswordResetToken(passwordToken, user);
        passwordResetTokenRepository.save(passwordResetToken);
    }

   public String validatePasswordResetToken(String theToken) {
           PasswordResetToken token = passwordResetTokenRepository.findByToken(theToken);
           if (token == null) {
               return "Invalid password reset token";
           }

           User user = token.getUser();
           Calendar calendar = Calendar.getInstance();
           if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
//            tokenRepository.delete(token);
               return "Link already expired, resend link";
           }
           return "valid";
   }


   public Optional<User> findUserByPasswordToken(String passwordToken) {
        return Optional.ofNullable(passwordResetTokenRepository.findByToken(passwordToken).getUser());
   }
}

package com.hafidtech.api_webdesagunungcondong.services;

import com.hafidtech.api_webdesagunungcondong.dto.JwtAuthenticationResponse;
import com.hafidtech.api_webdesagunungcondong.dto.LoginRequest;
import com.hafidtech.api_webdesagunungcondong.dto.RefreshTokenRequest;
import com.hafidtech.api_webdesagunungcondong.dto.RegistrationRequest;
import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.entities.token.VerificationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface UserService {

    UserDetailsService userDetailsService();
//    User registration(RegistrationRequest registrationRequest);
    JwtAuthenticationResponse login(LoginRequest loginRequest);
    VerificationToken generateNewVerificationToken(String oldToken);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
    List<User> getUsers();
    void createPasswordResetTokenForUser(User user, String passwordToken);
    String validatePasswordResetToken(String passwordResetToken);
    String validateToken(String theToken);
    User findByRole(Role role);
    Optional<User> findByEmail(String email);
    void saveUserVerificationToken(User theUser, String verificationToken);
    User findUserByPasswordToken(String passwordResetToken);
    void resetUserPassword(User user, String newPassword);

}

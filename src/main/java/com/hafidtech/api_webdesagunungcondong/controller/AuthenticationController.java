package com.hafidtech.api_webdesagunungcondong.controller;

import com.hafidtech.api_webdesagunungcondong.dto.*;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.entities.token.VerificationToken;
import com.hafidtech.api_webdesagunungcondong.event.RegistrationCompleteEvent;
import com.hafidtech.api_webdesagunungcondong.event.listener.RegistrationCompleteEventListener;
import com.hafidtech.api_webdesagunungcondong.logout.BlackList;
import com.hafidtech.api_webdesagunungcondong.repository.PasswordResetTokenRepository;
import com.hafidtech.api_webdesagunungcondong.repository.UserRepository;
import com.hafidtech.api_webdesagunungcondong.repository.VerificationTokenRepository;
import com.hafidtech.api_webdesagunungcondong.services.UserService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.login.LoginException;
import java.io.UnsupportedEncodingException;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthenticationController {

    private UserService authenticationService;
    private ApplicationEventPublisher publisher;
    private VerificationTokenRepository tokenRepository;
    private HttpServletRequest servletRequest;
    private RegistrationCompleteEventListener eventListener;
    private UserRepository userRepository;
    private PasswordResetTokenRepository passwordResetTokenRepository;
    private PasswordEncoder passwordEncoder;
    private BlackList blackList;


    @PostMapping("/register")
    public String register(@RequestBody RegistrationRequest registrationRequest,  final HttpServletRequest request) {
        User user = authenticationService.registration(registrationRequest);
        publisher.publishEvent(new RegistrationCompleteEvent(user, applicationUrl(request)));

        return "Success! Please, Check your email for complete your registration";

    }

    private String applicationUrl(HttpServletRequest request) {
        return "http://"+request.getServerName()+":"+request.getServerPort()+request.getContextPath();
    }

    @GetMapping("/verifyEmail")
    public String sendVerificationToken(@RequestParam("token") String token) {
        String url = applicationUrl(servletRequest)+"/api/v1/auth/resend-verification-token?token="+token;


        VerificationToken theToken = tokenRepository.findByToken(token);
        if(theToken.getUser().isEnabled()) {
            return "This account has already been verified, please login.";
        }
        String verificationResult = authenticationService.validateToken(token);
        if (verificationResult.equalsIgnoreCase("valid")) {
            return "Email verified successfully. Now you can login to your account";
        }
        return "Invalid verification link, <a href=\"" +url+ "\"> Get a new verification link. </a>";
    }


    @GetMapping("/resend-verification-token")
    public String resendVerificationCode(@RequestParam("token") String oldToken, final HttpServletRequest request) throws MessagingException, UnsupportedEncodingException {
        VerificationToken verificationToken = authenticationService.generateNewVerificationToken(oldToken);
        User theUser = verificationToken.getUser();
        resendVerificationTokenEmail(theUser, applicationUrl(request), verificationToken);
        return "A new verification link has been sent to your email." +
                " please check to activate your account";

    }

    private void resendVerificationTokenEmail(User theUser, String applicationUrl, VerificationToken token) throws MessagingException, UnsupportedEncodingException {
        String url = applicationUrl+"/api/v1/auth/verifyEmail?token="+token.getToken();
        eventListener.sendVerificationEmail(url);
        log.info("Click the link to verify your registration : {}", url);
    }


    @PostMapping("/login")
    public ResponseEntity<? extends Object> login(@RequestBody LoginRequest loginRequest) {
        boolean isEnabled = false;
        Optional<User> checkEmailStatus = userRepository.findByEmailAndIsEnabled(loginRequest.getEmail(), isEnabled);
        if (checkEmailStatus.isPresent() && checkEmailStatus.get().isEnabled() == false) {
            return new ResponseEntity<String>("you need verification your email before login", HttpStatus.UNAUTHORIZED);
        }

//        String password = passwordEncoder.encode(loginRequest.getPassword());
//        User checkUsernameAndPassword = userRepository.findByEmailAndPassword(loginRequest.getEmail(), password);
//
//        log.info(checkUsernameAndPassword.getEmail());
//        log.info(checkUsernameAndPassword.getPassword());
//        if (checkUsernameAndPassword == null) {
//            return new ResponseEntity<String>("Email atau Password yang anda masukkan salah!, silahkan periksa kembali", HttpStatus.BAD_REQUEST);
//        } else {
//           log.info("Berhasil");
//        }

        return ResponseEntity.ok(authenticationService.login(loginRequest));
    }


    @PostMapping("/logout")
    @PreAuthorize("hasAuthority('USER') or hasAuthority('ADMIN')")
    public String logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        if(authHeader != null && authHeader.startsWith("Bearer")) {
            token = authHeader.substring(7);
        }
        blackList.blackListToken(token);
        return "You have successfully logged out!";
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }

    @PostMapping("/password-reset-request")
    public Object resetPasswordRequest(@RequestBody PasswordResetRequest passwordResetRequest,
                                       final HttpServletRequest request) throws MessagingException, UnsupportedEncodingException {
        String passwordResetUrl = "";
        Optional<User> user = authenticationService.findByEmail(passwordResetRequest.getEmail());
            if (user.isPresent()) {
                try {
                    String passwordResetToken = UUID.randomUUID().toString();
                    authenticationService.createPasswordResetTokenForUser(user.get(), passwordResetToken);
                    passwordResetUrl = passwordResetEmailLink(user.get(), applicationUrl(request), passwordResetToken);
                } catch (Exception e) {
                    log.error(e.getMessage());
                    return new ResponseEntity<>("The token has been sent to your email, please check again", HttpStatus.CONFLICT);
                }
            }
        return passwordResetUrl;
    }

    private String passwordResetEmailLink(User user, String applicationUrl, String passwordResetToken) throws MessagingException, UnsupportedEncodingException {
        String url = applicationUrl+"/api/v1/auth/reset-password?token="+passwordResetToken;
        eventListener.sendPasswordResetVerificationEmail(url, user);
        log.info("Click the link to reset your password : {}", url);
        return url;
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestBody PasswordResetRequest passwordResetRequest,
                                @RequestParam("token") String token) {
        String tokenValidationResult = authenticationService.validatePasswordResetToken(token);
        if (!tokenValidationResult.equalsIgnoreCase("valid")) {
            return "Invalid password reset token";
        }
        User user = authenticationService.findUserByPasswordToken(token);
        if (user != null) {
            authenticationService.resetUserPassword(user, passwordResetRequest.getNewPassword());
            passwordResetTokenRepository.deleteByToken(token);
            return "Password has been reset successfully";
        }
        return "Invalid password reset token";
    }


}

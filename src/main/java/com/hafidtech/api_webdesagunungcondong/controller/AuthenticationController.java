package com.hafidtech.api_webdesagunungcondong.controller;

import com.hafidtech.api_webdesagunungcondong.dto.*;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.entities.token.VerificationToken;
import com.hafidtech.api_webdesagunungcondong.event.RegistrationCompleteEvent;
import com.hafidtech.api_webdesagunungcondong.event.listener.RegistrationCompleteEventListener;
import com.hafidtech.api_webdesagunungcondong.repository.UserRepository;
import com.hafidtech.api_webdesagunungcondong.repository.VerificationTokenRepository;
import com.hafidtech.api_webdesagunungcondong.services.UserService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {


    private final UserService authenticationService;
    private final ApplicationEventPublisher publisher;
    private final VerificationTokenRepository tokenRepository;
    private final HttpServletRequest servletRequest;
    private final RegistrationCompleteEventListener eventListener;
    private final UserRepository userRepository;

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
       try{
           if(checkEmailStatus.get().isEnabled() == false) {
               return new ResponseEntity<String>("you need verification your email before login",HttpStatus.UNAUTHORIZED);
           }
       } catch (Exception e) {
           e.printStackTrace();
       }
        return ResponseEntity.ok(authenticationService.login(loginRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }

    @PostMapping("/password-reset-request")
    public String resetPasswordRequest(@RequestBody PasswordResetRequest passwordResetRequest,
                                       final HttpServletRequest request) throws MessagingException, UnsupportedEncodingException {
        Optional<User> user = authenticationService.findByEmail(passwordResetRequest.getEmail());
        String passwordResetUrl = "";
        if (user.isPresent()) {
            String passwordResetToken = UUID.randomUUID().toString();
            authenticationService.createPasswordResetTokenForUser(user.get(), passwordResetToken);
            passwordResetUrl = passwordResetEmailLink(user.get(), applicationUrl(request), passwordResetToken);
        }

        return passwordResetUrl;
    }

    private String passwordResetEmailLink(User user, String applicationUrl, String passwordResetToken) throws MessagingException, UnsupportedEncodingException {
        String url = applicationUrl+"/register/reset-password?token="+passwordResetToken;
        eventListener.sendPasswordResetVerificationEmail(url);
        log.info("Click the link to reset your password : {}", url);
        return url;
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestBody PasswordResetRequest passwordResetRequest,
                                @RequestParam("token") String passwordResetToken) {
        String tokenValidationResult = authenticationService.validatePasswordResetToken(passwordResetToken);
        if (!tokenValidationResult.equalsIgnoreCase("valid")) {
            return "Invalid password reset token";
        }
        User user = userService.findUserByPasswordToken(passwordResetToken);
        if (user != null) {
            userService.resetUserPassword(user, passwordResetRequest.getNewPassword());
            return "Password has been reset successfully";
        }
        return "Invalid password reset token";
    }
}

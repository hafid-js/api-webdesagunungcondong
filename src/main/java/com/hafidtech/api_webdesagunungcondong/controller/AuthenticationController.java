package com.hafidtech.api_webdesagunungcondong.controller;

import com.hafidtech.api_webdesagunungcondong.dto.JwtAuthenticationResponse;
import com.hafidtech.api_webdesagunungcondong.dto.RefreshTokenRequest;
import com.hafidtech.api_webdesagunungcondong.dto.SignUpRequest;
import com.hafidtech.api_webdesagunungcondong.dto.SigninRequest;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.event.SignupCompleteEvent;
import com.hafidtech.api_webdesagunungcondong.services.AuthenticationService;
import com.hafidtech.api_webdesagunungcondong.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final ApplicationEventPublisher publisher;


    @PostMapping("/signup")
    public String signUpUser(SignUpRequest signUpRequest, final HttpServletRequest request) {
        User user = userService.signUp(signUpRequest);
        publisher.publishEvent(new SignupCompleteEvent(user, applicationUrl(request)));
        return  "Success! Please, check your email for to complete your registration";
    }

    private String applicationUrl(HttpServletRequest request) {
        return "http://"+request.getServerName()+":"+request.getServerPort()+request.getContextPath();

    }


//    @PostMapping("/signin")
//    public ResponseEntity<JwtAuthenticationResponse> signin(@RequestBody SigninRequest signinRequest) {
//        return ResponseEntity.ok(authenticationService.signin(signinRequest));
//    }
//
//    @PostMapping("/refresh")
//    public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
//        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
//    }
}

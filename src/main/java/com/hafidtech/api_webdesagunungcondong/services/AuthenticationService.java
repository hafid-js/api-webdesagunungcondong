package com.hafidtech.api_webdesagunungcondong.services;

import com.hafidtech.api_webdesagunungcondong.dto.JwtAuthenticationResponse;
import com.hafidtech.api_webdesagunungcondong.dto.RefreshTokenRequest;
import com.hafidtech.api_webdesagunungcondong.dto.SignUpRequest;
import com.hafidtech.api_webdesagunungcondong.dto.SigninRequest;
import com.hafidtech.api_webdesagunungcondong.entities.User;

public interface AuthenticationService {
    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SigninRequest signinRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}

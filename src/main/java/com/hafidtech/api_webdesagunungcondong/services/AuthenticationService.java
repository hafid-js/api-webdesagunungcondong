package com.hafidtech.api_webdesagunungcondong.services;

import com.hafidtech.api_webdesagunungcondong.dto.SignUpRequest;
import com.hafidtech.api_webdesagunungcondong.entities.User;

public interface AuthenticationService {
    User signup(SignUpRequest signUpRequest);
}

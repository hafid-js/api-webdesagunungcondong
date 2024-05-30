package com.hafidtech.api_webdesagunungcondong.services.impl;

import com.hafidtech.api_webdesagunungcondong.dto.SignUpRequest;
import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.repository.UserRepository;
import com.hafidtech.api_webdesagunungcondong.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public User signup(SignUpRequest signUpRequest) {
        User user  = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        return userRepository.save(user);
    }
}

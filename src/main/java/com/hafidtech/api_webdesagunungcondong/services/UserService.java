package com.hafidtech.api_webdesagunungcondong.services;

import com.hafidtech.api_webdesagunungcondong.dto.SignUpRequest;
import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;
import java.util.Optional;

public interface UserService {

    UserDetailsService userDetailsService();

    List<User> getUsers();

    User signUp(SignUpRequest signUpRequest);

    User findByRole(Role role);

    Optional<User> findByEmail(String email);
}

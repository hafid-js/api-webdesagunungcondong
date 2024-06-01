package com.hafidtech.api_webdesagunungcondong.services.impl;


import com.hafidtech.api_webdesagunungcondong.dto.JwtAuthenticationResponse;
import com.hafidtech.api_webdesagunungcondong.dto.LoginRequest;
import com.hafidtech.api_webdesagunungcondong.dto.RefreshTokenRequest;
import com.hafidtech.api_webdesagunungcondong.dto.RegistrationRequest;
import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.entities.token.VerificationToken;
import com.hafidtech.api_webdesagunungcondong.exception.UserAlreadyExistsException;
import com.hafidtech.api_webdesagunungcondong.repository.EmailSender;
import com.hafidtech.api_webdesagunungcondong.repository.UserRepository;
import com.hafidtech.api_webdesagunungcondong.repository.VerificationTokenRepository;
import com.hafidtech.api_webdesagunungcondong.services.JWTService;
import com.hafidtech.api_webdesagunungcondong.services.PasswordResetTokenService;
import com.hafidtech.api_webdesagunungcondong.services.UserService;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class UserServiceImpl implements UserService {

    private AuthenticationManager authenticationManager;
    private JWTService jwtService;
    private UserRepository userRepository;
    private VerificationTokenRepository tokenRepository;
    private PasswordEncoder passwordEncoder;
    private EmailSender emailSender;
    private PasswordResetTokenService passwordResetTokenService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserServiceImpl(@Lazy AuthenticationManager authenticationManager,@Lazy JWTService jwtService,@Lazy UserRepository userRepository,@Lazy VerificationTokenRepository tokenRepository,@Lazy PasswordEncoder passwordEncoder, @Lazy EmailSender emailSender, @Lazy BCryptPasswordEncoder bCryptPasswordEncoder, @Lazy PasswordResetTokenService passwordResetTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailSender = emailSender;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.passwordResetTokenService = passwordResetTokenService;
    }

    private final static String USER_NOT_FOUND_MSG = "user with email %s not found";

    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG)));
            }
        };
    }

    @Override
    public User registration(RegistrationRequest registrationRequest) {
        Optional<User> checkUser = this.userRepository.findByEmail(registrationRequest.getEmail());
        if (checkUser.isPresent()) {
            throw new UserAlreadyExistsException("User with email " + registrationRequest.getEmail() + " is already exists");
        }

        User user  = new User();
        user.setEmail(registrationRequest.getEmail());
        user.setFirstName(registrationRequest.getFirstName());
        user.setLastName(registrationRequest.getLastName());
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        return userRepository.save(user);
    }

    public JwtAuthenticationResponse login(LoginRequest loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        var user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();

        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String userEmail = jwtService.extractUserName(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();
        if(jwtService.isTokenValid(refreshTokenRequest.getToken(), user)){
            var jwt = jwtService.generateToken(user);

            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();

            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return jwtAuthenticationResponse;
        }

        return null;
    }

    @Override
    public String validateToken(String theToken) {
        VerificationToken token = tokenRepository.findByToken(theToken);
        if (token == null) {
            return "Invalid verification token";
        }

        User user = token.getUser();
        Calendar calendar = Calendar.getInstance();
        if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
//            tokenRepository.delete(token);
            return "Verification link already expired," +
                    " Please, click the link below to receive a new verification link";
        }

        user.setEnabled(true);
        userRepository.save(user);
        return "valid";
    }

    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }
    @Override
    public User findByRole(Role role) {
        return null;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public void saveUserVerificationToken(User theUser, String token) {
        var verificationToken = new VerificationToken(token, theUser);
        tokenRepository.save(verificationToken);
    }


    @Override
    public VerificationToken generateNewVerificationToken(String oldToken) {
        VerificationToken verificationToken = tokenRepository.findByToken(oldToken);
        var tokenExpirationTime = new VerificationToken();
        verificationToken.setToken(UUID.randomUUID().toString());
        verificationToken.setExpirationTime(tokenExpirationTime.getTokenExpirationTime());
        return tokenRepository.save(verificationToken);
    }

    @Override
    public String validatePasswordResetToken(String passwordResetToken) {
        return passwordResetTokenService.validatePasswordResetToken(passwordResetToken);
    }

    @Override
    public void createPasswordResetTokenForUser(User user, String passwordToken) {
        passwordResetTokenService.createPasswordResetTokenForUser(user, passwordToken);
    }
}

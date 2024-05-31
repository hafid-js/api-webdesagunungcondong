package com.hafidtech.api_webdesagunungcondong.event.listener;

import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.event.SignupCompleteEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class SignupCompleteEventListener implements ApplicationListener<SignupCompleteEvent> {

    @Override
    public void onApplicationEvent(SignupCompleteEvent event) {

        User theUser = event.getUser();

        String verificationToken = UUID.randomUUID().toString();

        String url = event.getApplicationUrl()+"/api/v1/auth/verifyEmail?token="+verificationToken;

        log.info("Click the link to verify your registration : {}", url);


    }
}

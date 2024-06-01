package com.hafidtech.api_webdesagunungcondong.repository;

import org.springframework.stereotype.Service;

public interface EmailSender {

    void send(String to, String email);
}

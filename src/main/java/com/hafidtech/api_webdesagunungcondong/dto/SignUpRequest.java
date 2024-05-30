package com.hafidtech.api_webdesagunungcondong.dto;

import lombok.Data;

@Data
public class SignUpRequest {

    private String firstName;

    private String lastName;

    private String email;

    private String password;
}

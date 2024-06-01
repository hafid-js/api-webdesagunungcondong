package com.hafidtech.api_webdesagunungcondong.dto;

import lombok.Data;

@Data
public class PasswordResetRequest {
    private String email;
    private String newPassword;
    private String confirmPassword;
}

package com.hafidtech.api_webdesagunungcondong.exception;

import org.springframework.dao.DataIntegrityViolationException;

public class DuplicateException extends DataIntegrityViolationException {

    public DuplicateException(String msg) {
        super(msg);
    }

}
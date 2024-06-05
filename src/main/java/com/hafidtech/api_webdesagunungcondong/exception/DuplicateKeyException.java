package com.hafidtech.api_webdesagunungcondong.exception;

import org.springframework.dao.DataIntegrityViolationException;

import java.io.Serializable;

public class DuplicateKeyException extends DataIntegrityViolationException {

    public DuplicateKeyException(String msg) {
        super(msg);
    }

}
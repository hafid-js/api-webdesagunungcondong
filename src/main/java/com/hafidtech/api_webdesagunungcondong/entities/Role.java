package com.hafidtech.api_webdesagunungcondong.entities;

public enum Role {

    USER("USER"),

    ADMIN("ADMIN");

    private String name;

    Role(String name) {
        this.name = name;
    }

    public String getRoleName() {
        return name;
    }
}

package com.hafidtech.api_webdesagunungcondong.logout;

import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class BlackList {

    private Set<String> blackListTokenSet = new HashSet<>();

    public void blackListToken(String token) {
        blackListTokenSet.add(token);
    }

    public boolean isBlacklisted(String token) {
        return blackListTokenSet.contains(token);
    }
}

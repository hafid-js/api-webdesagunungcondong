package com.hafidtech.api_webdesagunungcondong.event;

import com.hafidtech.api_webdesagunungcondong.entities.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

@Getter
@Setter
public class SignupCompleteEvent extends ApplicationEvent {

    private User user;
    private String applicationUrl;

    public SignupCompleteEvent(User user, String applicationUrl) {
        super(user);
        this.user = user;
        this.applicationUrl = applicationUrl;

    }
}

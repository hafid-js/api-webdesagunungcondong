package com.hafidtech.api_webdesagunungcondong.event.listener;

import com.hafidtech.api_webdesagunungcondong.entities.User;
import com.hafidtech.api_webdesagunungcondong.event.RegistrationCompleteEvent;
import com.hafidtech.api_webdesagunungcondong.services.impl.UserServiceImpl;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Lazy;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

    @Autowired
    private final UserServiceImpl userService;

    private final JavaMailSender mailSender;

    private User user;

//    public RegistrationCompleteEventListener(@Lazy UserServiceImpl userService,@Lazy JavaMailSender mailSender,@Lazy User theUser) {
//        this.userService = userService;
//        this.mailSender = mailSender;
//        this.theUser = theUser;
//    }

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {

        // get the newly registered used
        user = event.getUser();

        // create the verification token for the user
        String verificationToken = UUID.randomUUID().toString();

        // save the verification token for the user
        userService.saveUserVerificationToken(user, verificationToken);

        // build the verification url to be sent to the user
        String url = event.getApplicationUrl()+"/api/v1/auth/verifyEmail?token="+verificationToken;

        // send the email
        try {
            sendVerificationEmail(url, user);
        } catch (MessagingException | UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        log.info("Click the link to verify your registration : {}", url);
    }

    public void sendVerificationEmail(String url, User user) throws MessagingException, UnsupportedEncodingException {
        String subject = "Email Verification";
        String senderName = "gunungcondong.com";
        String mailContent = "<p> Hi, "+ user.getFirstName()+ ", </p>"+
                "<p>Terima kasih sudah mendaftar,"+"" +
                "Silahkan klik link dibawah ini untuk verifikasi akun anda.</p>"+
                "<a href=\"" +url+ "\">Verify your email to activate your account</a>"+
                "<p> Thank you <br> Website Profil Desa Gunung Condong";
        MimeMessage message = mailSender.createMimeMessage();
        var messageHelper = new MimeMessageHelper(message);
        messageHelper.setFrom("tapi.ngapain@gmail.com", senderName);
        messageHelper.setTo(user.getEmail());
        messageHelper.setSubject(subject);
        messageHelper.setText(mailContent, true);
        mailSender.send(message);
    }

    public void sendPasswordResetVerificationEmail(String url, User user) throws MessagingException, UnsupportedEncodingException {
        String subject = "Password Reset Request Verification";
        String senderName = "gunungcondong.com";
        String mailContent = "<p> Hi, "+ user.getFirstName()+ ", </p>"+
                "<p><b>Ypu recently requested to reset your password</b>,"+"" +
                "Please, follow the link below to complete the action.</p>"+
                "<a href=\"" +url+ "\">Reset Password</a>"+
                "<p> Thank you <br> Website Profil Desa Gunung Condong";
        MimeMessage message = mailSender.createMimeMessage();
        var messageHelper = new MimeMessageHelper(message);
        messageHelper.setFrom("tapi.ngapain@gmail.com", senderName);
        messageHelper.setTo(user.getEmail());
        messageHelper.setSubject(subject);
        messageHelper.setText(mailContent, true);
        mailSender.send(message);
    }
}

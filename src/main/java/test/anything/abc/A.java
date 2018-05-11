package test.anything.abc;


import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.*;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@RestController
@Validated
@RequestMapping(path = "test", produces = MediaType.APPLICATION_JSON_VALUE)
public class A {

    String secret = "JEKVTGFAOEZPFE7N";

    @RequestMapping(value = "{code}", method = RequestMethod.POST)
    public void create(@PathVariable("code") final Integer code) {
        System.out.println(code);
        Totp totp = new Totp(secret);
        if (!isValidLong(code.toString()) || !totp.verify(code.toString())) {
            System.out.println("2F failed");
        }
        else
            System.out.println("2F succeed");
    }

    @RequestMapping(value = "/generate", method = RequestMethod.POST)
    public String generateQR() throws UnsupportedEncodingException {
        System.out.println("g secret : " + this.secret );
        String QR_PREFIX =
                "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=";
        String APP_NAME = "tokup";
        String email = "abc@gmail.com";
        String url = QR_PREFIX + URLEncoder.encode(String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                APP_NAME, email, secret, APP_NAME),
                "UTF-8");

        System.out.println(url);
        return url;
    }

    private boolean isValidLong(String code) {
        try {
            Long.parseLong(code);
        } catch (NumberFormatException e) {
            return false;
        }
        System.out.println("long valided");
        return true;
    }
}

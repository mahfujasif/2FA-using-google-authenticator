package test.anything.abc;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.otp.api.Clock;
import org.jboss.aerogear.security.otp.api.Digits;
import org.jboss.aerogear.security.otp.api.Hash;
import org.jboss.aerogear.security.otp.api.Hmac;
import org.jboss.aerogear.security.otp.api.Base32.DecodingException;

public class TotpTest {
    private final String secret;
    private final Clock clock;
    private static final int DELAY_WINDOW = 1;

    public TotpTest(String secret) {
        this.secret = secret;
        this.clock = new Clock();
    }

    public TotpTest(String secret, Clock clock) {
        this.secret = secret;
        this.clock = clock;
    }

    public String uri(String name) {
        try {
            return String.format("otpauth://totp/%s?secret=%s", URLEncoder.encode(name, "UTF-8"), this.secret);
        } catch (UnsupportedEncodingException var3) {
            throw new IllegalArgumentException(var3.getMessage(), var3);
        }
    }

    public String now() {
        return this.leftPadding(this.hash(this.secret, this.clock.getCurrentInterval()));
    }

    public boolean verify(String otp) {
        long code = Long.parseLong(otp);
        long currentInterval = this.clock.getCurrentInterval();
        int pastResponse = Math.max(1, 0);

        for(int i = pastResponse; i >= 0; --i) {
            int candidate = this.generate(this.secret, currentInterval - (long)i);
            if ((long)candidate == code) {
                return true;
            }
        }

        return false;
    }

    private int generate(String secret, long interval) {
        return this.hash(secret, interval);
    }

    private int hash(String secret, long interval) {
        byte[] hash = new byte[0];

        try {
            hash = (new Hmac(Hash.SHA1, Base32.decode(secret), interval)).digest();
        } catch (NoSuchAlgorithmException var6) {
            var6.printStackTrace();
        } catch (InvalidKeyException var7) {
            var7.printStackTrace();
        } catch (DecodingException var8) {
            var8.printStackTrace();
        }

        return this.bytesToInt(hash);
    }

    private int bytesToInt(byte[] hash) {
        int offset = hash[hash.length - 1] & 15;
        int binary = (hash[offset] & 127) << 24 | (hash[offset + 1] & 255) << 16 | (hash[offset + 2] & 255) << 8 | hash[offset + 3] & 255;
        return binary % Digits.SIX.getValue();
    }

    private String leftPadding(int otp) {
        return String.format("%06d", otp);
    }
}


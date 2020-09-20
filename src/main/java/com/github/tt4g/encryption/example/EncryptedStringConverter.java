package com.github.tt4g.encryption.example;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;

public class EncryptedStringConverter {

    static final String SEPARATOR = ":";

    // RFC 4648
    private final Base64.Encoder base64Encoder = Base64.getEncoder();

    // RFC 4648
    private final Base64.Decoder base64Decoder = Base64.getDecoder();

    EncryptedString fromEncrypt(byte[] encrypted, IvParameterSpec iv) {
        byte[] ivBytes = iv.getIV();
        String encodedIv = new String(this.base64Encoder.encode(ivBytes), StandardCharsets.UTF_8);
        String encoded = new String(this.base64Encoder.encode(encrypted), StandardCharsets.UTF_8);

        return new EncryptedString(encodedIv + SEPARATOR + encoded);
    }

    EncryptedString fromString(String raw) {
        if (raw.indexOf(SEPARATOR) == -1) {
            throw new IllegalArgumentException("Can not convert EncryptedString.");
        }

        return new EncryptedString(raw);
    }

    AesCbcEncrypted toAesCbcEncrypted(EncryptedString encryptedString) {
        String raw = encryptedString.getEncodedString();

        String[] ivAndEncoded = raw.split(SEPARATOR, 2);
        if (ivAndEncoded.length != 2) {
            throw new IllegalArgumentException("Invalid EncryptedString.");
        }

        byte[] iv =
            this.base64Decoder.decode(ivAndEncoded[0].getBytes(StandardCharsets.UTF_8));
        byte[] encrypted =
            this.base64Decoder.decode(ivAndEncoded[1].getBytes(StandardCharsets.UTF_8));

        return new AesCbcEncrypted(encrypted, iv);
    }

}

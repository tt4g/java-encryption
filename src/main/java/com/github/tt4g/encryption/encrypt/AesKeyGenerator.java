package com.github.tt4g.encryption.encrypt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AesKeyGenerator {

    /**
     * Generate AES 256 key.
     *
     * @return AES 256 key.
     */
    public SecretKey generateAes256Key() {
        return generateAesKey(256);
    }

    /**
     * Generate AES key.
     *
     * @param keyLength AES key length.
     * @return Generated {@link SecretKey}.
     */
    public SecretKey generateAesKey(int keyLength) {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");

            keyGenerator.init(keyLength, SecureRandom.getInstanceStrong());
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("could not generate AES key.", ex);
        }

        return keyGenerator.generateKey();
    }

    public SecretKey generateAesKeyWithPassword(int keyLength, char[] password, byte[] salt) {
        SecretKeyFactory secretKeyFactory;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("could not get secret key factory.", ex);
        }

        // 6556 is iteration count.
        KeySpec keySpec = new PBEKeySpec(password, salt, 6556, keyLength);

        SecretKey generatedSecretKey;
        try {
            generatedSecretKey = secretKeyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalArgumentException(
                "could not generate secret key from 'password' and 'salt'.", ex);
        }

        return new SecretKeySpec(generatedSecretKey.getEncoded(), "AES");
    }

}

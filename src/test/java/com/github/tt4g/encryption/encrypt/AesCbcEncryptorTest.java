package com.github.tt4g.encryption.encrypt;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AesCbcEncryptorTest {

    @Test
    public void crypto() {
        AesKeyGenerator aesKeyGenerator = new AesKeyGenerator();
        SecretKey aesKey = aesKeyGenerator.generateAes256Key();

        AesCbcEncryptor aesCbcEncryptor = new AesCbcEncryptor(aesKey);

        IvGenerator ivGenerator = new IvGenerator();
        IvParameterSpec iv = ivGenerator.generate(16); // use 128 bit (16 bytes) iv: AES-128, AES-192, AES-256

        String plain = "❨╯°□°❩╯︵┻━┻";

        byte[] encrypted = aesCbcEncryptor.encrypt(plain.getBytes(StandardCharsets.UTF_8), iv);

        byte[] decrypted = aesCbcEncryptor.decrypt(encrypted, iv);

        String restore = new String(decrypted, StandardCharsets.UTF_8);

        assertThat(restore).isEqualTo(plain);
    }

}

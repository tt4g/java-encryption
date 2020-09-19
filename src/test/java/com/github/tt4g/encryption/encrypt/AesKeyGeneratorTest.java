package com.github.tt4g.encryption.encrypt;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AesKeyGeneratorTest {

    @Test
    public void generateAes256Key() {
        AesKeyGenerator aesKeyGenerator = new AesKeyGenerator();

        SecretKey secretKey = aesKeyGenerator.generateAes256Key();

        assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
        assertThat(secretKey.getEncoded()).hasSize(32); // 256 bit = 32 byte
        assertThat(secretKey.isDestroyed()).isFalse();
    }

    @Test
    public void generateAesKey() {
        AesKeyGenerator aesKeyGenerator = new AesKeyGenerator();

        SecretKey secretKey = aesKeyGenerator.generateAesKey(192);

        assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
        assertThat(secretKey.getEncoded()).hasSize(24); // 192 bit = 24 byte
        assertThat(secretKey.isDestroyed()).isFalse();
    }

    @Test
    public void generateAesKeyWithPassword() {
        AesKeyGenerator aesKeyGenerator = new AesKeyGenerator();

        SecretKey secretKey =
            aesKeyGenerator.generateAesKeyWithPassword(
                128,
                "foo".toCharArray(),
                "bar".getBytes(StandardCharsets.UTF_8));

        assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
        assertThat(secretKey.getEncoded()).hasSize(16); // 128 bit = 12 byte
        assertThat(secretKey.isDestroyed()).isFalse();
    }

}

package com.github.tt4g.encryption.example;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import javax.crypto.spec.IvParameterSpec;

import com.github.tt4g.encryption.encrypt.AesCbcEncryptor;
import com.github.tt4g.encryption.encrypt.IvGenerator;

public class AesStringEncryptor {

    private final AesCbcEncryptor aesCbcEncryptor;

    private final IvGenerator ivGenerator;

    private final EncryptedStringConverter encryptedStringConverter;

    public AesStringEncryptor(AesCbcEncryptor aesCbcEncryptor, IvGenerator ivGenerator) {
        this.aesCbcEncryptor = Objects.requireNonNull(aesCbcEncryptor);
        this.ivGenerator = Objects.requireNonNull(ivGenerator);
        this.encryptedStringConverter = new EncryptedStringConverter();
    }

    public EncryptedString encrypt(String plain) {
        Objects.requireNonNull(plain);

        byte[] plainBytes = plain.getBytes(StandardCharsets.UTF_8);

        // iv length always 16 bytes (128 bit) for AES-128, AES-192, AES-256.
        IvParameterSpec iv = this.ivGenerator.generate(16);

        byte[] encrypted = this.aesCbcEncryptor.encrypt(plainBytes, iv);

        return this.encryptedStringConverter.fromEncrypt(encrypted,iv);
    }

    public String decrypt(String encrypted) {
        AesCbcEncrypted aesCbcEncrypted =
            this.encryptedStringConverter.toAesCbcEncrypted(
                this.encryptedStringConverter.fromString(encrypted));

        IvParameterSpec iv = new IvParameterSpec(aesCbcEncrypted.getIv());

        byte[] decrypted = this.aesCbcEncryptor.decrypt(aesCbcEncrypted.getEncrypted(), iv);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

}

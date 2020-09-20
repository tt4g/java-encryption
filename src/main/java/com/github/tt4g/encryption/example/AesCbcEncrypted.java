package com.github.tt4g.encryption.example;

import java.util.Objects;

public class AesCbcEncrypted {

    private final byte[] encrypted;

    private final byte[] iv;

    AesCbcEncrypted(byte[] encrypted, byte[] iv) {
        this.encrypted = Objects.requireNonNull(encrypted);
        this.iv = Objects.requireNonNull(iv);
    }

    byte[] getEncrypted() {
        return this.encrypted;
    }

    byte[] getIv() {
        return this.iv;
    }

}

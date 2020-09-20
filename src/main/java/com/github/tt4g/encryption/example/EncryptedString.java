package com.github.tt4g.encryption.example;

public class EncryptedString {

    private final String encodedString;

    EncryptedString(String encodedString) {
        this.encodedString = encodedString;
    }

    public String getEncodedString() {
        return this.encodedString;
    }

}

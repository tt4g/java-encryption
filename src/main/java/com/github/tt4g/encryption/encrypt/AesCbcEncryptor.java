// This file was written based on the original code with the following license:
//
// https://github.com/spring-projects/spring-security/blob/5.4.0/crypto/src/main/java/org/springframework/security/crypto/encrypt/AesBytesEncryptor.java
//
// Copyright 2011-2016 the original author or authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.github.tt4g.encryption.encrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypt AES with CBC mode.
 *
 * Can use key length 128bit, 192bit or 256bit.
 *
 * This object is thread-safe.
 */
public class AesCbcEncryptor {

    private final SecretKey secretKey;

    private final Cipher encryptor;

    private final Cipher decryptor;

    private Cipher createCipher() {
        try {
            // NOTE: "PKCS5Padding" is instead of PKCS7Padding in Java.
            return Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new RuntimeException("Could not found cipher: \"AES/CBC/PKCS5Padding\".", ex);
        }
    }

    public AesCbcEncryptor(SecretKey secretKey) {
        Objects.requireNonNull(secretKey);

        this.secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
        this.encryptor = createCipher();
        this.decryptor = createCipher();
    }

    public byte[] encrypt(byte[] plain, IvParameterSpec iv) {
        Objects.requireNonNull(plain);
        Objects.requireNonNull(iv);

        synchronized (this.encryptor) {
            initCipher(this.encryptor, Cipher.ENCRYPT_MODE, this.secretKey, iv);

            return doFinal(this.encryptor, plain);
        }
    }

    public byte[] decrypt(byte[] encrypted, IvParameterSpec iv) {
        Objects.requireNonNull(encrypted);
        Objects.requireNonNull(iv);

        synchronized (this.decryptor) {
            initCipher(this.decryptor, Cipher.DECRYPT_MODE,this.secretKey,iv);

            return doFinal(this.decryptor,encrypted);
        }
    }

    private void initCipher(Cipher cipher, int mode, SecretKey key, IvParameterSpec iv) {
        try {

            cipher.init(mode, key, iv);

        } catch (InvalidKeyException ex) {
            throw new IllegalArgumentException("Invalid secret key.", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new IllegalArgumentException("Invalid iv parameter.", ex);
        }
    }

    private byte[] doFinal(Cipher cipher, byte[] source) {
        try {

            return cipher.doFinal(source);

        } catch (IllegalBlockSizeException ex) {
            throw new IllegalStateException(
                "Unable to encryption due to illegal block size.", ex);
        } catch (BadPaddingException ex) {
            throw new IllegalStateException(
                "Unable to encryption due to bad padding.", ex);
        }
    }

}

package com.github.tt4g.encryption.pem;

public interface PemKeyDecoder {

    /**
     * Decode PEM format key.
     *
     * @param key PEM format key.
     * @return Decoded key.
     */
    byte[] decode(byte[] key);

}

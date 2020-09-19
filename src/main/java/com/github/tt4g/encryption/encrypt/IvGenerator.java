package com.github.tt4g.encryption.encrypt;

import java.security.SecureRandom;
import java.util.Objects;
import javax.crypto.spec.IvParameterSpec;

/**
 * Generate initialization vector.
 *
 * This object is thread-safe.
 */
public class IvGenerator {

    private final SecureRandom secureRandom;

    /**
     * Construct object.
     *
     * Use <code>SecureRandom.getInstance("NativePRNGNonBlocking")</code>.
     */
    public IvGenerator() {
        this(new SecureRandom());
    }
    public IvGenerator(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom);
    }

    public IvParameterSpec generate(int byteLength) {
        byte[] iv = new byte[byteLength];

        this.secureRandom.nextBytes(iv);

        return new IvParameterSpec(iv);
    }

}

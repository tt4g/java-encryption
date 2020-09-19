package com.github.tt4g.encryption.pem;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public abstract class PemUtils {

    /**
     * Shortcut method of {@link #hasLabelBegin(byte[], byte[])}.
     *
     * @see {@link #hasLabelBegin(byte[], byte[])}
     */
    static boolean hasLabelBegin(byte[] key, String labelBegin) {
        return hasLabelBegin(key, labelBegin.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Check <code>key</code> begin with <code>labelBegin</code>.
     *
     * @param key PEM format key.
     * @param labelBegin PEM start label.
     * @return <code>true</code> if <code>key</code> begin with <code>labelBegin</code>,
     *         <code>false</code> if <code>key</code> does not begin with <code>labelBegin</code>
     */
    static boolean hasLabelBegin(byte[] key, byte[] labelBegin) {
        if (key.length < labelBegin.length) {
            return false;
        }

        return Arrays.equals(key, 0, labelBegin.length, labelBegin, 0, labelBegin.length);
    }


    static boolean hasLabelEnd(byte[] key, String labelEnd) {
        return hasLabelEnd(key, labelEnd.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Check <code>key</code> ends with <code>labelEnd</code>.
     *
     * @param key PEM format key.
     * @param labelEnd PEM end label.
     * @return <code>true</code> if <code>key</code> ends with <code>labelEnd</code>,
     *         <code>false</code> if <code>key</code> does not ends with <code>labelEnd</code>
     */
    static boolean hasLabelEnd(byte[] key, byte[] labelEnd) {
        if (key.length < labelEnd.length) {
            return false;
        }

        int endStartPos = key.length - labelEnd.length;

        return Arrays.equals(key, endStartPos, key.length, labelEnd, 0, labelEnd.length);
    }

    private PemUtils() {

    }

}

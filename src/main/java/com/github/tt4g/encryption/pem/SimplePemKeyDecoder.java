package com.github.tt4g.encryption.pem;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Simple {@link PemKeyDecoder} implementation.
 *
 * This object is thread-safe.
 *
 * References: RFC 7648
 */
public class SimplePemKeyDecoder implements PemKeyDecoder {

    // Base64.Decoder is thread-safe.
    private final Base64.Decoder base64Decoder = Base64.getMimeDecoder();

    @Override
    public byte[] decode(byte[] key) {
        Objects.requireNonNull(key);

        int startPos = searchPemBeginPosition(key);
        if (startPos == -1) {
            throw new IllegalArgumentException("Could not decode: 'key' is not PEM format.");
        }

        int endPos = searchPemEndPosition(key, startPos);

        if (endPos == -1) {
            throw new IllegalArgumentException("Could not decode: 'key' is not PEM format.");
        }

        byte[] parsed = extractKey(key, startPos, endPos);

        return this.base64Decoder.decode(parsed);
    }

    /**
     * Search the end position of the PEM start label.
     *
     * @param key PEM key.
     * @return The end of position if PEM start label is found, <code>-1</code> if not found.
     */
    private int searchPemBeginPosition(byte[] key) {
        byte[] labelBegin = PemSpec.LABEL_BEGIN.getBytes(StandardCharsets.US_ASCII);

        final int keyLength = key.length;
        final int beginLength = labelBegin.length;
        if (keyLength < beginLength) {
            return -1;
        }

        int beginPos = -1;
        // Search: -----BEGIN
        for (int i = 0; (i + beginLength) < keyLength; ++i) {
            if (key[i] == labelBegin[0]
                && key[i + 1] == labelBegin[1]
                && key[i + 2] == labelBegin[2]
                && key[i + 3] == labelBegin[3]
                && key[i + 4] == labelBegin[4]
                && key[i + 5] == labelBegin[5]
                && key[i + 6] == labelBegin[6]
                && key[i + 7] == labelBegin[7]
                && key[i + 8] == labelBegin[8]
                && key[i + 9] == labelBegin[9]) {

                beginPos = i + labelBegin.length;
                break;
            }
        }

        if (beginPos == -1) {
            return -1;
        }

        byte[] labelClose = PemSpec.LABEL_CLOSE.getBytes(StandardCharsets.US_ASCII);
        final int endLength = labelClose.length;
        // Search: -----
        for (int i = beginPos; (i + endLength) < keyLength; ++i) {
            if (key[i] == labelClose[0]
                && key[i + 1] == labelClose[1]
                && key[i + 2] == labelClose[2]
                && key[i + 3] == labelClose[3]
                && key[i + 4] == labelClose[4]) {

                return i + labelClose.length;
            }
        }

        return -1;
    }

    /**
     * Search the start position of the PEM end label.
     *
     * @param key PEM key.
     * @return The start of position if PEM end label is found, <code>-1</code> if not found.
     */
    private int searchPemEndPosition(byte[] key, int offset) {
        final int keyLength = key.length;
        if (key.length < offset) {
            return -1;
        }

        byte[] labelEnd = PemSpec.LABEL_END.getBytes(StandardCharsets.US_ASCII);
        final int endLength = labelEnd.length;
        // Search: -----END
        for (int i = offset; (i + endLength) < keyLength; ++i) {
            if (key[i] == labelEnd[0]
                && key[i + 1] == labelEnd[1]
                && key[i + 2] == labelEnd[2]
                && key[i + 3] == labelEnd[3]
                && key[i + 4] == labelEnd[4]
                && key[i + 5] == labelEnd[5]
                && key[i + 6] == labelEnd[6]
                && key[i + 7] == labelEnd[7]) {

                return i;
            }
        }

        return -1;
    }

    /**
     * Extract key from PEM format.
     *
     * PEM format contains new line characters.
     * This method removes line feed (<code>0x0a</code>) and carriage return
     * (<code>0x0d</code>).
     *
     * @param key PEM format key.
     * @param startPos key content start position.
     * @param endPos key content end position.
     * @return key bytes.
     */
    private byte[] extractKey(byte[] key, int startPos, int endPos) {
        ByteBuffer keyBuffer = ByteBuffer.allocate(key.length - startPos - (key.length - endPos));

        IntStream.range(startPos, endPos).boxed()
            .map(index -> key[index])
            .filter(keyByte -> keyByte != 0x0a && keyByte != 0x0d)
            .forEach(keyBuffer::put);

        keyBuffer.flip();
        byte[] extracted = new byte[keyBuffer.remaining()];
        keyBuffer.get(extracted);

        return extracted;
    }

}

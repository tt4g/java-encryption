package com.github.tt4g.encryption.pem;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PemUtilsTest {

    @Test
    public void hasLabel() {
        String labelBegin = "-----BEGIN PRIVATE KEY-----";
        String labelEnd = "-----END PRIVATE KEY-----";

        String key = labelBegin + "\nfoo\n" + labelEnd;
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);

        assertThat(PemUtils.hasLabelBegin(keyBytes, labelBegin)).isTrue();
        assertThat(PemUtils.hasLabelEnd(keyBytes, labelEnd)).isTrue();
    }

    @Test
    public void hasLabelBytes() {
        String labelBegin = "-----BEGIN PUBLIC KEY-----";
        String labelEnd = "-----END PUBLIC KEY-----";

        String key = labelBegin + "\nfoo\n" + labelEnd;
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);

        assertThat(PemUtils.hasLabelBegin(keyBytes, labelBegin.getBytes(StandardCharsets.US_ASCII))).isTrue();
        assertThat(PemUtils.hasLabelEnd(keyBytes, labelEnd.getBytes(StandardCharsets.US_ASCII))).isTrue();
    }

    @Test
    public void doesNotHasLabel() {
        String labelBegin = "-----BEGIN PRIVATE KEY-----";
        String labelEnd = "-----END PRIVATE KEY-----";

        String key =
            "-----BEGIN PUBLIC KEY-----" +
            "foo\n" +
            "-----END PUBLIC KEY-----";
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);

        assertThat(PemUtils.hasLabelBegin(keyBytes, labelBegin)).isFalse();
        assertThat(PemUtils.hasLabelEnd(keyBytes, labelEnd)).isFalse();
    }

    @Test
    public void doesNotHasLabelBytes() {
        String labelBegin = "-----BEGIN PUBLIC KEY-----";
        String labelEnd = "-----END PUBLIC KEY-----";

        String key =
            "-----BEGIN PRIVATE KEY-----" +
                "foo\n" +
                "-----END PRIVATE KEY-----";
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);

        assertThat(PemUtils.hasLabelBegin(keyBytes, labelBegin.getBytes(StandardCharsets.US_ASCII))).isFalse();
        assertThat(PemUtils.hasLabelEnd(keyBytes, labelEnd.getBytes(StandardCharsets.US_ASCII))).isFalse();
    }

}

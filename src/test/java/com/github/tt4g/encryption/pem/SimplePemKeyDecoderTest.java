package com.github.tt4g.encryption.pem;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SimplePemKeyDecoderTest {

    private SimplePemKeyDecoder simplePemKeyDecoder = new SimplePemKeyDecoder();

    private String removeNewLine(String value) {
        return value.replace("\n", "").replace("\r", "");
    }

    @Test
    public void decodeNull() {
        assertThatThrownBy(() -> this.simplePemKeyDecoder.decode(null))
            .isExactlyInstanceOf(NullPointerException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "-----BEGIN RSA PRIVATE KEY-----foo",
        "foo-----END RSA PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY-----foo",
        "foo-----END PUBLIC KEY-----"
    })
    public void decodeNotPemFormat(String key) {
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> this.simplePemKeyDecoder.decode(keyBytes))
            .isExactlyInstanceOf(IllegalArgumentException.class)
            .hasMessage("Could not decode: 'key' is not PEM format.");
    }

    @Test
    public void decodeEmptyKey() {
        String emptyKey = "-----BEGIN RSA PRIVATE KEY-----" + "-----END PUBLIC KEY-----";
        byte[] keyBytes = emptyKey.getBytes(StandardCharsets.US_ASCII);

        byte[] decoded = this.simplePemKeyDecoder.decode(keyBytes);

        assertThat(decoded).isEmpty();
    }

    @Test
    public void decodeUnknownLabel() {
        String key =
            "MIIBOQIBAAJBALS6O206oz7vkECeoER5M9Ycr0TP+u2eTzuSYNgW6mql4gDQB92b\n" +
            "lJ5fM1osjR96a+lF5PbLq6U+jApEpV8F4Y0CAwEAAQJAWXPMMjZR0rbUmYdqIDo1\n" +
            "dAbioZanxrES2pOLJ6nAAWSg1y+69qRIyIjiQurxzDeA2q/e8E1+k4caq86zCOwh\n" +
            "AQIhANiQa2dJOO6uoafi60+gm12b1P4E59E3QEU0WOWaUGrtAiEA1aM2gV8u/ejo\n" +
            "mN40Po9Kyei70NSHSgerHAW4PUkQXSECICmXAqlhTIe6Dd2aHKq8I1pE1RC7jHGH\n" +
            "dNZViUT+77a5AiAweFBEd+j8eJxVGoz16KLKPoBmN+Hd/PFocS/Ez8/joQIgB9d2\n" +
            "M9n6da4m7l5FPfwSHfAHfLnF3XoQPKWHRN7z/cA=";

        String unknownLabelKey = "-----BEGIN FOO BAR BAZ-----" +
            key +
            "-----END FOO BAR BAZ-----";

        byte[] decoded = this.simplePemKeyDecoder.decode(unknownLabelKey.getBytes(StandardCharsets.US_ASCII));

        String oneLineKey = removeNewLine(key);
        byte[] expected = Base64.getMimeDecoder().decode(oneLineKey);

        assertThat(decoded).containsOnly(expected);
    }

    @Test
    public void decodeRSAPrivateKey() {
        String key =
            "MIICXQIBAAKBgQCsOpaiVXNYbJvax2/u/jXwi9e5qQ1EDjuwDBF2bOTFFyH2LbLZ\n" +
            "imXAUJA5I1thOA28PMgrzWFm/vZY+JJf77oZ13jB/1aMMLQtEnR9ZpXR+1XYNK5m\n" +
            "mv3UN0qx0x4d9dsRRHhXrXaJcrKyEgsrNsuFbfLemrODA6OvIv5+f50d9QIDAQAB\n" +
            "AoGATTBE6qRZebvTbg4MQJR2IETMfk0hwOqQHaqK+QR800g21FpO2eiJCdQRj0ol\n" +
            "XkD9BuxG2jrF+J80UVO2ZoDOaqIORKNLpSMNwQ9u9wW0l3ih9WF5r/OCpubCxzS9\n" +
            "L+M8Hx1mjda4vqZFtG7yIdbCc+6AxQ2F+C/cRakTjQMk/QECQQDc4vtyTB6UqQdo\n" +
            "OoxjDLBvUC/wqm2XT7q4eD4EhLcXRHEz6pjSk0e6TwpuL/e/AKzrAPJy3Fd43W/L\n" +
            "nlNK9AgFAkEAx5t4PBYIqEFbujGEnlTTekyWEnLBXMR+3XX6avT7WQ//iqE9mzSC\n" +
            "v6NBqOOYogs/1ma3xW4uqfAjwLiz80ZRMQJBAKpTvWFdoRcxYCzXOPoIBuVPCCik\n" +
            "wu0y5eDpl6kUTbr7Y++Mr1txhpX77ScahggbFTwB9vLrRehFmLeC1uetVaECQDM8\n" +
            "LtKNfU9i516Vk0rozxeXTPYTSpq7PS0vOUX2+AVWW+uDk8Kg6eayywnE0crWRF6O\n" +
            "IyGkNIoeP68aOeZ56CECQQDbOhM+JUEvnkKjT0WDZMCQXzM5hXtEpj8wnB9MA64/\n" +
            "4rnwmUssrg/8xvKCjMo5BDHIFCpbni8BS93VyU3f+EnH";

        String pemKey =
            "-----BEGIN RSA PRIVATE KEY-----" +
            key +
            "-----END RSA PRIVATE KEY-----";

        byte[] decoded = this.simplePemKeyDecoder.decode(pemKey.getBytes(StandardCharsets.US_ASCII));

        String oneLineKey = removeNewLine(key);
        byte[] expected = Base64.getMimeDecoder().decode(oneLineKey);

        assertThat(decoded).containsOnly(expected);
    }

    @Test
    public void decodeRSAPublicKey() {
        String key =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsOpaiVXNYbJvax2/u/jXwi9e5\n" +
            "qQ1EDjuwDBF2bOTFFyH2LbLZimXAUJA5I1thOA28PMgrzWFm/vZY+JJf77oZ13jB\n" +
            "/1aMMLQtEnR9ZpXR+1XYNK5mmv3UN0qx0x4d9dsRRHhXrXaJcrKyEgsrNsuFbfLe\n" +
            "mrODA6OvIv5+f50d9QIDAQAB";

        String pemKey =
            "-----BEGIN PUBLIC KEY-----" +
            key +
            "-----END PUBLIC KEY-----";

        byte[] decoded = this.simplePemKeyDecoder.decode(pemKey.getBytes(StandardCharsets.US_ASCII));

        String oneLineKey = removeNewLine(key);
        byte[] expected = Base64.getMimeDecoder().decode(oneLineKey);

        assertThat(decoded).containsOnly(expected);
    }

}

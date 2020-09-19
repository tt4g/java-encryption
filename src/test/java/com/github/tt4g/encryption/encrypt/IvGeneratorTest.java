package com.github.tt4g.encryption.encrypt;

import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IvGeneratorTest {

    @Test
    public void generate() {
        IvGenerator ivGenerator = new IvGenerator();

        IvParameterSpec iv_128 = ivGenerator.generate(128);

        assertThat(iv_128.getIV()).hasSize(128);

        IvParameterSpec iv_192 = ivGenerator.generate(192);

        assertThat(iv_192.getIV()).hasSize(192);

        IvParameterSpec iv_256 = ivGenerator.generate(256);

        assertThat(iv_256.getIV()).hasSize(256);
    }

}

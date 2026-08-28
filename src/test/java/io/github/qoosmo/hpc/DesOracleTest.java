package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class DesOracleTest {
    @Test
    void encryptionIsDeterministicForAState() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "HPC reproducibility".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals(oracle.encryptState(42), oracle.encryptState(42));
    }

    @Test
    void differentStatesProduceDifferentCiphertextsForFixture() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "HPC reproducibility".getBytes(StandardCharsets.UTF_8));

        assertFalse(java.util.Arrays.equals(oracle.encryptState(41), oracle.encryptState(42)));
    }

    @Test
    void matchesRecognizesKnownState() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "known plaintext".getBytes(StandardCharsets.UTF_8));

        byte[] target = oracle.encryptState(731);

        assertTrue(oracle.matches(731, target));
        assertFalse(oracle.matches(730, target));
    }

    @Test
    void plaintextAccessorIsDefensive() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(8);
        byte[] input = "plaintext".getBytes(StandardCharsets.UTF_8);
        DesOracle oracle = new DesOracle(space, input);

        input[0] ^= 1;
        byte[] copy = oracle.plaintext();
        copy[0] ^= 1;

        assertArrayEquals(
                "plaintext".getBytes(StandardCharsets.UTF_8),
                oracle.plaintext());
    }
}

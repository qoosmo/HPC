package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class CrossLanguageReferenceVectorTest {
    private static final byte[] PLAINTEXT =
            "HPC reproducibility fixture".getBytes(StandardCharsets.UTF_8);

    @Test
    void sharedReferenceVectorsMatchJavaSemantics() throws Exception {
        var lines = Files.readAllLines(
                Path.of("test-vectors/java-rust-reference.csv"),
                StandardCharsets.UTF_8);

        for (String line : lines.subList(1, lines.size())) {
            if (line.isBlank()) {
                continue;
            }

            String[] columns = line.split(",");
            assertEquals(7, columns.length);

            int stateBits = Integer.parseInt(columns[0]);
            long state = Long.parseLong(columns[1]);
            String expectedKey = columns[2];
            String expectedCiphertext = columns[3];
            long expectedReduced = Long.parseLong(columns[4]);
            int chainLength = Integer.parseInt(columns[5]);
            long expectedEndpoint = Long.parseLong(columns[6]);

            ReducedDesKeySpace keySpace = new ReducedDesKeySpace(stateBits);
            DesOracle oracle = new DesOracle(keySpace, PLAINTEXT);
            LegacyReduction reduction = new LegacyReduction(keySpace);

            assertEquals(expectedKey, toHex(keySpace.toKeyBytes(state)));

            byte[] ciphertext = oracle.encryptState(state);
            assertEquals(expectedCiphertext, toHex(ciphertext));
            assertEquals(expectedReduced, reduction.reduce(ciphertext));

            long endpoint = state;
            for (int i = 0; i < chainLength; i++) {
                endpoint = reduction.reduce(oracle.encryptState(endpoint));
            }
            assertEquals(expectedEndpoint, endpoint);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format("%02x", Byte.toUnsignedInt(value)));
        }
        return out.toString();
    }
}

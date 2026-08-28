package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

final class ExhaustiveSearchTest {
    @Test
    void recoversKnownState() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "known plaintext".getBytes(StandardCharsets.UTF_8));
        ExhaustiveSearch search = new ExhaustiveSearch(space, oracle);

        long targetState = 2_731;
        OptionalLong found = search.find(oracle.encryptState(targetState));

        assertTrue(found.isPresent());
        assertEquals(targetState, found.getAsLong());
    }

    @Test
    void returnsEmptyWhenCiphertextIsOutsideExperimentImage() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(8);
        DesOracle oracle =
                new DesOracle(space, "known plaintext".getBytes(StandardCharsets.UTF_8));
        ExhaustiveSearch search = new ExhaustiveSearch(space, oracle);

        byte[] impossibleFixture = oracle.encryptState(17);
        impossibleFixture[0] ^= 0x55;

        assertTrue(search.find(impossibleFixture).isEmpty());
    }
}

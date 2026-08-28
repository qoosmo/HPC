package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class HellmanTableTest {
    @Test
    void recoversStateInsideStoredChain() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "Hellman fixture".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);

        long start = 137;
        int chainLength = 10;
        long targetState = advance(start, 4, oracle, reduction);

        HellmanTable table =
                HellmanTable.build(
                        space,
                        oracle,
                        reduction,
                        new long[] {start, 501, 901},
                        chainLength);

        HellmanTable.LookupResult result =
                table.lookup(oracle.encryptState(targetState));

        assertTrue(result.found());
        assertEquals(targetState, result.state().orElseThrow());
        assertTrue(result.endpointMatches() >= 1);
        assertTrue(result.candidateChainsChecked() >= 1);
    }

    @Test
    void reportsTableShape() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(10);
        DesOracle oracle =
                new DesOracle(space, "shape".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);

        HellmanTable table =
                HellmanTable.build(
                        space,
                        oracle,
                        reduction,
                        new long[] {1, 2, 3, 4},
                        7);

        assertEquals(4, table.chainCount());
        assertEquals(7, table.chainLength());
        assertTrue(table.distinctEndpointCount() >= 1);
        assertTrue(table.distinctEndpointCount() <= 4);
    }

    @Test
    void rejectsDuplicateStartStates() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(8);
        DesOracle oracle =
                new DesOracle(space, "duplicate".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);

        assertThrows(
                IllegalArgumentException.class,
                () -> HellmanTable.build(
                        space,
                        oracle,
                        reduction,
                        new long[] {7, 7},
                        4));
    }

    @Test
    void targetOutsideCandidateChainIsNotReportedAsFound() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "negative".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);

        long start = 11;
        int chainLength = 3;
        HellmanTable table =
                HellmanTable.build(
                        space,
                        oracle,
                        reduction,
                        new long[] {start},
                        chainLength);

        boolean[] covered = new boolean[(int) space.size()];
        long state = start;
        for (int i = 0; i < chainLength; i++) {
            covered[(int) state] = true;
            state = reduction.reduce(oracle.encryptState(state));
        }

        long outside = -1;
        for (int i = 0; i < covered.length; i++) {
            if (!covered[i]) {
                outside = i;
                break;
            }
        }

        assertTrue(outside >= 0);
        HellmanTable.LookupResult result =
                table.lookup(oracle.encryptState(outside));
        assertFalse(result.found());
    }

    private static long advance(
            long state,
            int steps,
            DesOracle oracle,
            LegacyReduction reduction) {
        long current = state;
        for (int i = 0; i < steps; i++) {
            current = reduction.reduce(oracle.encryptState(current));
        }
        return current;
    }
}

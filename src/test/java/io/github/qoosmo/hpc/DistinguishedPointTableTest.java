package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class DistinguishedPointTableTest {
    @Test
    void recoversExactTargetStateFromStoredChain() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DesOracle oracle =
                new DesOracle(space, "DP fixture".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(2, space);

        long start = findStartReachingDistinguishedPoint(
                space, oracle, reduction, predicate, 32);

        DistinguishedPointTable table =
                DistinguishedPointTable.build(
                        space,
                        oracle,
                        reduction,
                        predicate,
                        new long[] {start},
                        32);

        assertEquals(1, table.storedChains());

        DistinguishedPointTable.LookupResult result =
                table.lookup(oracle.encryptState(start));

        assertTrue(result.found());
        assertEquals(
                start,
                result.state().orElseThrow(),
                "lookup must return the verified target state, not a projected state");
        assertTrue(result.endpointCandidates() >= 1);
        assertTrue(result.candidateChainsChecked() >= 1);
    }

    @Test
    void accountsForChainsThatMissDistinguishedPointBeforeCutoff() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(10);
        DesOracle oracle =
                new DesOracle(space, "cutoff".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(6, space);

        long start = findStartMissingDistinguishedPointOnFirstTransition(
                space, oracle, reduction, predicate);

        DistinguishedPointTable table =
                DistinguishedPointTable.build(
                        space,
                        oracle,
                        reduction,
                        predicate,
                        new long[] {start},
                        1);

        assertEquals(1, table.generatedChains());
        assertEquals(0, table.storedChains());
        assertEquals(1, table.truncatedChains());
        assertEquals(0, table.distinctEndpointCount());
    }

    @Test
    void targetOutsideStoredChainIsNotReportedAsFound() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(10);
        DesOracle oracle =
                new DesOracle(space, "negative DP".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(2, space);

        long start = findStartReachingDistinguishedPoint(
                space, oracle, reduction, predicate, 16);

        DistinguishedPointTable table =
                DistinguishedPointTable.build(
                        space,
                        oracle,
                        reduction,
                        predicate,
                        new long[] {start},
                        16);

        boolean[] covered = coveredStates(
                space, oracle, reduction, predicate, start, 16);

        long outside = -1;
        for (int i = 0; i < covered.length; i++) {
            if (!covered[i]) {
                outside = i;
                break;
            }
        }

        assertTrue(outside >= 0);
        assertFalse(table.lookup(oracle.encryptState(outside)).found());
    }

    private static long findStartReachingDistinguishedPoint(
            ReducedDesKeySpace space,
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            int maxChainLength) {
        for (long start = 0; start < space.size(); start++) {
            long state = start;
            for (int i = 0; i < maxChainLength; i++) {
                state = reduction.reduce(oracle.encryptState(state));
                if (predicate.test(state)) {
                    return start;
                }
            }
        }
        throw new AssertionError("fixture did not find a chain reaching a distinguished point");
    }

    private static long findStartMissingDistinguishedPointOnFirstTransition(
            ReducedDesKeySpace space,
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate) {
        for (long start = 0; start < space.size(); start++) {
            long next = reduction.reduce(oracle.encryptState(start));
            if (!predicate.test(next)) {
                return start;
            }
        }
        throw new AssertionError("fixture did not find a truncated one-step chain");
    }

    private static boolean[] coveredStates(
            ReducedDesKeySpace space,
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            long start,
            int maxChainLength) {
        boolean[] covered = new boolean[(int) space.size()];
        long state = start;

        for (int i = 0; i < maxChainLength; i++) {
            covered[(int) state] = true;
            long next = reduction.reduce(oracle.encryptState(state));
            if (predicate.test(next)) {
                break;
            }
            state = next;
        }

        return covered;
    }
}

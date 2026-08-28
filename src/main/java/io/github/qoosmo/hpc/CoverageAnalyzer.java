package io.github.qoosmo.hpc;

import java.util.BitSet;

/**
 * Exact state-coverage analysis for small/medium reduced-keyspace experiments.
 *
 * <p>Coverage analysis is intentionally outside the timed table build/lookup
 * path. It replays chains and records represented reduced states in a BitSet.
 */
public final class CoverageAnalyzer {
    private CoverageAnalyzer() {}

    public static long hellmanCoverageStates(
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            long[] startStates,
            int chainLength) {
        requireCommon(keySpace, oracle, reduction, startStates);
        if (chainLength < 1) {
            throw new IllegalArgumentException("chainLength must be positive");
        }

        BitSet covered = new BitSet((int) keySpace.size());

        for (long start : startStates) {
            validateState(keySpace, start);
            long state = start;
            for (int i = 0; i < chainLength; i++) {
                covered.set((int) state);
                state = reduction.reduce(oracle.encryptState(state));
            }
        }

        return covered.cardinality();
    }

    public static long distinguishedPointCoverageStates(
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            long[] startStates,
            int maxChainLength) {
        requireCommon(keySpace, oracle, reduction, startStates);
        if (predicate == null) {
            throw new NullPointerException("predicate");
        }
        if (maxChainLength < 1) {
            throw new IllegalArgumentException("maxChainLength must be positive");
        }

        BitSet covered = new BitSet((int) keySpace.size());

        for (long start : startStates) {
            validateState(keySpace, start);

            int transitions = transitionsToDistinguishedPoint(
                    oracle, reduction, predicate, start, maxChainLength);

            if (transitions < 0) {
                continue;
            }

            long state = start;
            for (int i = 0; i < transitions; i++) {
                covered.set((int) state);
                state = reduction.reduce(oracle.encryptState(state));
            }
        }

        return covered.cardinality();
    }

    private static int transitionsToDistinguishedPoint(
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            long start,
            int maxChainLength) {
        long state = start;

        for (int transitions = 1; transitions <= maxChainLength; transitions++) {
            long next = reduction.reduce(oracle.encryptState(state));
            if (predicate.test(next)) {
                return transitions;
            }
            state = next;
        }

        return -1;
    }

    private static void requireCommon(
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            long[] startStates) {
        if (keySpace == null) {
            throw new NullPointerException("keySpace");
        }
        if (oracle == null) {
            throw new NullPointerException("oracle");
        }
        if (reduction == null) {
            throw new NullPointerException("reduction");
        }
        if (startStates == null) {
            throw new NullPointerException("startStates");
        }
    }

    private static void validateState(ReducedDesKeySpace keySpace, long state) {
        if (state < 0 || state >= keySpace.size()) {
            throw new IllegalArgumentException(
                    "start state outside reduced keyspace: " + state);
        }
    }
}

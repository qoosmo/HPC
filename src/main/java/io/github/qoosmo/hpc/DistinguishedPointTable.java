package io.github.qoosmo.hpc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Distinguished-point time-memory tradeoff table over the reduced DES state
 * space.
 *
 * <p>Only chains that reach a distinguished point within the configured
 * maximum length are stored. Endpoint collisions are retained and resolved by
 * regenerating candidate chains.
 */
public final class DistinguishedPointTable {
    private final DesOracle oracle;
    private final LegacyReduction reduction;
    private final DistinguishedPointPredicate predicate;
    private final int maxChainLength;
    private final Map<Long, List<Chain>> chainsByEndpoint;
    private final int generatedChains;
    private final int storedChains;
    private final int truncatedChains;

    private DistinguishedPointTable(
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            int maxChainLength,
            Map<Long, List<Chain>> chainsByEndpoint,
            int generatedChains,
            int storedChains,
            int truncatedChains) {
        this.oracle = oracle;
        this.reduction = reduction;
        this.predicate = predicate;
        this.maxChainLength = maxChainLength;
        this.chainsByEndpoint = chainsByEndpoint;
        this.generatedChains = generatedChains;
        this.storedChains = storedChains;
        this.truncatedChains = truncatedChains;
    }

    public static DistinguishedPointTable build(
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            long[] startStates,
            int maxChainLength) {
        if (keySpace == null) {
            throw new NullPointerException("keySpace");
        }
        if (oracle == null) {
            throw new NullPointerException("oracle");
        }
        if (reduction == null) {
            throw new NullPointerException("reduction");
        }
        if (predicate == null) {
            throw new NullPointerException("predicate");
        }
        if (startStates == null) {
            throw new NullPointerException("startStates");
        }
        if (maxChainLength < 1) {
            throw new IllegalArgumentException("maxChainLength must be positive");
        }

        Map<Long, List<Chain>> endpointIndex = new HashMap<>();
        Set<Long> uniqueStarts = new HashSet<>();
        int stored = 0;
        int truncated = 0;

        for (long start : startStates) {
            if (start < 0 || start >= keySpace.size()) {
                throw new IllegalArgumentException(
                        "start state outside reduced keyspace: " + start);
            }
            if (!uniqueStarts.add(start)) {
                throw new IllegalArgumentException("duplicate start state: " + start);
            }

            Chain chain = generateChain(
                    oracle, reduction, predicate, start, maxChainLength);

            if (chain == null) {
                truncated++;
                continue;
            }

            endpointIndex
                    .computeIfAbsent(chain.endpoint(), ignored -> new ArrayList<>())
                    .add(chain);
            stored++;
        }

        Map<Long, List<Chain>> immutableIndex = new HashMap<>();
        for (Map.Entry<Long, List<Chain>> entry : endpointIndex.entrySet()) {
            immutableIndex.put(entry.getKey(), List.copyOf(entry.getValue()));
        }

        return new DistinguishedPointTable(
                oracle,
                reduction,
                predicate,
                maxChainLength,
                Map.copyOf(immutableIndex),
                startStates.length,
                stored,
                truncated);
    }

    public int generatedChains() {
        return generatedChains;
    }

    public int storedChains() {
        return storedChains;
    }

    public int truncatedChains() {
        return truncatedChains;
    }

    public int distinctEndpointCount() {
        return chainsByEndpoint.size();
    }

    public int maxChainLength() {
        return maxChainLength;
    }

    /**
     * Attempts to recover the exact state whose encryption equals the target
     * ciphertext.
     *
     * <p>The target ciphertext first determines the next reduced state. The
     * online phase advances that state until a distinguished endpoint is
     * reached, then regenerates every stored chain sharing that endpoint and
     * verifies the original target ciphertext.
     */
    public LookupResult lookup(byte[] targetCiphertext) {
        if (targetCiphertext == null) {
            throw new NullPointerException("targetCiphertext");
        }

        long projected = reduction.reduce(targetCiphertext);
        int projectionSteps = 0;

        while (true) {
            if (predicate.test(projected)) {
                List<Chain> candidates = chainsByEndpoint.get(projected);
                if (candidates == null) {
                    return new LookupResult(
                            OptionalLong.empty(), projectionSteps, 0, 0);
                }

                int checked = 0;
                for (Chain chain : candidates) {
                    checked++;
                    OptionalLong recovered = regenerateAndFind(chain, targetCiphertext);
                    if (recovered.isPresent()) {
                        return new LookupResult(
                                recovered, projectionSteps, candidates.size(), checked);
                    }
                }

                return new LookupResult(
                        OptionalLong.empty(), projectionSteps, candidates.size(), checked);
            }

            if (projectionSteps >= maxChainLength - 1) {
                return new LookupResult(
                        OptionalLong.empty(), projectionSteps, 0, 0);
            }

            projected = step(projected);
            projectionSteps++;
        }
    }

    private OptionalLong regenerateAndFind(Chain chain, byte[] targetCiphertext) {
        long state = chain.start();

        for (int i = 0; i < chain.transitions(); i++) {
            byte[] ciphertext = oracle.encryptState(state);
            if (Arrays.equals(ciphertext, targetCiphertext)) {
                return OptionalLong.of(state);
            }
            state = reduction.reduce(ciphertext);
        }

        return OptionalLong.empty();
    }

    private long step(long state) {
        return reduction.reduce(oracle.encryptState(state));
    }

    private static Chain generateChain(
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            long start,
            int maxChainLength) {
        long state = start;

        for (int transitions = 1; transitions <= maxChainLength; transitions++) {
            long next = reduction.reduce(oracle.encryptState(state));
            if (predicate.test(next)) {
                return new Chain(start, next, transitions);
            }
            state = next;
        }

        return null;
    }

    private record Chain(long start, long endpoint, int transitions) {
        private Chain {
            if (transitions < 1) {
                throw new IllegalArgumentException("transitions must be positive");
            }
        }
    }

    public record LookupResult(
            OptionalLong state,
            int projectionSteps,
            int endpointCandidates,
            int candidateChainsChecked) {
        public LookupResult {
            if (state == null) {
                throw new NullPointerException("state");
            }
            if (projectionSteps < 0
                    || endpointCandidates < 0
                    || candidateChainsChecked < 0) {
                throw new IllegalArgumentException("lookup counters must be non-negative");
            }
        }

        public boolean found() {
            return state.isPresent();
        }
    }
}

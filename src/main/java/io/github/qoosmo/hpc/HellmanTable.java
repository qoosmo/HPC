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
 * Hellman time-memory tradeoff table over a deliberately reduced DES keyspace.
 *
 * <p>Each chain repeatedly applies {@code R(E(state))}. Endpoints are indexed
 * in a hash map so online lookup does not perform the nested linear scans used
 * by the historical prototype.
 */
public final class HellmanTable {
    private final DesOracle oracle;
    private final LegacyReduction reduction;
    private final int chainLength;
    private final Map<Long, List<Long>> startsByEndpoint;
    private final int chainCount;

    private HellmanTable(
            DesOracle oracle,
            LegacyReduction reduction,
            int chainLength,
            Map<Long, List<Long>> startsByEndpoint,
            int chainCount) {
        this.oracle = oracle;
        this.reduction = reduction;
        this.chainLength = chainLength;
        this.startsByEndpoint = startsByEndpoint;
        this.chainCount = chainCount;
    }

    public static HellmanTable build(
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            long[] startStates,
            int chainLength) {
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
        if (chainLength < 1) {
            throw new IllegalArgumentException("chainLength must be positive");
        }

        Map<Long, List<Long>> endpointIndex = new HashMap<>();
        Set<Long> uniqueStarts = new HashSet<>();

        for (long start : startStates) {
            if (start < 0 || start >= keySpace.size()) {
                throw new IllegalArgumentException(
                        "start state outside reduced keyspace: " + start);
            }
            if (!uniqueStarts.add(start)) {
                throw new IllegalArgumentException("duplicate start state: " + start);
            }

            long endpoint = endpoint(oracle, reduction, start, chainLength);
            endpointIndex
                    .computeIfAbsent(endpoint, ignored -> new ArrayList<>())
                    .add(start);
        }

        Map<Long, List<Long>> immutableIndex = new HashMap<>();
        for (Map.Entry<Long, List<Long>> entry : endpointIndex.entrySet()) {
            immutableIndex.put(entry.getKey(), List.copyOf(entry.getValue()));
        }

        return new HellmanTable(
                oracle,
                reduction,
                chainLength,
                Map.copyOf(immutableIndex),
                startStates.length);
    }

    public int chainCount() {
        return chainCount;
    }

    public int distinctEndpointCount() {
        return startsByEndpoint.size();
    }

    public int chainLength() {
        return chainLength;
    }

    /**
     * Search for a reduced-keyspace state encrypting to {@code targetCiphertext}.
     *
     * <p>{@code endpointMatches} counts projected endpoints that hit the table.
     * {@code candidateChainsChecked} counts distinct stored chains regenerated
     * to reject collisions or confirm the target.
     */
    public LookupResult lookup(byte[] targetCiphertext) {
        if (targetCiphertext == null) {
            throw new NullPointerException("targetCiphertext");
        }

        int endpointMatches = 0;
        int candidateChainsChecked = 0;
        Set<Long> checkedStarts = new HashSet<>();

        for (int targetPosition = chainLength - 1; targetPosition >= 0; targetPosition--) {
            long projectedEndpoint = projectToEndpoint(targetCiphertext, targetPosition);
            List<Long> candidates = startsByEndpoint.get(projectedEndpoint);
            if (candidates == null) {
                continue;
            }

            endpointMatches++;

            for (long start : candidates) {
                if (!checkedStarts.add(start)) {
                    continue;
                }

                candidateChainsChecked++;
                OptionalLong recovered = regenerateAndFind(start, targetCiphertext);
                if (recovered.isPresent()) {
                    return new LookupResult(
                            recovered, endpointMatches, candidateChainsChecked);
                }
            }
        }

        return new LookupResult(
                OptionalLong.empty(), endpointMatches, candidateChainsChecked);
    }

    private long projectToEndpoint(byte[] targetCiphertext, int targetPosition) {
        long state = reduction.reduce(targetCiphertext);

        for (int position = targetPosition + 1; position < chainLength; position++) {
            state = step(state);
        }

        return state;
    }

    private OptionalLong regenerateAndFind(long start, byte[] targetCiphertext) {
        long state = start;

        for (int position = 0; position < chainLength; position++) {
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

    private static long endpoint(
            DesOracle oracle,
            LegacyReduction reduction,
            long start,
            int chainLength) {
        long state = start;
        for (int i = 0; i < chainLength; i++) {
            state = reduction.reduce(oracle.encryptState(state));
        }
        return state;
    }

    public record LookupResult(
            OptionalLong state,
            int endpointMatches,
            int candidateChainsChecked) {
        public LookupResult {
            if (state == null) {
                throw new NullPointerException("state");
            }
            if (endpointMatches < 0 || candidateChainsChecked < 0) {
                throw new IllegalArgumentException("lookup counters must be non-negative");
            }
        }

        public boolean found() {
            return state.isPresent();
        }
    }
}

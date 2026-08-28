package io.github.qoosmo.hpc;

import java.util.OptionalLong;

/**
 * Exhaustive search over a {@link ReducedDesKeySpace}.
 */
public final class ExhaustiveSearch {
    private final ReducedDesKeySpace keySpace;
    private final DesOracle oracle;

    public ExhaustiveSearch(ReducedDesKeySpace keySpace, DesOracle oracle) {
        if (keySpace == null) {
            throw new NullPointerException("keySpace");
        }
        if (oracle == null) {
            throw new NullPointerException("oracle");
        }
        this.keySpace = keySpace;
        this.oracle = oracle;
    }

    /**
     * Returns the first reduced-keyspace state whose encryption matches the
     * supplied ciphertext.
     */
    public OptionalLong find(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext");
        }

        for (long state = 0; state < keySpace.size(); state++) {
            if (oracle.matches(state, ciphertext)) {
                return OptionalLong.of(state);
            }
        }
        return OptionalLong.empty();
    }
}

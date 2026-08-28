package io.github.qoosmo.hpc;

/**
 * Distinguished-point predicate over reduced states.
 *
 * <p>A state is distinguished when its configured number of low-order state
 * bits are zero. For a roughly uniform state mapping, the expected chain
 * length before a distinguished point is approximately 2^difficultyBits.
 */
public final class DistinguishedPointPredicate {
    private final int difficultyBits;
    private final long mask;

    public DistinguishedPointPredicate(int difficultyBits, ReducedDesKeySpace keySpace) {
        if (keySpace == null) {
            throw new NullPointerException("keySpace");
        }
        if (difficultyBits < 1 || difficultyBits > keySpace.stateBits()) {
            throw new IllegalArgumentException(
                    "difficultyBits must be in [1, " + keySpace.stateBits() + "]");
        }
        this.difficultyBits = difficultyBits;
        this.mask = (1L << difficultyBits) - 1L;
    }

    public int difficultyBits() {
        return difficultyBits;
    }

    public boolean test(long state) {
        return (state & mask) == 0L;
    }
}

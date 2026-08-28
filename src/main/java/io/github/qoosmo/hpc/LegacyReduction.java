package io.github.qoosmo.hpc;

/**
 * Reduction function matching the effective-bit structure of the historical
 * prototype.
 *
 * <p>The legacy implementation copied the final four ciphertext bytes into the
 * variable half of a DES key. DES ignores one parity bit per byte, so the
 * modern model extracts the upper seven effective bits of each of those four
 * bytes, giving a 28-bit state before truncation to the configured reduced
 * keyspace.
 */
public final class LegacyReduction {
    private static final int SOURCE_BYTES = 4;

    private final long stateMask;

    public LegacyReduction(ReducedDesKeySpace keySpace) {
        if (keySpace == null) {
            throw new NullPointerException("keySpace");
        }
        this.stateMask = keySpace.size() - 1L;
    }

    public long reduce(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new NullPointerException("ciphertext");
        }
        if (ciphertext.length < SOURCE_BYTES) {
            throw new IllegalArgumentException(
                    "ciphertext must contain at least four bytes");
        }

        long state = 0L;
        int start = ciphertext.length - SOURCE_BYTES;
        for (int i = start; i < ciphertext.length; i++) {
            int effectiveSevenBits = Byte.toUnsignedInt(ciphertext[i]) >>> 1;
            state = (state << 7) | effectiveSevenBits;
        }

        return state & stateMask;
    }
}

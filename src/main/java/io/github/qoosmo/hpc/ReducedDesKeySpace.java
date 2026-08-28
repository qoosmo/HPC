package io.github.qoosmo.hpc;

import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A deliberately reduced DES keyspace used only for reproducible experiments.
 *
 * <p>DES stores a key in 8 bytes, but one bit of each byte is a parity bit.
 * This class varies only effective DES key bits: each variable byte contributes
 * seven state bits, and the least-significant bit is set to odd parity.
 *
 * <p>The first four DES bytes are fixed at the same effective data bits as the
 * legacy prototype's 0xff prefix. The final four bytes carry at most 28
 * effective state bits. Therefore {@code stateBits} is an effective-state
 * dimension, not a count of raw Java key-representation bits.
 */
public final class ReducedDesKeySpace {
    public static final int MAX_STATE_BITS = 28;
    private static final int DES_KEY_BYTES = 8;
    private static final int VARIABLE_BYTES = 4;
    private static final int FIXED_SEVEN_BITS = 0x7f;

    private final int stateBits;
    private final long size;
    private final long stateMask;

    public ReducedDesKeySpace(int stateBits) {
        if (stateBits < 1 || stateBits > MAX_STATE_BITS) {
            throw new IllegalArgumentException(
                    "stateBits must be in [1, " + MAX_STATE_BITS + "]");
        }
        this.stateBits = stateBits;
        this.size = 1L << stateBits;
        this.stateMask = size - 1L;
    }

    public int stateBits() {
        return stateBits;
    }

    public long size() {
        return size;
    }

    public SecretKey toKey(long state) {
        return new SecretKeySpec(toKeyBytes(state), "DES");
    }

    public byte[] toKeyBytes(long state) {
        validateState(state);

        byte[] key = new byte[DES_KEY_BYTES];

        for (int i = 0; i < DES_KEY_BYTES - VARIABLE_BYTES; i++) {
            key[i] = withOddParity(FIXED_SEVEN_BITS);
        }

        long remaining = state;
        for (int i = DES_KEY_BYTES - 1; i >= DES_KEY_BYTES - VARIABLE_BYTES; i--) {
            int sevenBits = (int) (remaining & 0x7fL);
            key[i] = withOddParity(sevenBits);
            remaining >>>= 7;
        }

        return key;
    }

    public long toState(byte[] keyBytes) {
        Objects.requireNonNull(keyBytes, "keyBytes");
        if (keyBytes.length != DES_KEY_BYTES) {
            throw new IllegalArgumentException("DES key encoding must contain exactly 8 bytes");
        }

        long state = 0L;
        for (int i = DES_KEY_BYTES - VARIABLE_BYTES; i < DES_KEY_BYTES; i++) {
            int unsigned = Byte.toUnsignedInt(keyBytes[i]);
            int sevenBits = unsigned >>> 1;
            state = (state << 7) | sevenBits;
        }

        if ((state & ~stateMask) != 0L) {
            throw new IllegalArgumentException(
                    "key contains variable DES bits outside this reduced keyspace");
        }
        return state;
    }

    private void validateState(long state) {
        if (state < 0 || state >= size) {
            throw new IllegalArgumentException(
                    "state must be in [0, " + (size - 1L) + "]");
        }
    }

    private static byte withOddParity(int sevenBits) {
        int data = (sevenBits & 0x7f) << 1;
        int parity = (Integer.bitCount(sevenBits & 0x7f) & 1) == 0 ? 1 : 0;
        return (byte) (data | parity);
    }
}

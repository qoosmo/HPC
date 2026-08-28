package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

final class ReducedDesKeySpaceTest {
    @Test
    void reportsExactStateSpaceSize() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(16);
        assertEquals(16, space.stateBits());
        assertEquals(1L << 16, space.size());
    }

    @Test
    void rejectsUnsupportedDimensions() {
        assertThrows(IllegalArgumentException.class, () -> new ReducedDesKeySpace(0));
        assertThrows(IllegalArgumentException.class, () -> new ReducedDesKeySpace(29));
    }

    @Test
    void rejectsStatesOutsideConfiguredSpace() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        assertThrows(IllegalArgumentException.class, () -> space.toKeyBytes(-1));
        assertThrows(IllegalArgumentException.class, () -> space.toKeyBytes(1L << 12));
    }

    @Test
    void stateEncodingRoundTrips() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(16);
        long[] states = {0, 1, 2, 126, 127, 128, 255, 256, 65535};

        for (long state : states) {
            assertEquals(state, space.toState(space.toKeyBytes(state)));
        }
    }

    @Test
    void everyEncodedDesByteHasOddParity() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(20);
        long[] states = {0, 1, 127, 128, 0x12345, space.size() - 1};

        for (long state : states) {
            for (byte value : space.toKeyBytes(state)) {
                int ones = Integer.bitCount(Byte.toUnsignedInt(value));
                assertEquals(1, ones & 1, "DES byte must have odd parity");
            }
        }
    }

    @Test
    void secretKeyUsesCanonicalEncoding() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(16);
        assertArrayEquals(space.toKeyBytes(42), space.toKey(42).getEncoded());
    }

    @Test
    void rejectsKeyOutsideConfiguredReducedSpace() {
        ReducedDesKeySpace large = new ReducedDesKeySpace(28);
        ReducedDesKeySpace small = new ReducedDesKeySpace(8);
        byte[] outside = large.toKeyBytes(1L << 20);

        assertThrows(IllegalArgumentException.class, () -> small.toState(outside));
    }
}

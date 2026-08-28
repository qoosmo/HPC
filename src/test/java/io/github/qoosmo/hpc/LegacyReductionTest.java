package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class LegacyReductionTest {
    @Test
    void outputAlwaysFitsConfiguredStateSpace() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        LegacyReduction reduction = new LegacyReduction(space);

        byte[] ciphertext = {
            1, 2, 3, 4, 5, 6, (byte) 0xfe, (byte) 0xff
        };

        long state = reduction.reduce(ciphertext);
        assertTrue(state >= 0);
        assertTrue(state < space.size());
    }

    @Test
    void ignoresDesParityBitOfEachSourceByte() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(28);
        LegacyReduction reduction = new LegacyReduction(space);

        byte[] a = {10, 20, 30, 40, 0x22, 0x44, 0x66, (byte) 0x88};
        byte[] b = a.clone();

        for (int i = b.length - 4; i < b.length; i++) {
            b[i] ^= 0x01;
        }

        assertEquals(reduction.reduce(a), reduction.reduce(b));
    }

    @Test
    void rejectsTooShortCiphertext() {
        LegacyReduction reduction = new LegacyReduction(new ReducedDesKeySpace(8));
        assertThrows(
                IllegalArgumentException.class,
                () -> reduction.reduce(new byte[] {1, 2, 3}));
    }
}

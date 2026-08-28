package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class DistinguishedPointPredicateTest {
    @Test
    void recognizesConfiguredZeroSuffix() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(12);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(4, space);

        assertTrue(predicate.test(0b1010_0000));
        assertTrue(predicate.test(0));
        assertFalse(predicate.test(0b1010_0001));
    }

    @Test
    void validatesDifficultyAgainstStateDimension() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(8);

        assertThrows(
                IllegalArgumentException.class,
                () -> new DistinguishedPointPredicate(0, space));
        assertThrows(
                IllegalArgumentException.class,
                () -> new DistinguishedPointPredicate(9, space));
    }
}

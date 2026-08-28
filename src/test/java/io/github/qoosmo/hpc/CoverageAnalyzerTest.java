package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class CoverageAnalyzerTest {
    @Test
    void hellmanCoverageCountsUniqueRepresentedStates() {
        ReducedDesKeySpace space = new ReducedDesKeySpace(8);
        DesOracle oracle =
                new DesOracle(space, "coverage".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(space);

        long coverage =
                CoverageAnalyzer.hellmanCoverageStates(
                        space, oracle, reduction, new long[] {1, 2, 3}, 4);

        assertTrue(coverage >= 3);
        assertTrue(coverage <= 12);
    }

    @Test
    void exactCoverageRunnerIsDeterministic() {
        ExperimentRunner.Config config =
                new ExperimentRunner.Config(
                        8,
                        2,
                        123L,
                        16,
                        4,
                        16,
                        2,
                        8,
                        java.nio.file.Path.of("ignored.csv"));

        var a = ExactCoverageRunner.run(config);
        var b = ExactCoverageRunner.run(config);

        assertEquals(a, b);
        assertEquals(6, a.size());
    }
}

package io.github.qoosmo.hpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ExperimentRunnerTest {
    @TempDir
    Path tempDir;

    @Test
    void smokeExperimentProducesOneRowPerMethodPerTrial() {
        ExperimentRunner.Config config =
                new ExperimentRunner.Config(
                        8,
                        2,
                        12345L,
                        32,
                        8,
                        32,
                        2,
                        16,
                        tempDir.resolve("smoke.csv"));

        List<ExperimentRunner.Result> results = ExperimentRunner.run(config);

        assertEquals(6, results.size());
        assertEquals(2, results.stream().filter(r -> r.method().equals("exhaustive")).count());
        assertEquals(2, results.stream().filter(r -> r.method().equals("hellman")).count());
        assertEquals(
                2,
                results.stream()
                        .filter(r -> r.method().equals("distinguished_points"))
                        .count());
        assertTrue(
                results.stream()
                        .filter(r -> r.method().equals("exhaustive"))
                        .allMatch(ExperimentRunner.Result::exactRecovery));
    }

    @Test
    void uniqueRandomStatesAreDeterministicAndUnique() {
        long[] a =
                ExperimentRunner.uniqueRandomStates(
                        new SplittableRandom(7L), 256, 64);
        long[] b =
                ExperimentRunner.uniqueRandomStates(
                        new SplittableRandom(7L), 256, 64);

        assertEquals(64, a.length);
        org.junit.jupiter.api.Assertions.assertArrayEquals(a, b);

        for (int i = 1; i < a.length; i++) {
            assertTrue(a[i - 1] < a[i]);
        }
    }

    @Test
    void csvWriterEmitsHeaderAndRows() throws Exception {
        ExperimentRunner.Config config =
                new ExperimentRunner.Config(
                        8,
                        1,
                        1L,
                        16,
                        4,
                        16,
                        2,
                        8,
                        tempDir.resolve("results.csv"));

        List<ExperimentRunner.Result> results = ExperimentRunner.run(config);
        ExperimentRunner.writeCsv(config.output(), results);

        List<String> lines = Files.readAllLines(config.output());
        assertEquals(4, lines.size());
        assertEquals(ExperimentRunner.Result.csvHeader(), lines.get(0));
        assertTrue(lines.get(1).startsWith("0,"));
    }
}

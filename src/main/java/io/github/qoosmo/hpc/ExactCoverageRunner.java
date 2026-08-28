package io.github.qoosmo.hpc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.SplittableRandom;

/**
 * Replays the exact seeded experiment-table generation and computes exact
 * reduced-state coverage outside the timed benchmark path.
 */
public final class ExactCoverageRunner {
    private static final byte[] PLAINTEXT =
            "HPC reproducibility fixture".getBytes(StandardCharsets.UTF_8);

    private ExactCoverageRunner() {}

    public static void main(String[] args) throws Exception {
        ExperimentRunner.Config config = ExperimentRunner.Config.parse(args);
        List<CoverageResult> results = run(config);
        writeCsv(config.output(), results);
        System.out.println("WROTE " + config.output().toAbsolutePath());
        System.out.println("ROWS " + results.size());
    }

    public static List<CoverageResult> run(ExperimentRunner.Config config) {
        ReducedDesKeySpace keySpace = new ReducedDesKeySpace(config.stateBits());
        DesOracle oracle = new DesOracle(keySpace, PLAINTEXT);
        LegacyReduction reduction = new LegacyReduction(keySpace);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(config.dpDifficultyBits(), keySpace);

        SplittableRandom random = new SplittableRandom(config.seed());
        List<CoverageResult> rows = new ArrayList<>(config.trials() * 3);

        for (int trial = 0; trial < config.trials(); trial++) {
            // Advance the RNG exactly as ExperimentRunner does for the target.
            random.nextLong(keySpace.size());

            long[] hellmanStarts =
                    ExperimentRunner.uniqueRandomStates(
                            random, keySpace.size(), config.hellmanChains());

            long hellmanCoverage =
                    CoverageAnalyzer.hellmanCoverageStates(
                            keySpace,
                            oracle,
                            reduction,
                            hellmanStarts,
                            config.hellmanChainLength());

            rows.add(new CoverageResult(
                    trial,
                    "hellman",
                    hellmanCoverage,
                    ((double) hellmanCoverage) / keySpace.size()));

            long[] dpStarts =
                    ExperimentRunner.uniqueRandomStates(
                            random, keySpace.size(), config.dpChains());

            long dpCoverage =
                    CoverageAnalyzer.distinguishedPointCoverageStates(
                            keySpace,
                            oracle,
                            reduction,
                            predicate,
                            dpStarts,
                            config.dpMaxChainLength());

            rows.add(new CoverageResult(
                    trial,
                    "distinguished_points",
                    dpCoverage,
                    ((double) dpCoverage) / keySpace.size()));

            rows.add(new CoverageResult(
                    trial,
                    "exhaustive",
                    keySpace.size(),
                    1.0));
        }

        return List.copyOf(rows);
    }

    public static void writeCsv(Path output, List<CoverageResult> rows)
            throws IOException {
        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        StringBuilder csv = new StringBuilder();
        csv.append("trial,method,coverage_states,coverage_fraction\n");
        for (CoverageResult row : rows) {
            csv.append(row.toCsv()).append('\n');
        }

        Files.writeString(output, csv.toString(), StandardCharsets.UTF_8);
    }

    public record CoverageResult(
            int trial,
            String method,
            long coverageStates,
            double coverageFraction) {
        public String toCsv() {
            return String.format(
                    Locale.ROOT,
                    "%d,%s,%d,%.8f",
                    trial,
                    method,
                    coverageStates,
                    coverageFraction);
        }
    }
}

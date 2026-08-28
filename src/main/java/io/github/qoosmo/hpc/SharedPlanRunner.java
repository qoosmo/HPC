package io.github.qoosmo.hpc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs a literal language-neutral experiment plan and emits deterministic
 * algorithmic results only. Timings are intentionally excluded.
 */
public final class SharedPlanRunner {
    private SharedPlanRunner() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException(
                    "usage: SharedPlanRunner <plan-directory> <output.csv>");
        }

        Plan plan = Plan.load(Path.of(args[0]));
        List<Row> rows = run(plan);
        write(Path.of(args[1]), rows);

        System.out.println("SHARED_PLAN_ROWS=" + rows.size());
        System.out.println("WROTE " + Path.of(args[1]).toAbsolutePath());
    }

    static List<Row> run(Plan plan) {
        ReducedDesKeySpace keySpace = new ReducedDesKeySpace(plan.stateBits());
        if (keySpace.size() != plan.stateSpaceSize()) {
            throw new IllegalArgumentException("metadata state-space size mismatch");
        }

        DesOracle oracle = new DesOracle(
                keySpace,
                "HPC reproducibility fixture".getBytes(StandardCharsets.UTF_8));
        LegacyReduction reduction = new LegacyReduction(keySpace);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(plan.dpDifficultyBits(), keySpace);

        List<Row> rows = new ArrayList<>(plan.trials());

        for (int trial = 0; trial < plan.trials(); trial++) {
            long targetState = plan.targets()[trial];
            byte[] targetCiphertext = oracle.encryptState(targetState);

            long[] hellmanStarts = plan.hellmanStarts()[trial];
            HellmanTable hellman = HellmanTable.build(
                    keySpace, oracle, reduction, hellmanStarts, plan.hellmanChainLength());
            HellmanTable.LookupResult hellmanLookup = hellman.lookup(targetCiphertext);
            long hellmanCoverage = CoverageAnalyzer.hellmanCoverageStates(
                    keySpace, oracle, reduction, hellmanStarts, plan.hellmanChainLength());

            long[] dpStarts = plan.dpStarts()[trial];
            DistinguishedPointTable dp = DistinguishedPointTable.build(
                    keySpace,
                    oracle,
                    reduction,
                    predicate,
                    dpStarts,
                    plan.dpMaxChainLength());
            DistinguishedPointTable.LookupResult dpLookup = dp.lookup(targetCiphertext);
            long dpCoverage = CoverageAnalyzer.distinguishedPointCoverageStates(
                    keySpace,
                    oracle,
                    reduction,
                    predicate,
                    dpStarts,
                    plan.dpMaxChainLength());

            rows.add(new Row(
                    trial,
                    targetState,
                    hex(targetCiphertext),
                    hellmanCoverage,
                    hellman.distinctEndpointCount(),
                    hellmanLookup.state().orElse(-1L),
                    hellmanLookup.state().isPresent()
                            && hellmanLookup.state().getAsLong() == targetState,
                    hellmanLookup.endpointMatches(),
                    hellmanLookup.candidateChainsChecked(),
                    dpCoverage,
                    dp.generatedChains(),
                    dp.storedChains(),
                    dp.truncatedChains(),
                    dp.distinctEndpointCount(),
                    dpLookup.state().orElse(-1L),
                    dpLookup.state().isPresent()
                            && dpLookup.state().getAsLong() == targetState,
                    dpLookup.endpointCandidates(),
                    dpLookup.candidateChainsChecked(),
                    dpLookup.projectionSteps()));
        }

        return List.copyOf(rows);
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", Byte.toUnsignedInt(value)));
        }
        return builder.toString();
    }

    private static void write(Path output, List<Row> rows) throws IOException {
        if (output.getParent() != null) {
            Files.createDirectories(output.getParent());
        }
        StringBuilder csv = new StringBuilder();
        csv.append(Row.header()).append('\n');
        for (Row row : rows) {
            csv.append(row.toCsv()).append('\n');
        }
        Files.writeString(output, csv, StandardCharsets.UTF_8);
    }

    record Row(
            int trial,
            long targetState,
            String targetCiphertextHex,
            long hellmanCoverage,
            int hellmanDistinctEndpoints,
            long hellmanRecoveredState,
            boolean hellmanExactRecovery,
            int hellmanEndpointMatches,
            int hellmanCandidateChainsChecked,
            long dpCoverage,
            int dpGeneratedChains,
            int dpStoredChains,
            int dpTruncatedChains,
            int dpDistinctEndpoints,
            long dpRecoveredState,
            boolean dpExactRecovery,
            int dpEndpointCandidates,
            int dpCandidateChainsChecked,
            int dpProjectionSteps) {

        static String header() {
            return String.join(",",
                    "trial",
                    "target_state",
                    "target_ciphertext_hex",
                    "hellman_coverage",
                    "hellman_distinct_endpoints",
                    "hellman_recovered_state",
                    "hellman_exact_recovery",
                    "hellman_endpoint_matches",
                    "hellman_candidate_chains_checked",
                    "dp_coverage",
                    "dp_generated_chains",
                    "dp_stored_chains",
                    "dp_truncated_chains",
                    "dp_distinct_endpoints",
                    "dp_recovered_state",
                    "dp_exact_recovery",
                    "dp_endpoint_candidates",
                    "dp_candidate_chains_checked",
                    "dp_projection_steps");
        }

        String toCsv() {
            return String.join(",",
                    Integer.toString(trial),
                    Long.toString(targetState),
                    targetCiphertextHex,
                    Long.toString(hellmanCoverage),
                    Integer.toString(hellmanDistinctEndpoints),
                    Long.toString(hellmanRecoveredState),
                    Boolean.toString(hellmanExactRecovery),
                    Integer.toString(hellmanEndpointMatches),
                    Integer.toString(hellmanCandidateChainsChecked),
                    Long.toString(dpCoverage),
                    Integer.toString(dpGeneratedChains),
                    Integer.toString(dpStoredChains),
                    Integer.toString(dpTruncatedChains),
                    Integer.toString(dpDistinctEndpoints),
                    Long.toString(dpRecoveredState),
                    Boolean.toString(dpExactRecovery),
                    Integer.toString(dpEndpointCandidates),
                    Integer.toString(dpCandidateChainsChecked),
                    Integer.toString(dpProjectionSteps));
        }
    }

    record Plan(
            int stateBits,
            long stateSpaceSize,
            int trials,
            int hellmanChains,
            int hellmanChainLength,
            int dpChains,
            int dpDifficultyBits,
            int dpMaxChainLength,
            long[] targets,
            long[][] hellmanStarts,
            long[][] dpStarts) {

        static Plan load(Path directory) throws IOException {
            Map<String, Long> metadata = readMetadata(directory.resolve("metadata.csv"));

            int stateBits = intValue(metadata, "state_bits");
            long stateSpaceSize = longValue(metadata, "state_space_size");
            int trials = intValue(metadata, "trials");
            int hellmanChains = intValue(metadata, "hellman_chains");
            int hellmanChainLength = intValue(metadata, "hellman_chain_length");
            int dpChains = intValue(metadata, "dp_chains");
            int dpDifficultyBits = intValue(metadata, "dp_difficulty_bits");
            int dpMaxChainLength = intValue(metadata, "dp_max_chain_length");

            return new Plan(
                    stateBits,
                    stateSpaceSize,
                    trials,
                    hellmanChains,
                    hellmanChainLength,
                    dpChains,
                    dpDifficultyBits,
                    dpMaxChainLength,
                    readTargets(directory.resolve("targets.csv"), trials),
                    readStarts(directory.resolve("hellman-starts.csv"), trials, hellmanChains),
                    readStarts(directory.resolve("dp-starts.csv"), trials, dpChains));
        }

        private static Map<String, Long> readMetadata(Path path) throws IOException {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            requireHeader(lines, "key,value");
            Map<String, Long> values = new HashMap<>();
            for (int i = 1; i < lines.size(); i++) {
                String[] fields = lines.get(i).split(",", -1);
                if (fields.length != 2) {
                    throw new IllegalArgumentException("invalid metadata row: " + lines.get(i));
                }
                values.put(fields[0], Long.parseLong(fields[1]));
            }
            return Map.copyOf(values);
        }

        private static long[] readTargets(Path path, int trials) throws IOException {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            requireHeader(lines, "trial,target_state");
            if (lines.size() != trials + 1) {
                throw new IllegalArgumentException("target row count mismatch");
            }
            long[] result = new long[trials];
            for (int i = 1; i < lines.size(); i++) {
                String[] fields = lines.get(i).split(",", -1);
                int trial = Integer.parseInt(fields[0]);
                if (trial != i - 1) {
                    throw new IllegalArgumentException("targets must be ordered by trial");
                }
                result[trial] = Long.parseLong(fields[1]);
            }
            return result;
        }

        private static long[][] readStarts(Path path, int trials, int count)
                throws IOException {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            requireHeader(lines, "trial,index,start_state");
            if (lines.size() != trials * count + 1) {
                throw new IllegalArgumentException("start row count mismatch for " + path);
            }

            long[][] result = new long[trials][count];
            int[] nextIndex = new int[trials];

            for (int i = 1; i < lines.size(); i++) {
                String[] fields = lines.get(i).split(",", -1);
                int trial = Integer.parseInt(fields[0]);
                int index = Integer.parseInt(fields[1]);
                long state = Long.parseLong(fields[2]);

                if (trial < 0 || trial >= trials) {
                    throw new IllegalArgumentException("invalid trial in " + path);
                }
                if (index != nextIndex[trial] || index >= count) {
                    throw new IllegalArgumentException("non-contiguous start index in " + path);
                }

                result[trial][index] = state;
                nextIndex[trial]++;
            }

            for (int trial = 0; trial < trials; trial++) {
                if (nextIndex[trial] != count) {
                    throw new IllegalArgumentException("incomplete starts for trial " + trial);
                }
            }

            return result;
        }

        private static void requireHeader(List<String> lines, String expected) {
            if (lines.isEmpty() || !lines.get(0).equals(expected)) {
                throw new IllegalArgumentException("expected CSV header: " + expected);
            }
        }

        private static int intValue(Map<String, Long> values, String key) {
            return Math.toIntExact(longValue(values, key));
        }

        private static long longValue(Map<String, Long> values, String key) {
            Long value = values.get(key);
            if (value == null) {
                throw new IllegalArgumentException("missing metadata key: " + key);
            }
            return value;
        }
    }
}

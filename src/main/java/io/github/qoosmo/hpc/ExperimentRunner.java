package io.github.qoosmo.hpc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.OptionalLong;
import java.util.Set;
import java.util.SplittableRandom;

/**
 * Reproducible benchmark harness for exhaustive search, Hellman TMTO, and
 * distinguished-point TMTO over the deliberately reduced DES state space.
 *
 * <p>The runner reports measured wall-clock durations from {@link System#nanoTime()}.
 * Results are benchmark observations for this implementation and machine, not
 * cryptographic security estimates.
 */
public final class ExperimentRunner {
    private static final byte[] DEFAULT_PLAINTEXT =
            "HPC reproducibility fixture".getBytes(StandardCharsets.UTF_8);

    private ExperimentRunner() {}

    public static void main(String[] args) throws Exception {
        Config config = Config.parse(args);
        List<Result> results = run(config);
        writeCsv(config.output(), results);

        System.out.println("WROTE " + config.output().toAbsolutePath());
        System.out.println("ROWS " + results.size());
    }

    public static List<Result> run(Config config) {
        ReducedDesKeySpace keySpace = new ReducedDesKeySpace(config.stateBits());
        DesOracle oracle = new DesOracle(keySpace, DEFAULT_PLAINTEXT);
        LegacyReduction reduction = new LegacyReduction(keySpace);
        DistinguishedPointPredicate predicate =
                new DistinguishedPointPredicate(config.dpDifficultyBits(), keySpace);

        SplittableRandom random = new SplittableRandom(config.seed());
        List<Result> results = new ArrayList<>(config.trials() * 3);

        for (int trial = 0; trial < config.trials(); trial++) {
            long targetState = random.nextLong(keySpace.size());
            byte[] targetCiphertext = oracle.encryptState(targetState);

            results.add(runExhaustive(
                    config, trial, targetState, targetCiphertext, keySpace, oracle));

            long[] hellmanStarts =
                    uniqueRandomStates(random, keySpace.size(), config.hellmanChains());
            results.add(runHellman(
                    config,
                    trial,
                    targetState,
                    targetCiphertext,
                    keySpace,
                    oracle,
                    reduction,
                    hellmanStarts));

            long[] dpStarts =
                    uniqueRandomStates(random, keySpace.size(), config.dpChains());
            results.add(runDistinguishedPoints(
                    config,
                    trial,
                    targetState,
                    targetCiphertext,
                    keySpace,
                    oracle,
                    reduction,
                    predicate,
                    dpStarts));
        }

        return List.copyOf(results);
    }

    private static Result runExhaustive(
            Config config,
            int trial,
            long targetState,
            byte[] targetCiphertext,
            ReducedDesKeySpace keySpace,
            DesOracle oracle) {
        ExhaustiveSearch search = new ExhaustiveSearch(keySpace, oracle);

        long start = System.nanoTime();
        OptionalLong recovered = search.find(targetCiphertext);
        long onlineNs = System.nanoTime() - start;

        boolean exact = recovered.isPresent() && recovered.getAsLong() == targetState;

        return new Result(
                trial,
                "exhaustive",
                config.stateBits(),
                targetState,
                0,
                0,
                0,
                0,
                0,
                0L,
                onlineNs,
                exact,
                recovered.orElse(-1L),
                0,
                0,
                0,
                0);
    }

    private static Result runHellman(
            Config config,
            int trial,
            long targetState,
            byte[] targetCiphertext,
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            long[] starts) {
        long offlineStart = System.nanoTime();
        HellmanTable table =
                HellmanTable.build(
                        keySpace,
                        oracle,
                        reduction,
                        starts,
                        config.hellmanChainLength());
        long offlineNs = System.nanoTime() - offlineStart;

        long onlineStart = System.nanoTime();
        HellmanTable.LookupResult lookup = table.lookup(targetCiphertext);
        long onlineNs = System.nanoTime() - onlineStart;

        long recovered = lookup.state().orElse(-1L);
        boolean exact = lookup.found() && recovered == targetState;

        return new Result(
                trial,
                "hellman",
                config.stateBits(),
                targetState,
                config.hellmanChains(),
                config.hellmanChainLength(),
                0,
                table.chainCount(),
                table.distinctEndpointCount(),
                offlineNs,
                onlineNs,
                exact,
                recovered,
                lookup.endpointMatches(),
                lookup.candidateChainsChecked(),
                0,
                0);
    }

    private static Result runDistinguishedPoints(
            Config config,
            int trial,
            long targetState,
            byte[] targetCiphertext,
            ReducedDesKeySpace keySpace,
            DesOracle oracle,
            LegacyReduction reduction,
            DistinguishedPointPredicate predicate,
            long[] starts) {
        long offlineStart = System.nanoTime();
        DistinguishedPointTable table =
                DistinguishedPointTable.build(
                        keySpace,
                        oracle,
                        reduction,
                        predicate,
                        starts,
                        config.dpMaxChainLength());
        long offlineNs = System.nanoTime() - offlineStart;

        long onlineStart = System.nanoTime();
        DistinguishedPointTable.LookupResult lookup = table.lookup(targetCiphertext);
        long onlineNs = System.nanoTime() - onlineStart;

        long recovered = lookup.state().orElse(-1L);
        boolean exact = lookup.found() && recovered == targetState;

        return new Result(
                trial,
                "distinguished_points",
                config.stateBits(),
                targetState,
                config.dpChains(),
                config.dpMaxChainLength(),
                config.dpDifficultyBits(),
                table.storedChains(),
                table.distinctEndpointCount(),
                offlineNs,
                onlineNs,
                exact,
                recovered,
                lookup.endpointCandidates(),
                lookup.candidateChainsChecked(),
                table.truncatedChains(),
                lookup.projectionSteps());
    }

    static long[] uniqueRandomStates(
            SplittableRandom random, long stateSpaceSize, int count) {
        if (count < 0 || count > stateSpaceSize) {
            throw new IllegalArgumentException(
                    "count must be between 0 and the state-space size");
        }

        Set<Long> states = new HashSet<>();
        while (states.size() < count) {
            states.add(random.nextLong(stateSpaceSize));
        }

        return states.stream().mapToLong(Long::longValue).sorted().toArray();
    }

    public static void writeCsv(Path output, List<Result> results) throws IOException {
        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        StringBuilder csv = new StringBuilder();
        csv.append(Result.csvHeader()).append('\n');
        for (Result result : results) {
            csv.append(result.toCsv()).append('\n');
        }

        Files.writeString(output, csv.toString(), StandardCharsets.UTF_8);
    }

    public record Result(
            int trial,
            String method,
            int stateBits,
            long targetState,
            int configuredChains,
            int chainParameter,
            int dpDifficultyBits,
            int storedChains,
            int distinctEndpoints,
            long offlineNs,
            long onlineNs,
            boolean exactRecovery,
            long recoveredState,
            int endpointMatchesOrCandidates,
            int candidateChainsChecked,
            int truncatedChains,
            int projectionSteps) {

        public static String csvHeader() {
            return String.join(
                    ",",
                    "trial",
                    "method",
                    "state_bits",
                    "target_state",
                    "configured_chains",
                    "chain_parameter",
                    "dp_difficulty_bits",
                    "stored_chains",
                    "distinct_endpoints",
                    "offline_ns",
                    "online_ns",
                    "exact_recovery",
                    "recovered_state",
                    "endpoint_matches_or_candidates",
                    "candidate_chains_checked",
                    "truncated_chains",
                    "projection_steps");
        }

        public String toCsv() {
            return String.format(
                    Locale.ROOT,
                    "%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%d,%d,%d,%d,%d",
                    trial,
                    method,
                    stateBits,
                    targetState,
                    configuredChains,
                    chainParameter,
                    dpDifficultyBits,
                    storedChains,
                    distinctEndpoints,
                    offlineNs,
                    onlineNs,
                    Boolean.toString(exactRecovery),
                    recoveredState,
                    endpointMatchesOrCandidates,
                    candidateChainsChecked,
                    truncatedChains,
                    projectionSteps);
        }
    }

    public record Config(
            int stateBits,
            int trials,
            long seed,
            int hellmanChains,
            int hellmanChainLength,
            int dpChains,
            int dpDifficultyBits,
            int dpMaxChainLength,
            Path output) {

        public Config {
            if (stateBits < 1 || stateBits > ReducedDesKeySpace.MAX_STATE_BITS) {
                throw new IllegalArgumentException("invalid stateBits");
            }
            if (trials < 1) {
                throw new IllegalArgumentException("trials must be positive");
            }

            long stateSpaceSize = 1L << stateBits;
            if (hellmanChains < 1 || hellmanChains > stateSpaceSize) {
                throw new IllegalArgumentException("invalid hellmanChains");
            }
            if (hellmanChainLength < 1) {
                throw new IllegalArgumentException("hellmanChainLength must be positive");
            }
            if (dpChains < 1 || dpChains > stateSpaceSize) {
                throw new IllegalArgumentException("invalid dpChains");
            }
            if (dpDifficultyBits < 1 || dpDifficultyBits > stateBits) {
                throw new IllegalArgumentException("invalid dpDifficultyBits");
            }
            if (dpMaxChainLength < 1) {
                throw new IllegalArgumentException("dpMaxChainLength must be positive");
            }
            if (output == null) {
                throw new NullPointerException("output");
            }
        }

        public static Config parse(String[] args) {
            int stateBits = 12;
            int trials = 5;
            long seed = 20260828L;
            int hellmanChains = 256;
            int hellmanChainLength = 16;
            int dpChains = 256;
            int dpDifficultyBits = 4;
            int dpMaxChainLength = 64;
            Path output = Path.of("experiments/results/smoke.csv");

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                String value = requireValue(args, ++i, arg);
                switch (arg) {
                    case "--state-bits" -> stateBits = Integer.parseInt(value);
                    case "--trials" -> trials = Integer.parseInt(value);
                    case "--seed" -> seed = Long.parseLong(value);
                    case "--hellman-chains" -> hellmanChains = Integer.parseInt(value);
                    case "--hellman-chain-length" ->
                            hellmanChainLength = Integer.parseInt(value);
                    case "--dp-chains" -> dpChains = Integer.parseInt(value);
                    case "--dp-bits" -> dpDifficultyBits = Integer.parseInt(value);
                    case "--dp-max-chain" -> dpMaxChainLength = Integer.parseInt(value);
                    case "--output" -> output = Path.of(value);
                    default -> throw new IllegalArgumentException("unknown argument: " + arg);
                }
            }

            return new Config(
                    stateBits,
                    trials,
                    seed,
                    hellmanChains,
                    hellmanChainLength,
                    dpChains,
                    dpDifficultyBits,
                    dpMaxChainLength,
                    output);
        }

        private static String requireValue(String[] args, int index, String flag) {
            if (index >= args.length) {
                throw new IllegalArgumentException("missing value for " + flag);
            }
            return args[index];
        }
    }
}

use cryptanalytic_time_memory_tradeoffs::experiment::{
    run_experiment, write_run, ExperimentConfig,
};
use cryptanalytic_time_memory_tradeoffs::shared_plan::run_shared_plan;
use cryptanalytic_time_memory_tradeoffs::{
    distinguished_coverage_states, hellman_coverage_states, DesOracle, DistinguishedPointPredicate,
    DistinguishedPointTable, HellmanTable, LegacyReduction, ReducedDesKeySpace,
};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("smoke");

    match command {
        "smoke" => smoke(),
        "verified-small" => verified_small(),
        "experiment" => experiment(&args[1..]),
        "shared-plan" => shared_plan(&args[1..]),
        other => Err(format!(
            "unknown command: {other}; supported: smoke, verified-small, experiment, shared-plan"
        )
        .into()),
    }
}

fn smoke() -> Result<(), Box<dyn std::error::Error>> {
    let key_space = ReducedDesKeySpace::new(16)?;
    let oracle = DesOracle::standard(key_space);
    let reduction = LegacyReduction::new(key_space);
    let starts: Vec<u64> = (0..256).collect();

    let hellman = HellmanTable::build(key_space, oracle.clone(), reduction, &starts, 32)?;
    let hellman_coverage = hellman_coverage_states(key_space, &oracle, reduction, &starts, 32)?;

    let predicate = DistinguishedPointPredicate::new(4, key_space)?;
    let distinguished = DistinguishedPointTable::build(
        key_space,
        oracle.clone(),
        reduction,
        predicate,
        &starts,
        128,
    )?;
    let distinguished_coverage =
        distinguished_coverage_states(key_space, &oracle, reduction, predicate, &starts, 128)?;

    println!("state_bits={}", key_space.state_bits());
    println!("hellman_chains={}", hellman.chain_count());
    println!(
        "hellman_distinct_endpoints={}",
        hellman.distinct_endpoint_count()
    );
    println!("hellman_exact_coverage={hellman_coverage}");
    println!("dp_generated={}", distinguished.generated_chains());
    println!("dp_stored={}", distinguished.stored_chains());
    println!("dp_truncated={}", distinguished.truncated_chains());
    println!(
        "dp_distinct_endpoints={}",
        distinguished.distinct_endpoint_count()
    );
    println!("dp_exact_coverage={distinguished_coverage}");

    Ok(())
}

fn verified_small() -> Result<(), Box<dyn std::error::Error>> {
    // Warm up code paths separately from the measured run.
    let warmup = ExperimentConfig::smoke(
        PathBuf::from("/tmp/tmto-rust-warmup.csv"),
        PathBuf::from("/tmp/tmto-rust-warmup-coverage.csv"),
    );
    let _ = run_experiment(&warmup)?;

    let config = ExperimentConfig::verified_small();
    let run = run_experiment(&config)?;
    write_run(&config, &run)?;

    println!("WROTE {}", config.output.display());
    println!("WROTE {}", config.coverage_output.display());
    println!("ROWS {}", run.results.len());
    println!("COVERAGE_ROWS {}", run.coverage.len());
    Ok(())
}

fn experiment(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ExperimentConfig {
        state_bits: 12,
        trials: 5,
        seed: 20260828,
        hellman_chains: 256,
        hellman_chain_length: 16,
        dp_chains: 256,
        dp_difficulty_bits: 4,
        dp_max_chain_length: 64,
        output: PathBuf::from("experiments/results/rust-smoke.csv"),
        coverage_output: PathBuf::from("experiments/results/rust-smoke-coverage.csv"),
    };

    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        index += 1;

        match flag.as_str() {
            "--state-bits" => config.state_bits = value.parse()?,
            "--trials" => config.trials = value.parse()?,
            "--seed" => config.seed = value.parse()?,
            "--hellman-chains" => config.hellman_chains = value.parse()?,
            "--hellman-chain-length" => config.hellman_chain_length = value.parse()?,
            "--dp-chains" => config.dp_chains = value.parse()?,
            "--dp-bits" => config.dp_difficulty_bits = value.parse()?,
            "--dp-max-chain" => config.dp_max_chain_length = value.parse()?,
            "--output" => config.output = PathBuf::from(value),
            "--coverage-output" => config.coverage_output = PathBuf::from(value),
            _ => return Err(format!("unknown argument: {flag}").into()),
        }
    }

    let run = run_experiment(&config)?;
    write_run(&config, &run)?;
    println!("WROTE {}", config.output.display());
    println!("WROTE {}", config.coverage_output.display());
    println!("ROWS {}", run.results.len());
    println!("COVERAGE_ROWS {}", run.coverage.len());
    Ok(())
}

fn shared_plan(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 2 {
        return Err("usage: tmto shared-plan <plan-directory> <output.csv>".into());
    }
    run_shared_plan(
        std::path::Path::new(&args[0]),
        std::path::Path::new(&args[1]),
    )
}

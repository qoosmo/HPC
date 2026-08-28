use cryptanalytic_time_memory_tradeoffs::{
    distinguished_coverage_states, hellman_coverage_states, DesOracle, DistinguishedPointPredicate,
    DistinguishedPointTable, HellmanTable, LegacyReduction, ReducedDesKeySpace,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "smoke".to_string());

    match command.as_str() {
        "smoke" => smoke(),
        other => Err(format!("unknown command: {other}; supported: smoke").into()),
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

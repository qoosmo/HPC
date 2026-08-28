use crate::{
    distinguished_coverage_states, hellman_coverage_states, DesOracle, DistinguishedPointPredicate,
    DistinguishedPointTable, HellmanTable, LegacyReduction, ReducedDesKeySpace,
};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;

#[derive(Debug)]
struct Plan {
    state_bits: u8,
    state_space_size: u64,
    trials: usize,
    hellman_chain_length: usize,
    dp_difficulty_bits: u8,
    dp_max_chain_length: usize,
    targets: Vec<u64>,
    hellman_starts: Vec<Vec<u64>>,
    dp_starts: Vec<Vec<u64>>,
}

pub fn run_shared_plan(plan_dir: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    let plan = Plan::load(plan_dir)?;
    let key_space = ReducedDesKeySpace::new(plan.state_bits)?;
    if key_space.size() != plan.state_space_size {
        return Err("metadata state-space size mismatch".into());
    }

    let oracle = DesOracle::standard(key_space);
    let reduction = LegacyReduction::new(key_space);
    let predicate = DistinguishedPointPredicate::new(plan.dp_difficulty_bits, key_space)?;

    let mut csv = String::new();
    csv.push_str("trial,target_state,target_ciphertext_hex,hellman_coverage,hellman_distinct_endpoints,hellman_recovered_state,hellman_exact_recovery,hellman_endpoint_matches,hellman_candidate_chains_checked,dp_coverage,dp_generated_chains,dp_stored_chains,dp_truncated_chains,dp_distinct_endpoints,dp_recovered_state,dp_exact_recovery,dp_endpoint_candidates,dp_candidate_chains_checked,dp_projection_steps\n");

    for trial in 0..plan.trials {
        let target_state = plan.targets[trial];
        let target_ciphertext = oracle.encrypt_state(target_state)?;

        let hellman = HellmanTable::build(
            key_space,
            oracle.clone(),
            reduction,
            &plan.hellman_starts[trial],
            plan.hellman_chain_length,
        )?;
        let hellman_lookup = hellman.lookup(&target_ciphertext)?;
        let hellman_coverage = hellman_coverage_states(
            key_space,
            &oracle,
            reduction,
            &plan.hellman_starts[trial],
            plan.hellman_chain_length,
        )?;

        let dp = DistinguishedPointTable::build(
            key_space,
            oracle.clone(),
            reduction,
            predicate,
            &plan.dp_starts[trial],
            plan.dp_max_chain_length,
        )?;
        let dp_lookup = dp.lookup(&target_ciphertext)?;
        let dp_coverage = distinguished_coverage_states(
            key_space,
            &oracle,
            reduction,
            predicate,
            &plan.dp_starts[trial],
            plan.dp_max_chain_length,
        )?;

        let hellman_recovered = hellman_lookup
            .state
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-1".to_string());
        let dp_recovered = dp_lookup
            .state
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-1".to_string());

        csv.push_str(&format!(
            "{trial},{target_state},{target_hex},{hellman_coverage},{hellman_endpoints},{hellman_recovered},{hellman_exact},{hellman_matches},{hellman_checked},{dp_coverage},{dp_generated},{dp_stored},{dp_truncated},{dp_endpoints},{dp_recovered},{dp_exact},{dp_candidates},{dp_checked},{dp_steps}\n",
            target_hex = hex(&target_ciphertext),
            hellman_endpoints = hellman.distinct_endpoint_count(),
            hellman_exact = hellman_lookup.state == Some(target_state),
            hellman_matches = hellman_lookup.endpoint_matches,
            hellman_checked = hellman_lookup.candidate_chains_checked,
            dp_generated = dp.generated_chains(),
            dp_stored = dp.stored_chains(),
            dp_truncated = dp.truncated_chains(),
            dp_endpoints = dp.distinct_endpoint_count(),
            dp_exact = dp_lookup.state == Some(target_state),
            dp_candidates = dp_lookup.endpoint_candidates,
            dp_checked = dp_lookup.candidate_chains_checked,
            dp_steps = dp_lookup.projection_steps,
        ));
    }

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output, csv)?;
    println!("SHARED_PLAN_ROWS={}", plan.trials);
    println!("WROTE {}", output.display());
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

impl Plan {
    fn load(directory: &Path) -> Result<Self, Box<dyn Error>> {
        let metadata = read_metadata(&directory.join("metadata.csv"))?;
        let state_bits = u8::try_from(value(&metadata, "state_bits")?)?;
        let state_space_size = value(&metadata, "state_space_size")?;
        let trials = usize::try_from(value(&metadata, "trials")?)?;
        let hellman_chains = usize::try_from(value(&metadata, "hellman_chains")?)?;
        let hellman_chain_length = usize::try_from(value(&metadata, "hellman_chain_length")?)?;
        let dp_chains = usize::try_from(value(&metadata, "dp_chains")?)?;
        let dp_difficulty_bits = u8::try_from(value(&metadata, "dp_difficulty_bits")?)?;
        let dp_max_chain_length = usize::try_from(value(&metadata, "dp_max_chain_length")?)?;

        Ok(Self {
            state_bits,
            state_space_size,
            trials,
            hellman_chain_length,
            dp_difficulty_bits,
            dp_max_chain_length,
            targets: read_targets(&directory.join("targets.csv"), trials)?,
            hellman_starts: read_starts(
                &directory.join("hellman-starts.csv"),
                trials,
                hellman_chains,
            )?,
            dp_starts: read_starts(&directory.join("dp-starts.csv"), trials, dp_chains)?,
        })
    }
}

fn read_metadata(path: &Path) -> Result<HashMap<String, u64>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let mut lines = text.lines();
    if lines.next() != Some("key,value") {
        return Err("invalid metadata header".into());
    }
    let mut result = HashMap::new();
    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 2 {
            return Err(format!("invalid metadata row: {line}").into());
        }
        result.insert(fields[0].to_string(), fields[1].parse()?);
    }
    Ok(result)
}

fn value(values: &HashMap<String, u64>, key: &str) -> Result<u64, Box<dyn Error>> {
    values
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing metadata key: {key}").into())
}

fn read_targets(path: &Path, trials: usize) -> Result<Vec<u64>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let mut lines = text.lines();
    if lines.next() != Some("trial,target_state") {
        return Err("invalid target header".into());
    }

    let mut result = Vec::with_capacity(trials);
    for (expected_trial, line) in lines.enumerate() {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 2 {
            return Err(format!("invalid target row: {line}").into());
        }
        let trial: usize = fields[0].parse()?;
        if trial != expected_trial {
            return Err("targets must be ordered by trial".into());
        }
        result.push(fields[1].parse()?);
    }

    if result.len() != trials {
        return Err("target row count mismatch".into());
    }
    Ok(result)
}

fn read_starts(path: &Path, trials: usize, count: usize) -> Result<Vec<Vec<u64>>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let mut lines = text.lines();
    if lines.next() != Some("trial,index,start_state") {
        return Err(format!("invalid starts header: {}", path.display()).into());
    }

    let mut result = vec![Vec::with_capacity(count); trials];

    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 3 {
            return Err(format!("invalid start row: {line}").into());
        }

        let trial: usize = fields[0].parse()?;
        let index: usize = fields[1].parse()?;
        let state: u64 = fields[2].parse()?;

        if trial >= trials || index != result[trial].len() || index >= count {
            return Err(format!("non-contiguous start index in {}", path.display()).into());
        }

        result[trial].push(state);
    }

    if result.iter().any(|row| row.len() != count) {
        return Err(format!("incomplete starts in {}", path.display()).into());
    }

    Ok(result)
}

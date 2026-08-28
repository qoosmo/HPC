use crate::{
    distinguished_coverage_states, exhaustive_find, hellman_coverage_states, DesOracle,
    DistinguishedPointPredicate, DistinguishedPointTable, HellmanTable, LegacyReduction,
    ReducedDesKeySpace, TmtoError,
};
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
pub enum ExperimentError {
    Core(TmtoError),
    Io(std::io::Error),
    InvalidConfig(String),
}

impl Display for ExperimentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => Display::fmt(error, f),
            Self::Io(error) => Display::fmt(error, f),
            Self::InvalidConfig(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ExperimentError {}

impl From<TmtoError> for ExperimentError {
    fn from(value: TmtoError) -> Self {
        Self::Core(value)
    }
}

impl From<std::io::Error> for ExperimentError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone)]
pub struct ExperimentConfig {
    pub state_bits: u8,
    pub trials: usize,
    pub seed: u64,
    pub hellman_chains: usize,
    pub hellman_chain_length: usize,
    pub dp_chains: usize,
    pub dp_difficulty_bits: u8,
    pub dp_max_chain_length: usize,
    pub output: PathBuf,
    pub coverage_output: PathBuf,
}

impl ExperimentConfig {
    pub fn smoke(output: impl Into<PathBuf>, coverage_output: impl Into<PathBuf>) -> Self {
        Self {
            state_bits: 10,
            trials: 2,
            seed: 7,
            hellman_chains: 64,
            hellman_chain_length: 8,
            dp_chains: 64,
            dp_difficulty_bits: 3,
            dp_max_chain_length: 32,
            output: output.into(),
            coverage_output: coverage_output.into(),
        }
    }

    pub fn verified_small() -> Self {
        Self {
            state_bits: 16,
            trials: 30,
            seed: 20260828,
            hellman_chains: 1024,
            hellman_chain_length: 64,
            dp_chains: 1024,
            dp_difficulty_bits: 6,
            dp_max_chain_length: 256,
            output: PathBuf::from("experiments/results/rust-verified-small.csv"),
            coverage_output: PathBuf::from("experiments/results/rust-verified-small-coverage.csv"),
        }
    }

    fn validate(&self) -> Result<ReducedDesKeySpace, ExperimentError> {
        let key_space = ReducedDesKeySpace::new(self.state_bits)?;
        if self.trials == 0 {
            return Err(ExperimentError::InvalidConfig(
                "trials must be positive".to_string(),
            ));
        }
        if self.hellman_chains == 0 || self.hellman_chains as u64 > key_space.size() {
            return Err(ExperimentError::InvalidConfig(
                "hellman_chains must be in [1, state-space size]".to_string(),
            ));
        }
        if self.hellman_chain_length == 0 {
            return Err(ExperimentError::InvalidConfig(
                "hellman_chain_length must be positive".to_string(),
            ));
        }
        if self.dp_chains == 0 || self.dp_chains as u64 > key_space.size() {
            return Err(ExperimentError::InvalidConfig(
                "dp_chains must be in [1, state-space size]".to_string(),
            ));
        }
        DistinguishedPointPredicate::new(self.dp_difficulty_bits, key_space)?;
        if self.dp_max_chain_length == 0 {
            return Err(ExperimentError::InvalidConfig(
                "dp_max_chain_length must be positive".to_string(),
            ));
        }
        Ok(key_space)
    }
}

#[derive(Debug, Clone)]
pub struct ExperimentResult {
    pub trial: usize,
    pub method: &'static str,
    pub state_bits: u8,
    pub target_state: u64,
    pub configured_chains: usize,
    pub chain_parameter: usize,
    pub dp_difficulty_bits: u8,
    pub stored_chains: usize,
    pub distinct_endpoints: usize,
    pub offline_ns: u64,
    pub online_ns: u64,
    pub exact_recovery: bool,
    pub recovered_state: Option<u64>,
    pub endpoint_matches_or_candidates: usize,
    pub candidate_chains_checked: usize,
    pub truncated_chains: usize,
    pub projection_steps: usize,
}

impl ExperimentResult {
    pub const fn csv_header() -> &'static str {
        "trial,method,state_bits,target_state,configured_chains,chain_parameter,dp_difficulty_bits,stored_chains,distinct_endpoints,offline_ns,online_ns,exact_recovery,recovered_state,endpoint_matches_or_candidates,candidate_chains_checked,truncated_chains,projection_steps"
    }

    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.trial,
            self.method,
            self.state_bits,
            self.target_state,
            self.configured_chains,
            self.chain_parameter,
            self.dp_difficulty_bits,
            self.stored_chains,
            self.distinct_endpoints,
            self.offline_ns,
            self.online_ns,
            self.exact_recovery,
            self.recovered_state
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-1".to_string()),
            self.endpoint_matches_or_candidates,
            self.candidate_chains_checked,
            self.truncated_chains,
            self.projection_steps,
        )
    }
}

#[derive(Debug, Clone)]
pub struct CoverageResult {
    pub trial: usize,
    pub method: &'static str,
    pub covered_states: usize,
    pub state_space_size: u64,
}

impl CoverageResult {
    pub const fn csv_header() -> &'static str {
        "trial,method,covered_states,state_space_size,coverage_fraction"
    }

    fn to_csv(&self) -> String {
        let fraction = self.covered_states as f64 / self.state_space_size as f64;
        format!(
            "{},{},{},{},{:.12}",
            self.trial, self.method, self.covered_states, self.state_space_size, fraction
        )
    }
}

#[derive(Debug, Clone)]
pub struct ExperimentRun {
    pub results: Vec<ExperimentResult>,
    pub coverage: Vec<CoverageResult>,
}

#[derive(Debug, Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const GAMMA: u64 = 0x9e3779b97f4a7c15;

    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(Self::GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn next_state(&mut self, key_space: ReducedDesKeySpace) -> u64 {
        self.next_u64() & key_space.mask()
    }
}

pub fn run_experiment(config: &ExperimentConfig) -> Result<ExperimentRun, ExperimentError> {
    let key_space = config.validate()?;
    let oracle = DesOracle::standard(key_space);
    let reduction = LegacyReduction::new(key_space);
    let predicate = DistinguishedPointPredicate::new(config.dp_difficulty_bits, key_space)?;
    let mut rng = SplitMix64::new(config.seed);

    let mut results = Vec::with_capacity(config.trials * 3);
    let mut coverage = Vec::with_capacity(config.trials * 3);

    for trial in 0..config.trials {
        let target_state = rng.next_state(key_space);
        let target_ciphertext = oracle.encrypt_state(target_state)?;

        let online_start = Instant::now();
        let exhaustive = exhaustive_find(key_space, &oracle, &target_ciphertext)?;
        let exhaustive_online_ns = elapsed_ns(online_start);

        results.push(ExperimentResult {
            trial,
            method: "exhaustive",
            state_bits: config.state_bits,
            target_state,
            configured_chains: 0,
            chain_parameter: 0,
            dp_difficulty_bits: 0,
            stored_chains: 0,
            distinct_endpoints: 0,
            offline_ns: 0,
            online_ns: exhaustive_online_ns,
            exact_recovery: exhaustive == Some(target_state),
            recovered_state: exhaustive,
            endpoint_matches_or_candidates: 0,
            candidate_chains_checked: 0,
            truncated_chains: 0,
            projection_steps: 0,
        });
        coverage.push(CoverageResult {
            trial,
            method: "exhaustive",
            covered_states: key_space.size() as usize,
            state_space_size: key_space.size(),
        });

        let hellman_starts = unique_random_states(&mut rng, key_space, config.hellman_chains)?;

        let offline_start = Instant::now();
        let hellman = HellmanTable::build(
            key_space,
            oracle.clone(),
            reduction,
            &hellman_starts,
            config.hellman_chain_length,
        )?;
        let hellman_offline_ns = elapsed_ns(offline_start);

        let online_start = Instant::now();
        let hellman_lookup = hellman.lookup(&target_ciphertext)?;
        let hellman_online_ns = elapsed_ns(online_start);

        results.push(ExperimentResult {
            trial,
            method: "hellman",
            state_bits: config.state_bits,
            target_state,
            configured_chains: config.hellman_chains,
            chain_parameter: config.hellman_chain_length,
            dp_difficulty_bits: 0,
            stored_chains: hellman.chain_count(),
            distinct_endpoints: hellman.distinct_endpoint_count(),
            offline_ns: hellman_offline_ns,
            online_ns: hellman_online_ns,
            exact_recovery: hellman_lookup.state == Some(target_state),
            recovered_state: hellman_lookup.state,
            endpoint_matches_or_candidates: hellman_lookup.endpoint_matches,
            candidate_chains_checked: hellman_lookup.candidate_chains_checked,
            truncated_chains: 0,
            projection_steps: 0,
        });

        let hellman_covered = hellman_coverage_states(
            key_space,
            &oracle,
            reduction,
            &hellman_starts,
            config.hellman_chain_length,
        )?;
        coverage.push(CoverageResult {
            trial,
            method: "hellman",
            covered_states: hellman_covered,
            state_space_size: key_space.size(),
        });

        let dp_starts = unique_random_states(&mut rng, key_space, config.dp_chains)?;

        let offline_start = Instant::now();
        let dp_table = DistinguishedPointTable::build(
            key_space,
            oracle.clone(),
            reduction,
            predicate,
            &dp_starts,
            config.dp_max_chain_length,
        )?;
        let dp_offline_ns = elapsed_ns(offline_start);

        let online_start = Instant::now();
        let dp_lookup = dp_table.lookup(&target_ciphertext)?;
        let dp_online_ns = elapsed_ns(online_start);

        results.push(ExperimentResult {
            trial,
            method: "distinguished_points",
            state_bits: config.state_bits,
            target_state,
            configured_chains: config.dp_chains,
            chain_parameter: config.dp_max_chain_length,
            dp_difficulty_bits: config.dp_difficulty_bits,
            stored_chains: dp_table.stored_chains(),
            distinct_endpoints: dp_table.distinct_endpoint_count(),
            offline_ns: dp_offline_ns,
            online_ns: dp_online_ns,
            exact_recovery: dp_lookup.state == Some(target_state),
            recovered_state: dp_lookup.state,
            endpoint_matches_or_candidates: dp_lookup.endpoint_candidates,
            candidate_chains_checked: dp_lookup.candidate_chains_checked,
            truncated_chains: dp_table.truncated_chains(),
            projection_steps: dp_lookup.projection_steps,
        });

        let dp_covered = distinguished_coverage_states(
            key_space,
            &oracle,
            reduction,
            predicate,
            &dp_starts,
            config.dp_max_chain_length,
        )?;
        coverage.push(CoverageResult {
            trial,
            method: "distinguished_points",
            covered_states: dp_covered,
            state_space_size: key_space.size(),
        });
    }

    Ok(ExperimentRun { results, coverage })
}

pub fn write_run(config: &ExperimentConfig, run: &ExperimentRun) -> Result<(), ExperimentError> {
    write_results(&config.output, &run.results)?;
    write_coverage(&config.coverage_output, &run.coverage)?;
    Ok(())
}

fn write_results(path: &Path, rows: &[ExperimentResult]) -> Result<(), ExperimentError> {
    ensure_parent(path)?;
    let mut csv = String::new();
    csv.push_str(ExperimentResult::csv_header());
    csv.push('\n');
    for row in rows {
        csv.push_str(&row.to_csv());
        csv.push('\n');
    }
    fs::write(path, csv)?;
    Ok(())
}

fn write_coverage(path: &Path, rows: &[CoverageResult]) -> Result<(), ExperimentError> {
    ensure_parent(path)?;
    let mut csv = String::new();
    csv.push_str(CoverageResult::csv_header());
    csv.push('\n');
    for row in rows {
        csv.push_str(&row.to_csv());
        csv.push('\n');
    }
    fs::write(path, csv)?;
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<(), ExperimentError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn unique_random_states(
    rng: &mut SplitMix64,
    key_space: ReducedDesKeySpace,
    count: usize,
) -> Result<Vec<u64>, ExperimentError> {
    if count as u64 > key_space.size() {
        return Err(ExperimentError::InvalidConfig(
            "requested more unique starts than states".to_string(),
        ));
    }

    let mut states = HashSet::with_capacity(count.saturating_mul(2));
    while states.len() < count {
        states.insert(rng.next_state(key_space));
    }

    let mut states: Vec<u64> = states.into_iter().collect();
    states.sort_unstable();
    Ok(states)
}

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_experiment_repeats_algorithmic_outputs() {
        let config_a = ExperimentConfig::smoke(
            PathBuf::from("/tmp/tmto-rust-test-a.csv"),
            PathBuf::from("/tmp/tmto-rust-test-a-coverage.csv"),
        );
        let config_b = config_a.clone();

        let run_a = run_experiment(&config_a).expect("first run");
        let run_b = run_experiment(&config_b).expect("second run");

        assert_eq!(run_a.results.len(), run_b.results.len());
        assert_eq!(run_a.coverage.len(), run_b.coverage.len());

        for (left, right) in run_a.results.iter().zip(&run_b.results) {
            assert_eq!(left.trial, right.trial);
            assert_eq!(left.method, right.method);
            assert_eq!(left.target_state, right.target_state);
            assert_eq!(left.configured_chains, right.configured_chains);
            assert_eq!(left.chain_parameter, right.chain_parameter);
            assert_eq!(left.dp_difficulty_bits, right.dp_difficulty_bits);
            assert_eq!(left.stored_chains, right.stored_chains);
            assert_eq!(left.distinct_endpoints, right.distinct_endpoints);
            assert_eq!(left.exact_recovery, right.exact_recovery);
            assert_eq!(left.recovered_state, right.recovered_state);
            assert_eq!(
                left.endpoint_matches_or_candidates,
                right.endpoint_matches_or_candidates
            );
            assert_eq!(
                left.candidate_chains_checked,
                right.candidate_chains_checked
            );
            assert_eq!(left.truncated_chains, right.truncated_chains);
            assert_eq!(left.projection_steps, right.projection_steps);
        }

        for (left, right) in run_a.coverage.iter().zip(&run_b.coverage) {
            assert_eq!(left.trial, right.trial);
            assert_eq!(left.method, right.method);
            assert_eq!(left.covered_states, right.covered_states);
            assert_eq!(left.state_space_size, right.state_space_size);
        }
    }
}

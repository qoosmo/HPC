use cryptanalytic_time_memory_tradeoffs::{step, DesOracle, LegacyReduction, ReducedDesKeySpace};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;

const B: u8 = 16;
const N: usize = 1 << B;
const M: usize = 1024;
const BASE_SEED: u64 = 20_260_828;

#[derive(Clone, Copy)]
struct Config {
    label: &'static str,
    d: u8,
    limit: usize,
}

const CONFIGS: &[Config] = &[
    Config {
        label: "dp-d4-l16",
        d: 4,
        limit: 16,
    },
    Config {
        label: "dp-d4-l32",
        d: 4,
        limit: 32,
    },
    Config {
        label: "dp-d4-l64",
        d: 4,
        limit: 64,
    },
    Config {
        label: "dp-d6-l64",
        d: 6,
        limit: 64,
    },
    Config {
        label: "dp-d6-l128",
        d: 6,
        limit: 128,
    },
    Config {
        label: "dp-d6-l256",
        d: 6,
        limit: 256,
    },
    Config {
        label: "dp-d8-l256",
        d: 8,
        limit: 256,
    },
    Config {
        label: "dp-d8-l512",
        d: 8,
        limit: 512,
    },
    Config {
        label: "dp-d8-l1024",
        d: 8,
        limit: 1024,
    },
];

#[derive(Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(Self::GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

struct DpStats {
    covered_states: usize,
    stored: usize,
    truncated: usize,
    distinct_endpoints: usize,
    total_stored_transitions: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: paper_dp_sweep <output.csv> <trials>".into());
    }

    let output = Path::new(&args[0]);
    let trials: usize = args[1].parse()?;
    if trials == 0 {
        return Err("trials must be positive".into());
    }

    let key_space = ReducedDesKeySpace::new(B)?;
    let oracle = DesOracle::standard(key_space);
    let reduction = LegacyReduction::new(key_space);

    eprintln!("BUILD_DES_MAP b={B} N={N}");
    let mut des_map = Vec::with_capacity(N);
    for state in 0..N {
        des_map.push(u32::try_from(step(&oracle, reduction, state as u64)?)?);
    }

    let mut csv = String::from(
        "config,trial,map_type,b,N,m,d,limit,limit_over_mean,covered_states,coverage_fraction,stored_chains,truncated_chains,truncation_fraction,distinct_endpoints,mean_stored_transitions,theory_truncation_fraction\n",
    );

    for trial in 0..trials {
        let mut random_rng = SplitMix64::new(derive_seed(0x4450_524e, trial));
        let random_map: Vec<u32> = (0..N)
            .map(|_| (random_rng.next_u64() & ((N as u64) - 1)) as u32)
            .collect();

        let mut starts_rng = SplitMix64::new(derive_seed(0x4450_5354, trial));
        let starts = unique_sorted_states(&mut starts_rng, M);

        for &config in CONFIGS {
            append_stats(
                &mut csv,
                config,
                trial,
                "des",
                evaluate(&des_map, &starts, config),
            );
            append_stats(
                &mut csv,
                config,
                trial,
                "random",
                evaluate(&random_map, &starts, config),
            );
        }
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, csv)?;

    println!("DP_CONFIGS={}", CONFIGS.len());
    println!("DP_TRIALS={trials}");
    println!("DP_ROWS={}", CONFIGS.len() * trials * 2);
    println!("WROTE {}", output.display());
    Ok(())
}

fn derive_seed(tag: u64, trial: usize) -> u64 {
    BASE_SEED ^ tag.rotate_left(19) ^ (trial as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn unique_sorted_states(rng: &mut SplitMix64, count: usize) -> Vec<usize> {
    let mut set = HashSet::with_capacity(count.saturating_mul(2));
    while set.len() < count {
        set.insert((rng.next_u64() & ((N as u64) - 1)) as usize);
    }
    let mut values: Vec<usize> = set.into_iter().collect();
    values.sort_unstable();
    values
}

fn evaluate(map: &[u32], starts: &[usize], config: Config) -> DpStats {
    let mask = (1_usize << config.d) - 1;
    let mut covered = vec![false; map.len()];
    let mut endpoints = HashSet::with_capacity(starts.len().saturating_mul(2));
    let mut stored = 0;
    let mut truncated = 0;
    let mut total_stored_transitions = 0;

    for &start in starts {
        let mut state = start;
        let mut path = Vec::with_capacity(config.limit.min(1024));
        let mut endpoint = None;

        for transitions in 1..=config.limit {
            path.push(state);
            let next = map[state] as usize;

            if next & mask == 0 {
                endpoint = Some((next, transitions));
                break;
            }

            state = next;
        }

        if let Some((end, transitions)) = endpoint {
            stored += 1;
            total_stored_transitions += transitions;
            endpoints.insert(end);
            for state in path {
                covered[state] = true;
            }
        } else {
            truncated += 1;
        }
    }

    DpStats {
        covered_states: covered.into_iter().filter(|value| *value).count(),
        stored,
        truncated,
        distinct_endpoints: endpoints.len(),
        total_stored_transitions,
    }
}

fn append_stats(csv: &mut String, config: Config, trial: usize, map_type: &str, stats: DpStats) {
    let mean = 1_usize << config.d;
    let limit_over_mean = config.limit as f64 / mean as f64;
    let coverage_fraction = stats.covered_states as f64 / N as f64;
    let truncation_fraction = stats.truncated as f64 / M as f64;
    let mean_stored_transitions = if stats.stored == 0 {
        0.0
    } else {
        stats.total_stored_transitions as f64 / stats.stored as f64
    };
    let p = 2_f64.powi(-(config.d as i32));
    let theory_truncation = (1.0 - p).powi(config.limit as i32);

    csv.push_str(&format!(
        "{},{},{},{},{},{},{},{},{:.3},{},{:.12},{},{},{:.12},{},{:.6},{:.12}\n",
        config.label,
        trial,
        map_type,
        B,
        N,
        M,
        config.d,
        config.limit,
        limit_over_mean,
        stats.covered_states,
        coverage_fraction,
        stats.stored,
        stats.truncated,
        truncation_fraction,
        stats.distinct_endpoints,
        mean_stored_transitions,
        theory_truncation,
    ));
}

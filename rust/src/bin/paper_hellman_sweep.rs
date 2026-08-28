use cryptanalytic_time_memory_tradeoffs::{step, DesOracle, LegacyReduction, ReducedDesKeySpace};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;

const BASE_SEED: u64 = 20_260_828;

#[derive(Clone, Copy)]
struct Config {
    label: &'static str,
    b: u8,
    m: usize,
    t: usize,
}

const CONFIGS: &[Config] = &[
    Config {
        label: "stop-b12-a",
        b: 12,
        m: 64,
        t: 8,
    },
    Config {
        label: "stop-b12-b",
        b: 12,
        m: 16,
        t: 16,
    },
    Config {
        label: "stop-b14-a",
        b: 14,
        m: 64,
        t: 16,
    },
    Config {
        label: "stop-b14-b",
        b: 14,
        m: 16,
        t: 32,
    },
    Config {
        label: "stop-b16-a",
        b: 16,
        m: 256,
        t: 16,
    },
    Config {
        label: "stop-b16-b",
        b: 16,
        m: 64,
        t: 32,
    },
    Config {
        label: "stop-b16-c",
        b: 16,
        m: 16,
        t: 64,
    },
    Config {
        label: "stop-b18-a",
        b: 18,
        m: 256,
        t: 32,
    },
    Config {
        label: "stop-b18-b",
        b: 18,
        m: 64,
        t: 64,
    },
    Config {
        label: "stop-b18-c",
        b: 18,
        m: 16,
        t: 128,
    },
    Config {
        label: "budget-b16-t16",
        b: 16,
        m: 4096,
        t: 16,
    },
    Config {
        label: "budget-b16-t32",
        b: 16,
        m: 2048,
        t: 32,
    },
    Config {
        label: "stress-b16-current",
        b: 16,
        m: 1024,
        t: 64,
    },
    Config {
        label: "budget-b16-t128",
        b: 16,
        m: 512,
        t: 128,
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

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: paper_hellman_sweep <output.csv> <trials>".into());
    }
    let output = Path::new(&args[0]);
    let trials: usize = args[1].parse()?;
    if trials == 0 {
        return Err("trials must be positive".into());
    }

    let mut csv = String::from(
        "config,b,N,trial,map_type,m,t,mt_over_N,mt2_over_N,nominal_positions,covered_states,coverage_fraction,duplicate_positions,distinct_endpoints,ma_hong_fraction,iid_fraction,residual_vs_ma_hong\n",
    );

    for &b in &[12_u8, 14, 16, 18] {
        let key_space = ReducedDesKeySpace::new(b)?;
        let n = key_space.size() as usize;
        let oracle = DesOracle::standard(key_space);
        let reduction = LegacyReduction::new(key_space);

        eprintln!("BUILD_DES_MAP b={b} N={n}");
        let mut des_map = Vec::with_capacity(n);
        for state in 0..n {
            des_map.push(u32::try_from(step(&oracle, reduction, state as u64)?)?);
        }

        let configs_for_b: Vec<(usize, Config)> = CONFIGS
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, config)| config.b == b)
            .collect();

        for trial in 0..trials {
            let mut random_rng = SplitMix64::new(derive_seed(0x5241_4e44, b, trial, 0));
            let random_map: Vec<u32> = (0..n)
                .map(|_| (random_rng.next_u64() & ((n as u64) - 1)) as u32)
                .collect();

            for (config_index, config) in &configs_for_b {
                let mut starts_rng =
                    SplitMix64::new(derive_seed(0x5354_4152, b, trial, *config_index as u64));
                let starts = unique_sorted_states(&mut starts_rng, n, config.m);

                let (des_covered, des_endpoints) = exact_coverage(&des_map, &starts, config.t);
                let (random_covered, random_endpoints) =
                    exact_coverage(&random_map, &starts, config.t);

                append_row(&mut csv, *config, trial, "des", des_covered, des_endpoints);
                append_row(
                    &mut csv,
                    *config,
                    trial,
                    "random",
                    random_covered,
                    random_endpoints,
                );
            }
        }
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, csv)?;

    println!("SWEEP_CONFIGS={}", CONFIGS.len());
    println!("SWEEP_TRIALS={trials}");
    println!("SWEEP_ROWS={}", CONFIGS.len() * trials * 2);
    println!("WROTE {}", output.display());
    Ok(())
}

fn derive_seed(tag: u64, b: u8, trial: usize, config_index: u64) -> u64 {
    BASE_SEED
        ^ tag.rotate_left(17)
        ^ (u64::from(b) << 48)
        ^ (trial as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ config_index.wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

fn unique_sorted_states(rng: &mut SplitMix64, n: usize, count: usize) -> Vec<usize> {
    assert!(count <= n);
    let mask = (n as u64) - 1;
    let mut set = HashSet::with_capacity(count.saturating_mul(2));
    while set.len() < count {
        set.insert((rng.next_u64() & mask) as usize);
    }
    let mut values: Vec<usize> = set.into_iter().collect();
    values.sort_unstable();
    values
}

fn exact_coverage(map: &[u32], starts: &[usize], t: usize) -> (usize, usize) {
    let mut covered = vec![false; map.len()];
    let mut endpoints = HashSet::with_capacity(starts.len().saturating_mul(2));

    for &start in starts {
        let mut state = start;
        for _ in 0..t {
            covered[state] = true;
            state = map[state] as usize;
        }
        endpoints.insert(state);
    }

    let covered_states = covered.into_iter().filter(|value| *value).count();
    (covered_states, endpoints.len())
}

fn ma_hong_fraction(n: usize, m: usize, t: usize) -> f64 {
    let m_over_n = m as f64 / n as f64;
    let mut s = 0.0_f64;
    for _ in 0..t {
        s = 1.0 - (-m_over_n - s).exp();
    }
    s
}

fn append_row(
    csv: &mut String,
    config: Config,
    trial: usize,
    map_type: &str,
    covered_states: usize,
    distinct_endpoints: usize,
) {
    let n = 1_usize << config.b;
    let nominal = config.m * config.t;
    let coverage_fraction = covered_states as f64 / n as f64;
    let ma_hong = ma_hong_fraction(n, config.m, config.t);
    let iid = 1.0 - (-(nominal as f64 / n as f64)).exp();
    let residual = coverage_fraction - ma_hong;
    let duplicate_positions = nominal - covered_states;

    csv.push_str(&format!(
        "{},{},{},{},{},{},{},{:.12},{:.12},{},{},{:.12},{},{},{:.12},{:.12},{:.12}\n",
        config.label,
        config.b,
        n,
        trial,
        map_type,
        config.m,
        config.t,
        nominal as f64 / n as f64,
        (config.m * config.t * config.t) as f64 / n as f64,
        nominal,
        covered_states,
        coverage_fraction,
        duplicate_positions,
        distinct_endpoints,
        ma_hong,
        iid,
        residual,
    ));
}

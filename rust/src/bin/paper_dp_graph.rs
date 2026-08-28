use cryptanalytic_time_memory_tradeoffs::{step, DesOracle, LegacyReduction, ReducedDesKeySpace};
use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::Path;

const B: u8 = 16;
const N: usize = 1 << B;
const BASE_SEED: u64 = 20_260_828;
const INF: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Config {
    d: u8,
    limit: usize,
}

const CONFIGS: &[Config] = &[
    Config { d: 4, limit: 16 },
    Config { d: 4, limit: 32 },
    Config { d: 4, limit: 64 },
    Config { d: 6, limit: 64 },
    Config { d: 6, limit: 128 },
    Config { d: 6, limit: 256 },
    Config { d: 8, limit: 256 },
    Config { d: 8, limit: 512 },
    Config { d: 8, limit: 1024 },
];

struct Reachability {
    eventual_truncation_floor: f64,
    exact_truncation_fraction: f64,
    max_finite_hitting_transitions: usize,
    reachable_start_fraction: f64,
}

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
        return Err("usage: paper_dp_graph <output.csv> <random-map-trials>".into());
    }
    let output = Path::new(&args[0]);
    let random_trials: usize = args[1].parse()?;
    if random_trials == 0 {
        return Err("random-map-trials must be positive".into());
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
        "map_type,trial,d,limit,exact_truncation_fraction,eventual_truncation_floor,reachable_start_fraction,max_finite_hitting_transitions\n",
    );

    for &config in CONFIGS {
        let stats = analyze(&des_map, config.d, config.limit);
        append(&mut csv, "des", -1, config, &stats);
    }

    for trial in 0..random_trials {
        let mut rng = SplitMix64::new(derive_seed(0x4450_524e, trial));
        let random_map: Vec<u32> = (0..N)
            .map(|_| (rng.next_u64() & ((N as u64) - 1)) as u32)
            .collect();

        for &config in CONFIGS {
            let stats = analyze(&random_map, config.d, config.limit);
            append(&mut csv, "random", trial as isize, config, &stats);
        }
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, csv)?;

    println!("DP_GRAPH_CONFIGS={}", CONFIGS.len());
    println!("DP_GRAPH_RANDOM_TRIALS={random_trials}");
    println!("DP_GRAPH_ROWS={}", CONFIGS.len() * (random_trials + 1));
    println!("WROTE {}", output.display());
    Ok(())
}

fn derive_seed(tag: u64, trial: usize) -> u64 {
    BASE_SEED ^ tag.rotate_left(19) ^ (trial as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn analyze(map: &[u32], d: u8, limit: usize) -> Reachability {
    let mask = (1_usize << d) - 1;

    let mut reverse = vec![Vec::<u32>::new(); map.len()];
    for (source, &target) in map.iter().enumerate() {
        reverse[target as usize].push(source as u32);
    }

    let mut distance = vec![INF; map.len()];
    let mut queue = VecDeque::new();

    for (state, dist) in distance.iter_mut().enumerate() {
        if state & mask == 0 {
            *dist = 0;
            queue.push_back(state);
        }
    }

    while let Some(state) = queue.pop_front() {
        let next_distance = distance[state] + 1;
        for &predecessor in &reverse[state] {
            let predecessor = predecessor as usize;
            if distance[predecessor] == INF {
                distance[predecessor] = next_distance;
                queue.push_back(predecessor);
            }
        }
    }

    let mut eventual_fail = 0usize;
    let mut finite_limit_fail = 0usize;
    let mut max_finite_hitting_transitions = 0usize;

    for &next in map {
        let dist = distance[next as usize];
        if dist == INF {
            eventual_fail += 1;
            finite_limit_fail += 1;
        } else {
            let transitions = dist as usize + 1;
            max_finite_hitting_transitions = max_finite_hitting_transitions.max(transitions);
            if transitions > limit {
                finite_limit_fail += 1;
            }
        }
    }

    let eventual = eventual_fail as f64 / map.len() as f64;
    let finite = finite_limit_fail as f64 / map.len() as f64;

    Reachability {
        eventual_truncation_floor: eventual,
        exact_truncation_fraction: finite,
        max_finite_hitting_transitions,
        reachable_start_fraction: 1.0 - eventual,
    }
}

fn append(csv: &mut String, map_type: &str, trial: isize, config: Config, stats: &Reachability) {
    csv.push_str(&format!(
        "{map_type},{trial},{},{},{:.12},{:.12},{:.12},{}\n",
        config.d,
        config.limit,
        stats.exact_truncation_fraction,
        stats.eventual_truncation_floor,
        stats.reachable_start_fraction,
        stats.max_finite_hitting_transitions,
    ));
}

#!/usr/bin/env python3
from pathlib import Path

OUT = Path(__file__).resolve().parent

STATE_BITS = 16
N = 1 << STATE_BITS
TRIALS = 30
SEED = 20260828
HELLMAN_CHAINS = 1024
HELLMAN_CHAIN_LENGTH = 64
DP_CHAINS = 1024
DP_DIFFICULTY_BITS = 6
DP_MAX_CHAIN_LENGTH = 256

MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15

class SplitMix64:
    def __init__(self, seed: int):
        self.state = seed & MASK64

    def next_u64(self) -> int:
        self.state = (self.state + GAMMA) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return (z ^ (z >> 31)) & MASK64

    def next_state(self) -> int:
        return self.next_u64() & (N - 1)

def unique_sorted_states(rng: SplitMix64, count: int):
    values = set()
    while len(values) < count:
        values.add(rng.next_state())
    return sorted(values)

rng = SplitMix64(SEED)

targets = []
hellman = []
dp = []

for trial in range(TRIALS):
    targets.append((trial, rng.next_state()))
    for index, state in enumerate(unique_sorted_states(rng, HELLMAN_CHAINS)):
        hellman.append((trial, index, state))
    for index, state in enumerate(unique_sorted_states(rng, DP_CHAINS)):
        dp.append((trial, index, state))

metadata = [
    ("state_bits", STATE_BITS),
    ("state_space_size", N),
    ("trials", TRIALS),
    ("seed_provenance", SEED),
    ("hellman_chains", HELLMAN_CHAINS),
    ("hellman_chain_length", HELLMAN_CHAIN_LENGTH),
    ("dp_chains", DP_CHAINS),
    ("dp_difficulty_bits", DP_DIFFICULTY_BITS),
    ("dp_max_chain_length", DP_MAX_CHAIN_LENGTH),
]

def write_rows(path: Path, header: str, rows):
    with path.open("w", newline="\n") as f:
        f.write(header + "\n")
        for row in rows:
            f.write(",".join(str(x) for x in row) + "\n")

write_rows(OUT / "metadata.csv", "key,value", metadata)
write_rows(OUT / "targets.csv", "trial,target_state", targets)
write_rows(OUT / "hellman-starts.csv", "trial,index,start_state", hellman)
write_rows(OUT / "dp-starts.csv", "trial,index,start_state", dp)

assert targets[0][1] == 57417
assert targets[1][1] == 59109
assert targets[2][1] == 21223

print(f"PLAN_TRIALS={TRIALS}")
print(f"HELLMAN_START_ROWS={len(hellman)}")
print(f"DP_START_ROWS={len(dp)}")
print(f"TARGET_0={targets[0][1]}")

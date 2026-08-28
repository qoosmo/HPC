//! Rust reference implementation of the reduced-DES TMTO semantics.
//!
//! The crate mirrors the modern Java model before any performance-oriented
//! optimization. DES is obsolete and is used only as a reproducibility fixture.

use des::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use des::Des;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};

pub mod experiment;

pub const MAX_STATE_BITS: u8 = 28;
pub const DEFAULT_PLAINTEXT: &[u8] = b"HPC reproducibility fixture";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TmtoError {
    InvalidStateBits(u8),
    InvalidState(u64),
    InvalidKeyLength(usize),
    InvalidCiphertextLength(usize),
    EmptyPlaintext,
    InvalidChainLength,
    InvalidDifficulty { difficulty_bits: u8, state_bits: u8 },
    DuplicateStart(u64),
}

impl Display for TmtoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStateBits(bits) => {
                write!(f, "state_bits must be in [1, {MAX_STATE_BITS}], got {bits}")
            }
            Self::InvalidState(state) => write!(f, "state outside reduced keyspace: {state}"),
            Self::InvalidKeyLength(len) => write!(
                f,
                "DES key encoding must contain exactly 8 bytes, got {len}"
            ),
            Self::InvalidCiphertextLength(len) => {
                write!(f, "ciphertext must contain at least four bytes, got {len}")
            }
            Self::EmptyPlaintext => write!(f, "plaintext must not be empty"),
            Self::InvalidChainLength => write!(f, "chain length must be positive"),
            Self::InvalidDifficulty {
                difficulty_bits,
                state_bits,
            } => write!(
                f,
                "difficulty_bits must be in [1, {state_bits}], got {difficulty_bits}"
            ),
            Self::DuplicateStart(state) => write!(f, "duplicate start state: {state}"),
        }
    }
}

impl std::error::Error for TmtoError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReducedDesKeySpace {
    state_bits: u8,
    size: u64,
    mask: u64,
}

impl ReducedDesKeySpace {
    pub fn new(state_bits: u8) -> Result<Self, TmtoError> {
        if !(1..=MAX_STATE_BITS).contains(&state_bits) {
            return Err(TmtoError::InvalidStateBits(state_bits));
        }
        let size = 1_u64 << state_bits;
        Ok(Self {
            state_bits,
            size,
            mask: size - 1,
        })
    }

    pub fn state_bits(self) -> u8 {
        self.state_bits
    }

    pub fn size(self) -> u64 {
        self.size
    }

    pub fn mask(self) -> u64 {
        self.mask
    }

    pub fn to_key_bytes(self, state: u64) -> Result<[u8; 8], TmtoError> {
        self.validate_state(state)?;

        let mut key = [with_odd_parity(0x7f); 8];
        let mut remaining = state;

        for index in (4..8).rev() {
            let seven_bits = (remaining & 0x7f) as u8;
            key[index] = with_odd_parity(seven_bits);
            remaining >>= 7;
        }

        Ok(key)
    }

    pub fn to_state(self, key: &[u8]) -> Result<u64, TmtoError> {
        if key.len() != 8 {
            return Err(TmtoError::InvalidKeyLength(key.len()));
        }

        let mut state = 0_u64;
        for byte in &key[4..] {
            state = (state << 7) | u64::from(*byte >> 1);
        }

        if state & !self.mask != 0 {
            return Err(TmtoError::InvalidState(state));
        }
        Ok(state)
    }

    pub fn validate_state(self, state: u64) -> Result<(), TmtoError> {
        if state >= self.size {
            return Err(TmtoError::InvalidState(state));
        }
        Ok(())
    }
}

fn with_odd_parity(seven_bits: u8) -> u8 {
    let seven_bits = seven_bits & 0x7f;
    let data = seven_bits << 1;
    let parity = if seven_bits.count_ones() % 2 == 0 {
        1
    } else {
        0
    };
    data | parity
}

#[derive(Clone)]
pub struct DesOracle {
    key_space: ReducedDesKeySpace,
    plaintext: Vec<u8>,
}

impl DesOracle {
    pub fn new(key_space: ReducedDesKeySpace, plaintext: &[u8]) -> Result<Self, TmtoError> {
        if plaintext.is_empty() {
            return Err(TmtoError::EmptyPlaintext);
        }
        Ok(Self {
            key_space,
            plaintext: plaintext.to_vec(),
        })
    }

    pub fn standard(key_space: ReducedDesKeySpace) -> Self {
        Self::new(key_space, DEFAULT_PLAINTEXT).expect("default plaintext is non-empty")
    }

    pub fn key_space(&self) -> ReducedDesKeySpace {
        self.key_space
    }

    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub fn encrypt_state(&self, state: u64) -> Result<Vec<u8>, TmtoError> {
        let key = self.key_space.to_key_bytes(state)?;
        let cipher = Des::new_from_slice(&key).expect("DES key is exactly eight bytes");

        let block_size = 8;
        let pad_len = block_size - (self.plaintext.len() % block_size);
        let mut output = Vec::with_capacity(self.plaintext.len() + pad_len);
        output.extend_from_slice(&self.plaintext);
        output.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        for chunk in output.chunks_exact_mut(block_size) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }

        Ok(output)
    }

    pub fn matches(&self, state: u64, expected: &[u8]) -> Result<bool, TmtoError> {
        Ok(self.encrypt_state(state)? == expected)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LegacyReduction {
    state_mask: u64,
}

impl LegacyReduction {
    pub fn new(key_space: ReducedDesKeySpace) -> Self {
        Self {
            state_mask: key_space.mask(),
        }
    }

    pub fn reduce(self, ciphertext: &[u8]) -> Result<u64, TmtoError> {
        if ciphertext.len() < 4 {
            return Err(TmtoError::InvalidCiphertextLength(ciphertext.len()));
        }

        let mut state = 0_u64;
        for byte in &ciphertext[ciphertext.len() - 4..] {
            state = (state << 7) | u64::from(*byte >> 1);
        }

        Ok(state & self.state_mask)
    }
}

pub fn step(oracle: &DesOracle, reduction: LegacyReduction, state: u64) -> Result<u64, TmtoError> {
    reduction.reduce(&oracle.encrypt_state(state)?)
}

pub fn exhaustive_find(
    key_space: ReducedDesKeySpace,
    oracle: &DesOracle,
    target_ciphertext: &[u8],
) -> Result<Option<u64>, TmtoError> {
    for state in 0..key_space.size() {
        if oracle.matches(state, target_ciphertext)? {
            return Ok(Some(state));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HellmanLookup {
    pub state: Option<u64>,
    pub endpoint_matches: usize,
    pub candidate_chains_checked: usize,
}

#[derive(Clone)]
pub struct HellmanTable {
    oracle: DesOracle,
    reduction: LegacyReduction,
    chain_length: usize,
    starts_by_endpoint: HashMap<u64, Vec<u64>>,
    chain_count: usize,
}

impl HellmanTable {
    pub fn build(
        key_space: ReducedDesKeySpace,
        oracle: DesOracle,
        reduction: LegacyReduction,
        start_states: &[u64],
        chain_length: usize,
    ) -> Result<Self, TmtoError> {
        if chain_length == 0 {
            return Err(TmtoError::InvalidChainLength);
        }

        let mut starts_by_endpoint: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut unique_starts = HashSet::new();

        for &start in start_states {
            key_space.validate_state(start)?;
            if !unique_starts.insert(start) {
                return Err(TmtoError::DuplicateStart(start));
            }

            let mut state = start;
            for _ in 0..chain_length {
                state = step(&oracle, reduction, state)?;
            }
            starts_by_endpoint.entry(state).or_default().push(start);
        }

        Ok(Self {
            oracle,
            reduction,
            chain_length,
            starts_by_endpoint,
            chain_count: start_states.len(),
        })
    }

    pub fn chain_count(&self) -> usize {
        self.chain_count
    }

    pub fn distinct_endpoint_count(&self) -> usize {
        self.starts_by_endpoint.len()
    }

    pub fn lookup(&self, target_ciphertext: &[u8]) -> Result<HellmanLookup, TmtoError> {
        let mut endpoint_matches = 0;
        let mut candidate_chains_checked = 0;
        let mut checked_starts = HashSet::new();

        for target_position in (0..self.chain_length).rev() {
            let projected_endpoint =
                self.project_to_endpoint(target_ciphertext, target_position)?;
            let Some(candidates) = self.starts_by_endpoint.get(&projected_endpoint) else {
                continue;
            };

            endpoint_matches += 1;

            for &start in candidates {
                if !checked_starts.insert(start) {
                    continue;
                }

                candidate_chains_checked += 1;
                if let Some(state) = self.regenerate_and_find(start, target_ciphertext)? {
                    return Ok(HellmanLookup {
                        state: Some(state),
                        endpoint_matches,
                        candidate_chains_checked,
                    });
                }
            }
        }

        Ok(HellmanLookup {
            state: None,
            endpoint_matches,
            candidate_chains_checked,
        })
    }

    fn project_to_endpoint(
        &self,
        target_ciphertext: &[u8],
        target_position: usize,
    ) -> Result<u64, TmtoError> {
        let mut state = self.reduction.reduce(target_ciphertext)?;
        for _ in (target_position + 1)..self.chain_length {
            state = step(&self.oracle, self.reduction, state)?;
        }
        Ok(state)
    }

    fn regenerate_and_find(
        &self,
        start: u64,
        target_ciphertext: &[u8],
    ) -> Result<Option<u64>, TmtoError> {
        let mut state = start;
        for _ in 0..self.chain_length {
            let ciphertext = self.oracle.encrypt_state(state)?;
            if ciphertext.as_slice() == target_ciphertext {
                return Ok(Some(state));
            }
            state = self.reduction.reduce(&ciphertext)?;
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DistinguishedPointPredicate {
    mask: u64,
    difficulty_bits: u8,
}

impl DistinguishedPointPredicate {
    pub fn new(difficulty_bits: u8, key_space: ReducedDesKeySpace) -> Result<Self, TmtoError> {
        if difficulty_bits == 0 || difficulty_bits > key_space.state_bits() {
            return Err(TmtoError::InvalidDifficulty {
                difficulty_bits,
                state_bits: key_space.state_bits(),
            });
        }
        Ok(Self {
            mask: (1_u64 << difficulty_bits) - 1,
            difficulty_bits,
        })
    }

    pub fn difficulty_bits(self) -> u8 {
        self.difficulty_bits
    }

    pub fn test(self, state: u64) -> bool {
        state & self.mask == 0
    }
}

#[derive(Debug, Clone, Copy)]
struct DistinguishedChain {
    start: u64,
    endpoint: u64,
    transitions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedLookup {
    pub state: Option<u64>,
    pub projection_steps: usize,
    pub endpoint_candidates: usize,
    pub candidate_chains_checked: usize,
}

#[derive(Clone)]
pub struct DistinguishedPointTable {
    oracle: DesOracle,
    reduction: LegacyReduction,
    predicate: DistinguishedPointPredicate,
    max_chain_length: usize,
    chains_by_endpoint: HashMap<u64, Vec<DistinguishedChain>>,
    generated_chains: usize,
    stored_chains: usize,
    truncated_chains: usize,
}

impl DistinguishedPointTable {
    pub fn build(
        key_space: ReducedDesKeySpace,
        oracle: DesOracle,
        reduction: LegacyReduction,
        predicate: DistinguishedPointPredicate,
        start_states: &[u64],
        max_chain_length: usize,
    ) -> Result<Self, TmtoError> {
        if max_chain_length == 0 {
            return Err(TmtoError::InvalidChainLength);
        }

        let mut chains_by_endpoint: HashMap<u64, Vec<DistinguishedChain>> = HashMap::new();
        let mut unique_starts = HashSet::new();
        let mut stored_chains = 0;
        let mut truncated_chains = 0;

        for &start in start_states {
            key_space.validate_state(start)?;
            if !unique_starts.insert(start) {
                return Err(TmtoError::DuplicateStart(start));
            }

            if let Some(chain) = generate_distinguished_chain(
                &oracle,
                reduction,
                predicate,
                start,
                max_chain_length,
            )? {
                chains_by_endpoint
                    .entry(chain.endpoint)
                    .or_default()
                    .push(chain);
                stored_chains += 1;
            } else {
                truncated_chains += 1;
            }
        }

        Ok(Self {
            oracle,
            reduction,
            predicate,
            max_chain_length,
            chains_by_endpoint,
            generated_chains: start_states.len(),
            stored_chains,
            truncated_chains,
        })
    }

    pub fn generated_chains(&self) -> usize {
        self.generated_chains
    }

    pub fn stored_chains(&self) -> usize {
        self.stored_chains
    }

    pub fn truncated_chains(&self) -> usize {
        self.truncated_chains
    }

    pub fn distinct_endpoint_count(&self) -> usize {
        self.chains_by_endpoint.len()
    }

    pub fn lookup(&self, target_ciphertext: &[u8]) -> Result<DistinguishedLookup, TmtoError> {
        let mut projected = self.reduction.reduce(target_ciphertext)?;
        let mut projection_steps = 0;

        loop {
            if self.predicate.test(projected) {
                let Some(candidates) = self.chains_by_endpoint.get(&projected) else {
                    return Ok(DistinguishedLookup {
                        state: None,
                        projection_steps,
                        endpoint_candidates: 0,
                        candidate_chains_checked: 0,
                    });
                };

                for (index, chain) in candidates.iter().enumerate() {
                    if let Some(state) = self.regenerate_and_find(*chain, target_ciphertext)? {
                        return Ok(DistinguishedLookup {
                            state: Some(state),
                            projection_steps,
                            endpoint_candidates: candidates.len(),
                            candidate_chains_checked: index + 1,
                        });
                    }
                }

                return Ok(DistinguishedLookup {
                    state: None,
                    projection_steps,
                    endpoint_candidates: candidates.len(),
                    candidate_chains_checked: candidates.len(),
                });
            }

            if projection_steps >= self.max_chain_length - 1 {
                return Ok(DistinguishedLookup {
                    state: None,
                    projection_steps,
                    endpoint_candidates: 0,
                    candidate_chains_checked: 0,
                });
            }

            projected = step(&self.oracle, self.reduction, projected)?;
            projection_steps += 1;
        }
    }

    fn regenerate_and_find(
        &self,
        chain: DistinguishedChain,
        target_ciphertext: &[u8],
    ) -> Result<Option<u64>, TmtoError> {
        let mut state = chain.start;
        for _ in 0..chain.transitions {
            let ciphertext = self.oracle.encrypt_state(state)?;
            if ciphertext.as_slice() == target_ciphertext {
                return Ok(Some(state));
            }
            state = self.reduction.reduce(&ciphertext)?;
        }
        Ok(None)
    }
}

fn generate_distinguished_chain(
    oracle: &DesOracle,
    reduction: LegacyReduction,
    predicate: DistinguishedPointPredicate,
    start: u64,
    max_chain_length: usize,
) -> Result<Option<DistinguishedChain>, TmtoError> {
    let mut state = start;

    for transitions in 1..=max_chain_length {
        let next = step(oracle, reduction, state)?;
        if predicate.test(next) {
            return Ok(Some(DistinguishedChain {
                start,
                endpoint: next,
                transitions,
            }));
        }
        state = next;
    }

    Ok(None)
}

pub fn hellman_coverage_states(
    key_space: ReducedDesKeySpace,
    oracle: &DesOracle,
    reduction: LegacyReduction,
    start_states: &[u64],
    chain_length: usize,
) -> Result<usize, TmtoError> {
    if chain_length == 0 {
        return Err(TmtoError::InvalidChainLength);
    }

    let mut covered = HashSet::new();
    for &start in start_states {
        key_space.validate_state(start)?;
        let mut state = start;
        for _ in 0..chain_length {
            covered.insert(state);
            state = step(oracle, reduction, state)?;
        }
    }
    Ok(covered.len())
}

pub fn distinguished_coverage_states(
    key_space: ReducedDesKeySpace,
    oracle: &DesOracle,
    reduction: LegacyReduction,
    predicate: DistinguishedPointPredicate,
    start_states: &[u64],
    max_chain_length: usize,
) -> Result<usize, TmtoError> {
    if max_chain_length == 0 {
        return Err(TmtoError::InvalidChainLength);
    }

    let mut covered = HashSet::new();

    for &start in start_states {
        key_space.validate_state(start)?;
        let Some(chain) =
            generate_distinguished_chain(oracle, reduction, predicate, start, max_chain_length)?
        else {
            continue;
        };

        let mut state = start;
        for _ in 0..chain.transitions {
            covered.insert(state);
            state = step(oracle, reduction, state)?;
        }
    }

    Ok(covered.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0);
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn key_encoding_round_trips_and_has_odd_parity() {
        let key_space = ReducedDesKeySpace::new(16).unwrap();
        for state in [0, 1, 2, 127, 128, 0x1234, 0xffff] {
            let key = key_space.to_key_bytes(state).unwrap();
            assert_eq!(key_space.to_state(&key).unwrap(), state);
            for byte in key {
                assert_eq!(byte.count_ones() % 2, 1);
            }
        }
    }

    #[test]
    fn shared_java_rust_reference_vectors_match() {
        let csv = include_str!("../../test-vectors/java-rust-reference.csv");

        for line in csv.lines().skip(1).filter(|line| !line.trim().is_empty()) {
            let columns: Vec<&str> = line.split(',').collect();
            assert_eq!(columns.len(), 7);

            let state_bits: u8 = columns[0].parse().unwrap();
            let state: u64 = columns[1].parse().unwrap();
            let expected_key = columns[2];
            let expected_ciphertext = columns[3];
            let expected_reduced: u64 = columns[4].parse().unwrap();
            let chain_length: usize = columns[5].parse().unwrap();
            let expected_endpoint: u64 = columns[6].parse().unwrap();

            let key_space = ReducedDesKeySpace::new(state_bits).unwrap();
            let oracle = DesOracle::standard(key_space);
            let reduction = LegacyReduction::new(key_space);

            let key = key_space.to_key_bytes(state).unwrap();
            assert_eq!(encode_hex(&key), expected_key);

            let ciphertext = oracle.encrypt_state(state).unwrap();
            assert_eq!(encode_hex(&ciphertext), expected_ciphertext);
            assert_eq!(reduction.reduce(&ciphertext).unwrap(), expected_reduced);

            let mut endpoint = state;
            for _ in 0..chain_length {
                endpoint = step(&oracle, reduction, endpoint).unwrap();
            }
            assert_eq!(endpoint, expected_endpoint);

            assert_eq!(decode_hex(expected_ciphertext), ciphertext);
        }
    }

    #[test]
    fn exhaustive_search_recovers_exact_state() {
        let key_space = ReducedDesKeySpace::new(12).unwrap();
        let oracle = DesOracle::standard(key_space);
        let target_state = 0x5a3;
        let target = oracle.encrypt_state(target_state).unwrap();
        assert_eq!(
            exhaustive_find(key_space, &oracle, &target).unwrap(),
            Some(target_state)
        );
    }

    #[test]
    fn hellman_recovers_state_from_stored_chain() {
        let key_space = ReducedDesKeySpace::new(16).unwrap();
        let oracle = DesOracle::standard(key_space);
        let reduction = LegacyReduction::new(key_space);
        let starts = [0, 1, 4660, 65535];

        let table = HellmanTable::build(key_space, oracle.clone(), reduction, &starts, 8).unwrap();
        let target = oracle.encrypt_state(4660).unwrap();
        let lookup = table.lookup(&target).unwrap();

        assert_eq!(lookup.state, Some(4660));
    }

    #[test]
    fn distinguished_points_recover_start_state() {
        let key_space = ReducedDesKeySpace::new(16).unwrap();
        let oracle = DesOracle::standard(key_space);
        let reduction = LegacyReduction::new(key_space);
        let predicate = DistinguishedPointPredicate::new(4, key_space).unwrap();

        let table = DistinguishedPointTable::build(
            key_space,
            oracle.clone(),
            reduction,
            predicate,
            &[0, 1, 4660, 65535],
            64,
        )
        .unwrap();

        let target = oracle.encrypt_state(0).unwrap();
        let lookup = table.lookup(&target).unwrap();
        assert_eq!(lookup.state, Some(0));
    }

    #[test]
    fn exact_coverage_matches_reference_chain_count_for_disjoint_short_chains() {
        let key_space = ReducedDesKeySpace::new(16).unwrap();
        let oracle = DesOracle::standard(key_space);
        let reduction = LegacyReduction::new(key_space);

        assert_eq!(
            hellman_coverage_states(key_space, &oracle, reduction, &[0, 1], 8).unwrap(),
            16
        );
    }
}

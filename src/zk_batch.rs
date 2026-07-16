//! Fixed-shape shielded batch circuit skeleton.
//!
//! The public shape reserves 64 input and 64 output slots and a depth-32
//! Merkle path. This first implementation deliberately permits only slot zero
//! to be active; the other slots are constrained to padding. It therefore gives
//! us a real circuit and stable encodings to audit before enabling 64 active
//! notes. It is not connected to consensus and is not a production verifier.

use std::array;

use halo2_gadgets::poseidon::{
    Hash, Pow5Chip, Pow5Config,
    primitives::{self as poseidon, ConstantLength, P128Pow5T3},
};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, SimpleFloorPlanner, Value},
    pasta::{
        Fp,
        group::ff::{Field, PrimeField},
    },
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

use crate::zk_circuit::ToyNoteWitness;

pub const BATCH_MAX_INPUTS: usize = 64;
pub const BATCH_MAX_OUTPUTS: usize = 64;
pub const BATCH_MERKLE_DEPTH: usize = 32;
pub const BATCH_PUBLIC_INPUT_COUNT: usize = 16;
pub const BATCH_CIRCUIT_K: u32 = 15;
pub const BATCH_ZK_PROTOCOL_VERSION: u16 = 2;
pub const BATCH_CIRCUIT_ID: &str = "asteria.shielded.batch.poseidon.64x64.d32.domain.v2";

const WIDTH: usize = 3;
const RATE: usize = 2;
const DOMAIN_LEN: usize = 5;
const NOTE_LEN: usize = 8;
const POLICY_LEN: usize = 7;
const NULLIFIER_LEN: usize = 5;
const PAIR_LEN: usize = 3;
const OWNER_LEN: usize = 2;
const COMMITMENT_TAG: u64 = 0x4153_4243;
const POLICY_TAG: u64 = 0x4153_4250;
const NULLIFIER_TAG: u64 = 0x4153_424e;
const MERKLE_TAG: u64 = 0x4153_424d;
const DOMAIN_TAG: u64 = 0x4153_4244;
const OWNER_TAG: u64 = 0x4153_424f;
const BASIS_POINTS: u64 = 10_000;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum BatchNativeError {
    #[error("only slot zero may be active in this circuit stage")]
    ActiveSlotNotSupported,
    #[error("slot zero must contain one active input and one active output")]
    MissingActiveSlot,
    #[error("batch domain fields must be non-zero")]
    InvalidDomain,
    #[error("input owner secret must be non-zero and match the note owner commitment")]
    InvalidOwnerSecret,
    #[error("batch policy is outside the bounded circuit domain")]
    InvalidPolicy,
    #[error("batch fee is below the policy minimum")]
    FeeBelowMinimum,
    #[error("output commitment does not match its opening")]
    OutputCommitmentMismatch,
    #[error("nullifier does not match its opening")]
    NullifierMismatch,
    #[error("Merkle path does not derive the anchor root")]
    MerkleRootMismatch,
    #[error("collateral is not conserved")]
    CollateralConservation,
    #[error("position is not conserved")]
    PositionConservation,
    #[error("output leverage or collateral is invalid")]
    InvalidLeverage,
    #[error("output collateral is below the isolated-margin requirement")]
    InsufficientMargin,
    #[error("integer product is outside the 128-bit circuit domain")]
    IntegerOutOfRange,
}

/// Public policy fields. Mark and scale are bounded to 32 bits in this stage
/// so all margin products fit in a 128-bit range proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchPolicy {
    pub mark_price: u64,
    pub price_scale: u64,
    pub minimum_initial_margin_bps: u32,
    pub maximum_leverage: u16,
    pub minimum_fee: u64,
}

impl BatchPolicy {
    pub fn validate(&self) -> Result<(), BatchNativeError> {
        if self.mark_price == 0
            || self.mark_price > u64::from(u32::MAX)
            || self.price_scale == 0
            || self.price_scale > u64::from(u32::MAX)
            || self.minimum_initial_margin_bps > BASIS_POINTS as u32
            || self.maximum_leverage == 0
        {
            return Err(BatchNativeError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Public protocol domain bound into every batch commitment and nullifier.
///
/// The values are field elements here because this experimental circuit does
/// not yet own the canonical byte-to-field encoding used by the production
/// shielded protocol. The eventual envelope must bind these fields to its
/// chain, ledger, market, and collateral-asset identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchDomain {
    pub chain_domain: Fp,
    pub ledger_id: Fp,
    pub market_id: Fp,
    pub collateral_asset: Fp,
}

impl Default for BatchDomain {
    fn default() -> Self {
        Self {
            chain_domain: Fp::from(1),
            ledger_id: Fp::from(2),
            market_id: Fp::from(3),
            collateral_asset: Fp::from(4),
        }
    }
}

impl BatchDomain {
    pub fn validate(&self) -> Result<(), BatchNativeError> {
        if self.chain_domain == Fp::from(0)
            || self.ledger_id == Fp::from(0)
            || self.market_id == Fp::from(0)
            || self.collateral_asset == Fp::from(0)
        {
            return Err(BatchNativeError::InvalidDomain);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchInputWitness {
    pub active: bool,
    pub note: ToyNoteWitness,
    pub owner_secret: Fp,
    pub leaf_index: u64,
    pub siblings: [Fp; BATCH_MERKLE_DEPTH],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchOutputWitness {
    pub active: bool,
    pub note: ToyNoteWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchWitness {
    pub inputs: [BatchInputWitness; BATCH_MAX_INPUTS],
    pub outputs: [BatchOutputWitness; BATCH_MAX_OUTPUTS],
    pub fee: u64,
    pub policy: BatchPolicy,
    pub domain: BatchDomain,
    pub anchor_root: Fp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchPublicInputs {
    pub anchor_root: Fp,
    pub policy_hash: Fp,
    pub fee: Fp,
    pub nullifier: Fp,
    pub output_commitment: Fp,
    pub input_active: Fp,
    pub output_active: Fp,
    pub mark_price: Fp,
    pub price_scale: Fp,
    pub minimum_initial_margin_bps: Fp,
    pub maximum_leverage: Fp,
    pub minimum_fee: Fp,
    pub chain_domain: Fp,
    pub ledger_id: Fp,
    pub market_id: Fp,
    pub collateral_asset: Fp,
}

impl BatchPublicInputs {
    pub fn as_fields(self) -> [Fp; BATCH_PUBLIC_INPUT_COUNT] {
        [
            self.anchor_root,
            self.policy_hash,
            self.fee,
            self.nullifier,
            self.output_commitment,
            self.input_active,
            self.output_active,
            self.mark_price,
            self.price_scale,
            self.minimum_initial_margin_bps,
            self.maximum_leverage,
            self.minimum_fee,
            self.chain_domain,
            self.ledger_id,
            self.market_id,
            self.collateral_asset,
        ]
    }
}

impl BatchWitness {
    pub fn zero_padding(policy: BatchPolicy) -> Self {
        let note = ToyNoteWitness {
            owner: Fp::from(0),
            nullifier_key: Fp::from(0),
            collateral: 0,
            position: 0,
            leverage: 0,
            blinding: Fp::from(0),
        };
        Self {
            inputs: [BatchInputWitness {
                active: false,
                note,
                owner_secret: Fp::from(0),
                leaf_index: 0,
                siblings: [Fp::from(0); BATCH_MERKLE_DEPTH],
            }; BATCH_MAX_INPUTS],
            outputs: [BatchOutputWitness {
                active: false,
                note,
            }; BATCH_MAX_OUTPUTS],
            fee: 0,
            policy,
            domain: BatchDomain::default(),
            anchor_root: Fp::from(0),
        }
    }

    pub fn zero_padding_with_domain(policy: BatchPolicy, domain: BatchDomain) -> Self {
        let mut witness = Self::zero_padding(policy);
        witness.domain = domain;
        witness
    }

    pub fn public_inputs(&self) -> BatchPublicInputs {
        let input = self.inputs[0];
        let output = self.outputs[0];
        let domain_hash = batch_domain_hash(&self.domain);
        let input_commitment = batch_note_commitment_with_domain(&input.note, domain_hash);
        BatchPublicInputs {
            anchor_root: self.anchor_root,
            policy_hash: batch_policy_hash_with_domain(&self.policy, domain_hash),
            fee: Fp::from(self.fee),
            nullifier: batch_nullifier_with_domain(
                input_commitment,
                input.note.nullifier_key,
                input.leaf_index,
                domain_hash,
            ),
            output_commitment: batch_note_commitment_with_domain(&output.note, domain_hash),
            input_active: Fp::from(u64::from(input.active)),
            output_active: Fp::from(u64::from(output.active)),
            mark_price: Fp::from(self.policy.mark_price),
            price_scale: Fp::from(self.policy.price_scale),
            minimum_initial_margin_bps: Fp::from(u64::from(self.policy.minimum_initial_margin_bps)),
            maximum_leverage: Fp::from(u64::from(self.policy.maximum_leverage)),
            minimum_fee: Fp::from(self.policy.minimum_fee),
            chain_domain: self.domain.chain_domain,
            ledger_id: self.domain.ledger_id,
            market_id: self.domain.market_id,
            collateral_asset: self.domain.collateral_asset,
        }
    }

    pub fn validate_native(&self) -> Result<(), BatchNativeError> {
        if !self.inputs[0].active || !self.outputs[0].active {
            return Err(BatchNativeError::MissingActiveSlot);
        }
        if self.inputs.iter().skip(1).any(|item| item.active)
            || self.outputs.iter().skip(1).any(|item| item.active)
        {
            return Err(BatchNativeError::ActiveSlotNotSupported);
        }
        self.domain.validate()?;
        self.policy.validate()?;
        if self.fee < self.policy.minimum_fee {
            return Err(BatchNativeError::FeeBelowMinimum);
        }
        let input = self.inputs[0];
        let output = self.outputs[0];
        if input.owner_secret == Fp::from(0)
            || input.note.owner != batch_owner_commitment(input.owner_secret)
        {
            return Err(BatchNativeError::InvalidOwnerSecret);
        }
        if input.leaf_index >= (1_u64 << 32) {
            return Err(BatchNativeError::IntegerOutOfRange);
        }
        let domain_hash = batch_domain_hash(&self.domain);
        let input_commitment = batch_note_commitment_with_domain(&input.note, domain_hash);
        let output_commitment = batch_note_commitment_with_domain(&output.note, domain_hash);
        let public = self.public_inputs();
        if public.output_commitment != output_commitment {
            return Err(BatchNativeError::OutputCommitmentMismatch);
        }
        if public.nullifier
            != batch_nullifier_with_domain(
                input_commitment,
                input.note.nullifier_key,
                input.leaf_index,
                domain_hash,
            )
        {
            return Err(BatchNativeError::NullifierMismatch);
        }
        if batch_merkle_root(input_commitment, input.leaf_index, input.siblings) != self.anchor_root
        {
            return Err(BatchNativeError::MerkleRootMismatch);
        }
        if input.note.collateral
            != output
                .note
                .collateral
                .checked_add(self.fee)
                .ok_or(BatchNativeError::IntegerOutOfRange)?
        {
            return Err(BatchNativeError::CollateralConservation);
        }
        if input.note.position != output.note.position {
            return Err(BatchNativeError::PositionConservation);
        }
        if output.note.leverage == 0
            || output.note.leverage > self.policy.maximum_leverage
            || output.note.collateral == 0
        {
            return Err(BatchNativeError::InvalidLeverage);
        }
        let quantity = u128::from(output.note.position.unsigned_abs());
        let numerator = quantity
            .checked_mul(u128::from(self.policy.mark_price))
            .ok_or(BatchNativeError::IntegerOutOfRange)?;
        let lev_lhs = u128::from(output.note.collateral)
            .checked_mul(u128::from(output.note.leverage))
            .and_then(|value| value.checked_mul(u128::from(self.policy.price_scale)))
            .ok_or(BatchNativeError::IntegerOutOfRange)?;
        if lev_lhs < numerator {
            return Err(BatchNativeError::InsufficientMargin);
        }
        let bps_lhs = u128::from(output.note.collateral)
            .checked_mul(u128::from(BASIS_POINTS))
            .and_then(|value| value.checked_mul(u128::from(self.policy.price_scale)))
            .ok_or(BatchNativeError::IntegerOutOfRange)?;
        let bps_rhs = numerator
            .checked_mul(u128::from(self.policy.minimum_initial_margin_bps))
            .ok_or(BatchNativeError::IntegerOutOfRange)?;
        if bps_lhs < bps_rhs {
            return Err(BatchNativeError::InsufficientMargin);
        }
        Ok(())
    }
}

pub fn batch_domain_hash(domain: &BatchDomain) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<DOMAIN_LEN>, WIDTH, RATE>::init().hash([
        Fp::from(DOMAIN_TAG),
        domain.chain_domain,
        domain.ledger_id,
        domain.market_id,
        domain.collateral_asset,
    ])
}

pub fn batch_owner_commitment(owner_secret: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<OWNER_LEN>, WIDTH, RATE>::init()
        .hash([Fp::from(OWNER_TAG), owner_secret])
}

pub fn batch_note_commitment(note: &ToyNoteWitness) -> Fp {
    batch_note_commitment_with_domain(note, batch_domain_hash(&BatchDomain::default()))
}

pub fn batch_note_commitment_with_domain(note: &ToyNoteWitness, domain_hash: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<NOTE_LEN>, WIDTH, RATE>::init().hash([
        Fp::from(COMMITMENT_TAG),
        domain_hash,
        note.owner,
        note.nullifier_key,
        Fp::from(note.collateral),
        crate::zk_circuit::position_to_field(note.position),
        Fp::from(u64::from(note.leverage)),
        note.blinding,
    ])
}

pub fn batch_policy_hash(policy: &BatchPolicy) -> Fp {
    batch_policy_hash_with_domain(policy, batch_domain_hash(&BatchDomain::default()))
}

pub fn batch_policy_hash_with_domain(policy: &BatchPolicy, domain_hash: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<POLICY_LEN>, WIDTH, RATE>::init().hash([
        Fp::from(POLICY_TAG),
        domain_hash,
        Fp::from(policy.mark_price),
        Fp::from(policy.price_scale),
        Fp::from(u64::from(policy.minimum_initial_margin_bps)),
        Fp::from(u64::from(policy.maximum_leverage)),
        Fp::from(policy.minimum_fee),
    ])
}

pub fn batch_pair_hash(left: Fp, right: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<PAIR_LEN>, WIDTH, RATE>::init().hash([
        Fp::from(MERKLE_TAG),
        left,
        right,
    ])
}

pub fn batch_nullifier(commitment: Fp, nullifier_key: Fp, leaf_index: u64) -> Fp {
    batch_nullifier_with_domain(
        commitment,
        nullifier_key,
        leaf_index,
        batch_domain_hash(&BatchDomain::default()),
    )
}

pub fn batch_nullifier_with_domain(
    commitment: Fp,
    nullifier_key: Fp,
    leaf_index: u64,
    domain_hash: Fp,
) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<NULLIFIER_LEN>, WIDTH, RATE>::init().hash([
        Fp::from(NULLIFIER_TAG),
        domain_hash,
        commitment,
        nullifier_key,
        Fp::from(leaf_index),
    ])
}

pub fn batch_merkle_root(leaf: Fp, leaf_index: u64, siblings: [Fp; BATCH_MERKLE_DEPTH]) -> Fp {
    let mut current = leaf;
    for (level, sibling) in siblings.into_iter().enumerate() {
        let bit = (leaf_index >> level) & 1;
        current = if bit == 0 {
            batch_pair_hash(current, sibling)
        } else {
            batch_pair_hash(sibling, current)
        };
    }
    current
}

#[derive(Clone, Debug)]
pub struct BatchCircuitConfig {
    witness: Column<Advice>,
    public: Column<Instance>,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
    active: Column<Advice>,
    active_selector: Selector,
    padding_selector: Selector,
    relation: [Column<Advice>; 5],
    relation_selector: Selector,
    signed: [Column<Advice>; 3],
    signed_selector: Selector,
    margin: [Column<Advice>; 12],
    margin_selector: Selector,
    fee_check: [Column<Advice>; 3],
    fee_selector: Selector,
    bps_bound: [Column<Advice>; 2],
    bps_selector: Selector,
    nonzero_value: Column<Advice>,
    nonzero_inverse: Column<Advice>,
    nonzero_selector: Selector,
    path: [Column<Advice>; 5],
    path_selector: Selector,
    range_value: Column<Advice>,
    range_bit: Column<Advice>,
    range_acc: Column<Advice>,
    range_weight: Column<Fixed>,
    range_bit_selector: Selector,
    range_step_selector: Selector,
}

#[derive(Clone, Debug)]
pub struct BatchCircuit {
    witness: Option<Box<BatchWitness>>,
}

impl BatchCircuit {
    pub fn empty() -> Self {
        Self { witness: None }
    }

    pub fn new(witness: BatchWitness) -> Self {
        Self {
            witness: Some(Box::new(witness)),
        }
    }
}

impl Default for BatchCircuit {
    fn default() -> Self {
        Self::empty()
    }
}

impl Circuit<Fp> for BatchCircuit {
    type Config = BatchCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state: [Column<Advice>; WIDTH] = array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let round_constants_a: [Column<Fixed>; WIDTH] = array::from_fn(|_| meta.fixed_column());
        let round_constants_b: [Column<Fixed>; WIDTH] = array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(round_constants_b[0]);

        let witness = meta.advice_column();
        let public = meta.instance_column();
        meta.enable_equality(witness);
        meta.enable_equality(public);

        let active = meta.advice_column();
        meta.enable_equality(active);
        let active_selector = meta.selector();
        let padding_selector = meta.selector();
        meta.create_gate("active slot is one", |meta| {
            let q = meta.query_selector(active_selector);
            vec![
                q * (meta.query_advice(active, Rotation::cur())
                    - Expression::Constant(Fp::from(1))),
            ]
        });
        meta.create_gate("padding slot is zero", |meta| {
            let q = meta.query_selector(padding_selector);
            vec![q * meta.query_advice(active, Rotation::cur())]
        });

        let relation: [Column<Advice>; 5] = array::from_fn(|_| meta.advice_column());
        for column in relation {
            meta.enable_equality(column);
        }
        let relation_selector = meta.selector();
        meta.create_gate("balance and position conservation", |meta| {
            let q = meta.query_selector(relation_selector);
            let input_collateral = meta.query_advice(relation[0], Rotation::cur());
            let output_collateral = meta.query_advice(relation[1], Rotation::cur());
            let fee = meta.query_advice(relation[2], Rotation::cur());
            let input_position = meta.query_advice(relation[3], Rotation::cur());
            let output_position = meta.query_advice(relation[4], Rotation::cur());
            vec![
                q.clone() * (input_collateral - output_collateral - fee),
                q * (input_position - output_position),
            ]
        });

        let signed: [Column<Advice>; 3] = array::from_fn(|_| meta.advice_column());
        for column in signed {
            meta.enable_equality(column);
        }
        let signed_selector = meta.selector();
        meta.create_gate("signed magnitude", |meta| {
            let q = meta.query_selector(signed_selector);
            let position = meta.query_advice(signed[0], Rotation::cur());
            let sign = meta.query_advice(signed[1], Rotation::cur());
            let magnitude = meta.query_advice(signed[2], Rotation::cur());
            vec![
                q.clone() * sign.clone() * (sign.clone() - Expression::Constant(Fp::from(1))),
                q * (position - magnitude.clone()
                    + Expression::Constant(Fp::from(2)) * sign * magnitude),
            ]
        });

        let margin: [Column<Advice>; 12] = array::from_fn(|_| meta.advice_column());
        for column in margin {
            meta.enable_equality(column);
        }
        let margin_selector = meta.selector();
        meta.create_gate("isolated margin products", |meta| {
            let q = meta.query_selector(margin_selector);
            let collateral = meta.query_advice(margin[0], Rotation::cur());
            let leverage = meta.query_advice(margin[1], Rotation::cur());
            let scale = meta.query_advice(margin[2], Rotation::cur());
            let quantity = meta.query_advice(margin[3], Rotation::cur());
            let mark = meta.query_advice(margin[4], Rotation::cur());
            let bps = meta.query_advice(margin[5], Rotation::cur());
            let lev_lhs = meta.query_advice(margin[6], Rotation::cur());
            let notional = meta.query_advice(margin[7], Rotation::cur());
            let lev_slack = meta.query_advice(margin[8], Rotation::cur());
            let bps_lhs = meta.query_advice(margin[9], Rotation::cur());
            let bps_rhs = meta.query_advice(margin[10], Rotation::cur());
            let bps_slack = meta.query_advice(margin[11], Rotation::cur());
            vec![
                q.clone()
                    * (lev_lhs.clone() - collateral.clone() * leverage.clone() * scale.clone()),
                q.clone() * (notional.clone() - quantity * mark),
                q.clone() * (lev_lhs - notional.clone() - lev_slack),
                q.clone()
                    * (bps_lhs.clone()
                        - collateral * Expression::Constant(Fp::from(BASIS_POINTS)) * scale),
                q.clone() * (bps_rhs.clone() - notional * bps),
                q * (bps_lhs - bps_rhs - bps_slack),
            ]
        });

        let fee_check: [Column<Advice>; 3] = array::from_fn(|_| meta.advice_column());
        for column in fee_check {
            meta.enable_equality(column);
        }
        let fee_selector = meta.selector();
        meta.create_gate("fee meets policy minimum", |meta| {
            let q = meta.query_selector(fee_selector);
            let fee = meta.query_advice(fee_check[0], Rotation::cur());
            let minimum = meta.query_advice(fee_check[1], Rotation::cur());
            let slack = meta.query_advice(fee_check[2], Rotation::cur());
            vec![q * (fee - minimum - slack)]
        });

        let bps_bound: [Column<Advice>; 2] = array::from_fn(|_| meta.advice_column());
        for column in bps_bound {
            meta.enable_equality(column);
        }
        let bps_selector = meta.selector();
        meta.create_gate("policy basis points are bounded", |meta| {
            let q = meta.query_selector(bps_selector);
            let bps = meta.query_advice(bps_bound[0], Rotation::cur());
            let slack = meta.query_advice(bps_bound[1], Rotation::cur());
            vec![q * (bps + slack - Expression::Constant(Fp::from(BASIS_POINTS)))]
        });

        let nonzero_value = meta.advice_column();
        let nonzero_inverse = meta.advice_column();
        meta.enable_equality(nonzero_value);
        let nonzero_selector = meta.selector();
        meta.create_gate("required values are non-zero", |meta| {
            let q = meta.query_selector(nonzero_selector);
            let value = meta.query_advice(nonzero_value, Rotation::cur());
            let inverse = meta.query_advice(nonzero_inverse, Rotation::cur());
            vec![q * (value * inverse - Expression::Constant(Fp::from(1)))]
        });

        let path: [Column<Advice>; 5] = array::from_fn(|_| meta.advice_column());
        for column in path {
            meta.enable_equality(column);
        }
        let path_selector = meta.selector();
        meta.create_gate("Merkle path orientation", |meta| {
            let q = meta.query_selector(path_selector);
            let current = meta.query_advice(path[0], Rotation::cur());
            let sibling = meta.query_advice(path[1], Rotation::cur());
            let bit = meta.query_advice(path[2], Rotation::cur());
            let left = meta.query_advice(path[3], Rotation::cur());
            let right = meta.query_advice(path[4], Rotation::cur());
            let one = Expression::Constant(Fp::from(1));
            vec![
                q.clone() * bit.clone() * (bit.clone() - one.clone()),
                q.clone()
                    * (left
                        - ((one.clone() - bit.clone()) * current.clone()
                            + bit.clone() * sibling.clone())),
                q * (right - ((one - bit.clone()) * sibling + bit * current)),
            ]
        });

        let range_value = meta.advice_column();
        let range_bit = meta.advice_column();
        let range_acc = meta.advice_column();
        let range_weight = meta.fixed_column();
        meta.enable_equality(range_value);
        meta.enable_equality(range_bit);
        meta.enable_equality(range_acc);
        let range_bit_selector = meta.selector();
        let range_step_selector = meta.selector();
        meta.create_gate("range bit boolean", |meta| {
            let q = meta.query_selector(range_bit_selector);
            let bit = meta.query_advice(range_bit, Rotation::cur());
            vec![q * bit.clone() * (bit - Expression::Constant(Fp::from(1)))]
        });
        meta.create_gate("range accumulator", |meta| {
            let q = meta.query_selector(range_step_selector);
            vec![
                q * (meta.query_advice(range_acc, Rotation::cur())
                    - meta.query_advice(range_acc, Rotation::prev())
                    - meta.query_advice(range_bit, Rotation::cur())
                        * meta.query_fixed(range_weight)),
            ]
        });

        BatchCircuitConfig {
            witness,
            public,
            poseidon: Pow5Chip::configure::<P128Pow5T3>(
                meta,
                state,
                partial_sbox,
                round_constants_a,
                round_constants_b,
            ),
            active,
            active_selector,
            padding_selector,
            relation,
            relation_selector,
            signed,
            signed_selector,
            margin,
            margin_selector,
            fee_check,
            fee_selector,
            bps_bound,
            bps_selector,
            nonzero_value,
            nonzero_inverse,
            nonzero_selector,
            path,
            path_selector,
            range_value,
            range_bit,
            range_acc,
            range_weight,
            range_bit_selector,
            range_step_selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let witness = self.witness.as_deref();
        let input = witness.map(|value| value.inputs[0]);
        let output = witness.map(|value| value.outputs[0]);
        let policy = witness.map(|value| value.policy);
        let domain = witness.map(|value| value.domain);

        let domain_cells = assign_values(
            layouter.namespace(|| "batch domain"),
            config.witness,
            [
                optional_value(domain, |value| value.chain_domain),
                optional_value(domain, |value| value.ledger_id),
                optional_value(domain, |value| value.market_id),
                optional_value(domain, |value| value.collateral_asset),
            ],
            "domain field",
        )?;
        let domain_tag = assign_single(
            layouter.namespace(|| "domain tag"),
            config.witness,
            Value::known(Fp::from(DOMAIN_TAG)),
            "domain tag",
        )?;
        let domain_hash = hash_fixed(
            &config,
            &mut layouter,
            ConstantLength::<DOMAIN_LEN>,
            [
                domain_tag,
                domain_cells[0].clone(),
                domain_cells[1].clone(),
                domain_cells[2].clone(),
                domain_cells[3].clone(),
            ],
            "domain hash",
        )?;

        let policy_cells = assign_values(
            layouter.namespace(|| "policy fields"),
            config.witness,
            [
                optional_value(policy, |value| Fp::from(value.mark_price)),
                optional_value(policy, |value| Fp::from(value.price_scale)),
                optional_value(policy, |value| {
                    Fp::from(u64::from(value.minimum_initial_margin_bps))
                }),
                optional_value(policy, |value| Fp::from(u64::from(value.maximum_leverage))),
                optional_value(policy, |value| Fp::from(value.minimum_fee)),
            ],
            "policy field",
        )?;
        let policy_tag = assign_single(
            layouter.namespace(|| "policy tag"),
            config.witness,
            Value::known(Fp::from(POLICY_TAG)),
            "policy tag",
        )?;
        let policy_hash = hash_fixed(
            &config,
            &mut layouter,
            ConstantLength::<POLICY_LEN>,
            [
                policy_tag,
                domain_hash.clone(),
                policy_cells[0].clone(),
                policy_cells[1].clone(),
                policy_cells[2].clone(),
                policy_cells[3].clone(),
                policy_cells[4].clone(),
            ],
            "policy hash",
        )?;

        let input_values = assign_note_values(
            layouter.namespace(|| "input note"),
            config.witness,
            input.map(|value| value.note),
            domain_hash.clone(),
            "input note",
        )?;
        let input_commitment = hash_fixed(
            &config,
            &mut layouter,
            ConstantLength::<NOTE_LEN>,
            input_values.clone(),
            "input commitment",
        )?;
        copy_equal(&mut layouter, input_values[1].cell(), domain_hash.cell())?;
        let output_values = assign_note_values(
            layouter.namespace(|| "output note"),
            config.witness,
            output.map(|value| value.note),
            domain_hash.clone(),
            "output note",
        )?;
        let output_commitment = hash_fixed(
            &config,
            &mut layouter,
            ConstantLength::<NOTE_LEN>,
            output_values.clone(),
            "output commitment",
        )?;
        copy_equal(&mut layouter, output_values[1].cell(), domain_hash.cell())?;

        let owner_secret = assign_single(
            layouter.namespace(|| "input owner secret"),
            config.witness,
            optional_value(input, |value| value.owner_secret),
            "input owner secret",
        )?;
        let owner_tag = assign_single(
            layouter.namespace(|| "owner tag"),
            config.witness,
            Value::known(Fp::from(OWNER_TAG)),
            "owner tag",
        )?;
        let owner_commitment = hash_fixed(
            &config,
            &mut layouter,
            ConstantLength::<OWNER_LEN>,
            [owner_tag, owner_secret.clone()],
            "owner commitment",
        )?;
        copy_equal(
            &mut layouter,
            input_values[2].cell(),
            owner_commitment.cell(),
        )?;

        let leaf = assign_range::<32>(
            &mut layouter,
            &config,
            input.map(|value| u128::from(value.leaf_index)),
            32,
            "leaf index",
        )?;
        let siblings = assign_values::<BATCH_MERKLE_DEPTH>(
            layouter.namespace(|| "Merkle siblings"),
            config.witness,
            array::from_fn(|index| optional_value(input, |value| value.siblings[index])),
            "Merkle sibling",
        )?;
        let mut current = input_commitment.clone();
        let mut current_value = input.zip(domain).map(|(value, domain)| {
            batch_note_commitment_with_domain(&value.note, batch_domain_hash(&domain))
        });
        for (level, (sibling, bit)) in siblings.iter().zip(leaf.bits.iter()).enumerate() {
            let sibling = sibling.clone();
            let bit = bit.clone();
            let bit_value = input.map(|value| Fp::from((value.leaf_index >> level) & 1));
            let sibling_value = input.map(|value| value.siblings[level]);
            let left_value = select_value(bit_value, current_value, sibling_value, false);
            let right_value = select_value(bit_value, current_value, sibling_value, true);
            let path_cells: [AssignedCell<Fp, Fp>; 5] = layouter.assign_region(
                || format!("Merkle orientation {level}"),
                |mut region| {
                    config.path_selector.enable(&mut region, 0)?;
                    let values = [
                        value_or_unknown(current_value),
                        value_or_unknown(sibling_value),
                        value_or_unknown(bit_value),
                        value_or_unknown(left_value),
                        value_or_unknown(right_value),
                    ];
                    let mut cells = Vec::with_capacity(5);
                    for (index, value) in values.into_iter().enumerate() {
                        cells.push(region.assign_advice(
                            || format!("path field {index}"),
                            config.path[index],
                            0,
                            || value,
                        )?);
                    }
                    cells.try_into().map_err(|_| Error::Synthesis)
                },
            )?;
            copy_equal(&mut layouter, current.cell(), path_cells[0].cell())?;
            copy_equal(&mut layouter, sibling.cell(), path_cells[1].cell())?;
            copy_equal(&mut layouter, bit.cell(), path_cells[2].cell())?;
            let merkle_tag = assign_single(
                layouter.namespace(|| format!("Merkle tag {level}")),
                config.witness,
                Value::known(Fp::from(MERKLE_TAG)),
                "Merkle tag",
            )?;
            current = hash_fixed(
                &config,
                &mut layouter,
                ConstantLength::<PAIR_LEN>,
                [merkle_tag, path_cells[3].clone(), path_cells[4].clone()],
                "Merkle pair",
            )?;
            current_value =
                current_value
                    .zip(bit_value)
                    .zip(sibling_value)
                    .map(|((current, bit), sibling)| {
                        let left = (Fp::from(1) - bit) * current + bit * sibling;
                        let right = (Fp::from(1) - bit) * sibling + bit * current;
                        batch_pair_hash(left, right)
                    });
        }

        let nullifier_values = assign_values(
            layouter.namespace(|| "nullifier fields"),
            config.witness,
            [
                optional_value(input, |value| value.note.nullifier_key),
                optional_value(input, |value| Fp::from(value.leaf_index)),
            ],
            "nullifier field",
        )?;
        let nullifier_tag = assign_single(
            layouter.namespace(|| "nullifier tag"),
            config.witness,
            Value::known(Fp::from(NULLIFIER_TAG)),
            "nullifier tag",
        )?;
        copy_equal(&mut layouter, leaf.value.cell(), nullifier_values[1].cell())?;
        let nullifier = hash_fixed(
            &config,
            &mut layouter,
            ConstantLength::<NULLIFIER_LEN>,
            [
                nullifier_tag,
                domain_hash.clone(),
                input_commitment.clone(),
                nullifier_values[0].clone(),
                nullifier_values[1].clone(),
            ],
            "nullifier",
        )?;

        let fee = assign_single(
            layouter.namespace(|| "fee"),
            config.witness,
            optional_value(witness, |value| Fp::from(value.fee)),
            "fee",
        )?;
        let input_active = assign_single(
            layouter.namespace(|| "input active"),
            config.witness,
            optional_value(input, |value| Fp::from(u64::from(value.active))),
            "input active",
        )?;
        let output_active = assign_single(
            layouter.namespace(|| "output active"),
            config.witness,
            optional_value(output, |value| Fp::from(u64::from(value.active))),
            "output active",
        )?;
        let active_cells = layouter.assign_region(
            || "active slot constraints",
            |mut region| {
                config.active_selector.enable(&mut region, 0)?;
                config.active_selector.enable(&mut region, 1)?;
                let input_cell = region.assign_advice(
                    || "active input",
                    config.active,
                    0,
                    || optional_value(input, |value| Fp::from(u64::from(value.active))),
                )?;
                let output_cell = region.assign_advice(
                    || "active output",
                    config.active,
                    1,
                    || optional_value(output, |value| Fp::from(u64::from(value.active))),
                )?;
                Ok((input_cell, output_cell))
            },
        )?;
        copy_equal(&mut layouter, input_active.cell(), active_cells.0.cell())?;
        copy_equal(&mut layouter, output_active.cell(), active_cells.1.cell())?;

        let input_collateral = assign_range::<64>(
            &mut layouter,
            &config,
            input.map(|value| u128::from(value.note.collateral)),
            64,
            "input collateral",
        )?;
        let output_collateral = assign_range::<64>(
            &mut layouter,
            &config,
            output.map(|value| u128::from(value.note.collateral)),
            64,
            "output collateral",
        )?;
        copy_equal(
            &mut layouter,
            input_values[4].cell(),
            input_collateral.value.cell(),
        )?;
        copy_equal(
            &mut layouter,
            output_values[4].cell(),
            output_collateral.value.cell(),
        )?;

        let input_signed = assign_signed(
            &mut layouter,
            &config,
            input_values[5].clone(),
            input.map(|value| value.note.position),
            "input position",
        )?;
        let output_signed = assign_signed(
            &mut layouter,
            &config,
            output_values[5].clone(),
            output.map(|value| value.note.position),
            "output position",
        )?;
        let output_leverage = assign_range::<16>(
            &mut layouter,
            &config,
            output.map(|value| u128::from(value.note.leverage)),
            16,
            "output leverage",
        )?;
        copy_equal(
            &mut layouter,
            output_values[6].cell(),
            output_leverage.value.cell(),
        )?;

        let policy_mark = assign_range::<32>(
            &mut layouter,
            &config,
            policy.map(|value| u128::from(value.mark_price)),
            32,
            "policy mark",
        )?;
        let policy_scale = assign_range::<32>(
            &mut layouter,
            &config,
            policy.map(|value| u128::from(value.price_scale)),
            32,
            "policy scale",
        )?;
        let policy_bps = assign_range::<14>(
            &mut layouter,
            &config,
            policy.map(|value| u128::from(value.minimum_initial_margin_bps)),
            14,
            "policy bps",
        )?;
        let policy_max = assign_range::<16>(
            &mut layouter,
            &config,
            policy.map(|value| u128::from(value.maximum_leverage)),
            16,
            "policy max leverage",
        )?;
        let policy_fee = assign_range::<64>(
            &mut layouter,
            &config,
            policy.map(|value| u128::from(value.minimum_fee)),
            64,
            "policy minimum fee",
        )?;
        let fee_range = assign_range::<64>(
            &mut layouter,
            &config,
            witness.map(|value| u128::from(value.fee)),
            64,
            "fee range",
        )?;
        copy_equal(
            &mut layouter,
            policy_cells[0].cell(),
            policy_mark.value.cell(),
        )?;
        copy_equal(
            &mut layouter,
            policy_cells[1].cell(),
            policy_scale.value.cell(),
        )?;
        copy_equal(
            &mut layouter,
            policy_cells[2].cell(),
            policy_bps.value.cell(),
        )?;
        copy_equal(
            &mut layouter,
            policy_cells[3].cell(),
            policy_max.value.cell(),
        )?;
        copy_equal(
            &mut layouter,
            policy_cells[4].cell(),
            policy_fee.value.cell(),
        )?;
        copy_equal(&mut layouter, fee.cell(), fee_range.value.cell())?;

        let fee_slack = assign_range::<64>(
            &mut layouter,
            &config,
            witness.map(|value| u128::from(value.fee.saturating_sub(value.policy.minimum_fee))),
            64,
            "fee minimum slack",
        )?;
        let leverage_slack = assign_range::<16>(
            &mut layouter,
            &config,
            witness.map(|value| {
                u128::from(
                    value
                        .policy
                        .maximum_leverage
                        .saturating_sub(value.outputs[0].note.leverage),
                )
            }),
            16,
            "maximum leverage slack",
        )?;
        let bound_cells = layouter.assign_region(
            || "policy lower and upper bounds",
            |mut region| {
                let values = [
                    [
                        fee_range.value.value().copied(),
                        policy_fee.value.value().copied(),
                        fee_slack.value.value().copied(),
                    ],
                    [
                        policy_max.value.value().copied(),
                        output_leverage.value.value().copied(),
                        leverage_slack.value.value().copied(),
                    ],
                ];
                let mut cells = Vec::with_capacity(2);
                for (row, row_values) in values.into_iter().enumerate() {
                    config.fee_selector.enable(&mut region, row)?;
                    let mut row_cells = Vec::with_capacity(3);
                    for (column, value) in row_values.into_iter().enumerate() {
                        row_cells.push(region.assign_advice(
                            || format!("bound {row} field {column}"),
                            config.fee_check[column],
                            row,
                            || value,
                        )?);
                    }
                    cells.push(row_cells);
                }
                Ok(cells)
            },
        )?;
        for (cell, source) in bound_cells[0].iter().zip([
            fee_range.value.cell(),
            policy_fee.value.cell(),
            fee_slack.value.cell(),
        ]) {
            copy_equal(&mut layouter, cell.cell(), source)?;
        }
        for (cell, source) in bound_cells[1].iter().zip([
            policy_max.value.cell(),
            output_leverage.value.cell(),
            leverage_slack.value.cell(),
        ]) {
            copy_equal(&mut layouter, cell.cell(), source)?;
        }

        let bps_slack = assign_range::<14>(
            &mut layouter,
            &config,
            policy.map(|value| {
                u128::from((BASIS_POINTS as u32).saturating_sub(value.minimum_initial_margin_bps))
            }),
            14,
            "policy bps slack",
        )?;
        let bps_cells = layouter.assign_region(
            || "policy bps bound",
            |mut region| {
                config.bps_selector.enable(&mut region, 0)?;
                let bps = region.assign_advice(
                    || "policy bps",
                    config.bps_bound[0],
                    0,
                    || policy_bps.value.value().copied(),
                )?;
                let slack = region.assign_advice(
                    || "policy bps slack",
                    config.bps_bound[1],
                    0,
                    || bps_slack.value.value().copied(),
                )?;
                Ok((bps, slack))
            },
        )?;
        copy_equal(&mut layouter, bps_cells.0.cell(), policy_bps.value.cell())?;
        copy_equal(&mut layouter, bps_cells.1.cell(), bps_slack.value.cell())?;

        let nonzero_values = [
            policy.map(|value| Fp::from(value.mark_price)),
            policy.map(|value| Fp::from(value.price_scale)),
            policy.map(|value| Fp::from(u64::from(value.maximum_leverage))),
            output.map(|value| Fp::from(value.note.collateral)),
            output.map(|value| Fp::from(u64::from(value.note.leverage))),
            domain.map(|value| value.chain_domain),
            domain.map(|value| value.ledger_id),
            domain.map(|value| value.market_id),
            domain.map(|value| value.collateral_asset),
            input.map(|value| value.owner_secret),
        ];
        let nonzero_sources = [
            policy_mark.value.cell(),
            policy_scale.value.cell(),
            policy_max.value.cell(),
            output_collateral.value.cell(),
            output_leverage.value.cell(),
            domain_cells[0].cell(),
            domain_cells[1].cell(),
            domain_cells[2].cell(),
            domain_cells[3].cell(),
            owner_secret.cell(),
        ];
        let nonzero_cells = layouter.assign_region(
            || "required non-zero values",
            |mut region| {
                let mut cells = Vec::with_capacity(nonzero_values.len());
                for (row, value) in nonzero_values.into_iter().enumerate() {
                    config.nonzero_selector.enable(&mut region, row)?;
                    let value_cell = region.assign_advice(
                        || format!("non-zero value {row}"),
                        config.nonzero_value,
                        row,
                        || value_or_unknown(value),
                    )?;
                    region.assign_advice(
                        || format!("non-zero inverse {row}"),
                        config.nonzero_inverse,
                        row,
                        || {
                            value.map_or_else(Value::unknown, |value| {
                                Value::known(inverse_or_zero(value))
                            })
                        },
                    )?;
                    cells.push(value_cell);
                }
                Ok(cells)
            },
        )?;
        for (cell, source) in nonzero_cells.iter().zip(nonzero_sources) {
            copy_equal(&mut layouter, cell.cell(), source)?;
        }

        let relation = layouter.assign_region(
            || "balance and position conservation",
            |mut region| {
                config.relation_selector.enable(&mut region, 0)?;
                let values = [
                    input_collateral.value.value().copied(),
                    output_collateral.value.value().copied(),
                    fee.value().copied(),
                    input_signed.position.value().copied(),
                    output_signed.position.value().copied(),
                ];
                let mut cells = Vec::with_capacity(5);
                for (index, value) in values.into_iter().enumerate() {
                    cells.push(region.assign_advice(
                        || format!("relation {index}"),
                        config.relation[index],
                        0,
                        || value,
                    )?);
                }
                Ok(cells)
            },
        )?;
        for (cell, source) in relation.iter().zip([
            input_collateral.value.cell(),
            output_collateral.value.cell(),
            fee.cell(),
            input_signed.position.cell(),
            output_signed.position.cell(),
        ]) {
            copy_equal(&mut layouter, cell.cell(), source)?;
        }

        let margin = margin_values(input, output, policy);
        let margin_cells = layouter.assign_region(
            || "isolated margin products",
            |mut region| {
                config.margin_selector.enable(&mut region, 0)?;
                let mut cells = Vec::with_capacity(12);
                for (index, value) in margin.into_iter().enumerate() {
                    cells.push(region.assign_advice(
                        || format!("margin {index}"),
                        config.margin[index],
                        0,
                        || value,
                    )?);
                }
                Ok(cells)
            },
        )?;
        for (cell, source) in margin_cells.iter().take(6).zip([
            output_collateral.value.cell(),
            output_leverage.value.cell(),
            policy_scale.value.cell(),
            output_signed.magnitude.value.cell(),
            policy_mark.value.cell(),
            policy_bps.value.cell(),
        ]) {
            copy_equal(&mut layouter, cell.cell(), source)?;
        }
        for (cell, integer) in margin_cells
            .iter()
            .skip(6)
            .zip(margin_integers(input, output, policy).into_iter().skip(6))
        {
            let range =
                assign_range::<128>(&mut layouter, &config, integer, 128, "margin product")?;
            copy_equal(&mut layouter, cell.cell(), range.value.cell())?;
        }

        for index in 1..BATCH_MAX_INPUTS {
            layouter.assign_region(
                || format!("input padding {index}"),
                |mut region| {
                    config.padding_selector.enable(&mut region, 0)?;
                    region.assign_advice(
                        || "padding",
                        config.active,
                        0,
                        || {
                            optional_value(witness, |value| {
                                Fp::from(u64::from(value.inputs[index].active))
                            })
                        },
                    )
                },
            )?;
        }
        for index in 1..BATCH_MAX_OUTPUTS {
            layouter.assign_region(
                || format!("output padding {index}"),
                |mut region| {
                    config.padding_selector.enable(&mut region, 0)?;
                    region.assign_advice(
                        || "padding",
                        config.active,
                        0,
                        || {
                            optional_value(witness, |value| {
                                Fp::from(u64::from(value.outputs[index].active))
                            })
                        },
                    )
                },
            )?;
        }

        let public_cells = [
            current,
            policy_hash,
            fee,
            nullifier,
            output_commitment,
            input_active,
            output_active,
            policy_cells[0].clone(),
            policy_cells[1].clone(),
            policy_cells[2].clone(),
            policy_cells[3].clone(),
            policy_cells[4].clone(),
            domain_cells[0].clone(),
            domain_cells[1].clone(),
            domain_cells[2].clone(),
            domain_cells[3].clone(),
        ];
        for (index, cell) in public_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.public, index)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RangeAssignment<const BITS: usize> {
    value: AssignedCell<Fp, Fp>,
    bits: [AssignedCell<Fp, Fp>; BITS],
}

#[derive(Clone)]
struct SignedAssignment {
    position: AssignedCell<Fp, Fp>,
    magnitude: RangeAssignment<64>,
}

fn assign_range<const BITS: usize>(
    layouter: &mut impl Layouter<Fp>,
    config: &BatchCircuitConfig,
    value: Option<u128>,
    expected_bits: usize,
    annotation: &'static str,
) -> Result<RangeAssignment<BITS>, Error> {
    debug_assert_eq!(BITS, expected_bits);
    let cells = layouter.assign_region(
        || annotation,
        |mut region| {
            let value_cell = region.assign_advice(
                || "range value",
                config.range_value,
                0,
                || value.map_or_else(Value::unknown, |value| Value::known(Fp::from_u128(value))),
            )?;
            region.assign_advice(
                || "range zero",
                config.range_acc,
                0,
                || Value::known(Fp::from(0)),
            )?;
            let mut bits = Vec::with_capacity(BITS);
            let mut accumulator = 0_u128;
            let mut last_accumulator = None;
            for index in 0..BITS {
                let bit = value.map(|value| (value >> index) & 1);
                accumulator = accumulator
                    .checked_add(bit.unwrap_or(0) << index)
                    .unwrap_or(0);
                let bit_cell = region.assign_advice(
                    || "range bit",
                    config.range_bit,
                    index + 1,
                    || bit.map_or_else(Value::unknown, |bit| Value::known(Fp::from(bit as u64))),
                )?;
                let accumulator_cell = region.assign_advice(
                    || "range accumulator",
                    config.range_acc,
                    index + 1,
                    || Value::known(Fp::from_u128(accumulator)),
                )?;
                region.assign_fixed(
                    || "range weight",
                    config.range_weight,
                    index + 1,
                    || Value::known(Fp::from_u128(1_u128 << index)),
                )?;
                config.range_bit_selector.enable(&mut region, index + 1)?;
                config.range_step_selector.enable(&mut region, index + 1)?;
                bits.push(bit_cell);
                last_accumulator = Some(accumulator_cell);
            }
            let final_acc = region.assign_advice(
                || "range final",
                config.range_acc,
                BITS + 1,
                || value.map_or_else(Value::unknown, |value| Value::known(Fp::from_u128(value))),
            )?;
            region.constrain_equal(value_cell.cell(), final_acc.cell())?;
            region.constrain_equal(
                final_acc.cell(),
                last_accumulator.ok_or(Error::Synthesis)?.cell(),
            )?;
            Ok((value_cell, bits.try_into().map_err(|_| Error::Synthesis)?))
        },
    )?;
    Ok(RangeAssignment {
        value: cells.0,
        bits: cells.1,
    })
}

fn assign_signed(
    layouter: &mut impl Layouter<Fp>,
    config: &BatchCircuitConfig,
    position: AssignedCell<Fp, Fp>,
    value: Option<i64>,
    annotation: &'static str,
) -> Result<SignedAssignment, Error> {
    let magnitude = assign_range(
        layouter,
        config,
        value.map(|value| u128::from(value.unsigned_abs())),
        64,
        "signed magnitude",
    )?;
    let sign = assign_range::<1>(
        layouter,
        config,
        value.map(|value| u128::from(value < 0)),
        1,
        "signed sign",
    )?;
    let cells = layouter.assign_region(
        || annotation,
        |mut region| {
            config.signed_selector.enable(&mut region, 0)?;
            let position_cell = region.assign_advice(
                || "signed position",
                config.signed[0],
                0,
                || position.value().copied(),
            )?;
            let sign_cell = region.assign_advice(
                || "signed sign",
                config.signed[1],
                0,
                || sign.value.value().copied(),
            )?;
            let magnitude_cell = region.assign_advice(
                || "signed magnitude",
                config.signed[2],
                0,
                || magnitude.value.value().copied(),
            )?;
            Ok((position_cell, sign_cell, magnitude_cell))
        },
    )?;
    copy_equal(layouter, position.cell(), cells.0.cell())?;
    copy_equal(layouter, sign.value.cell(), cells.1.cell())?;
    copy_equal(layouter, magnitude.value.cell(), cells.2.cell())?;
    Ok(SignedAssignment {
        position,
        magnitude,
    })
}

fn copy_equal(layouter: &mut impl Layouter<Fp>, left: Cell, right: Cell) -> Result<(), Error> {
    layouter.assign_region(
        || "copy equality",
        |mut region| region.constrain_equal(left, right),
    )
}

fn assign_single(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    value: Value<Fp>,
    annotation: &'static str,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    layouter.assign_region(
        || annotation,
        |mut region| region.assign_advice(|| annotation, column, 0, || value),
    )
}

fn assign_values<const LENGTH: usize>(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    values: [Value<Fp>; LENGTH],
    annotation: &'static str,
) -> Result<[AssignedCell<Fp, Fp>; LENGTH], Error> {
    let cells = layouter.assign_region(
        || annotation,
        |mut region| {
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    region.assign_advice(
                        || format!("{annotation} {index}"),
                        column,
                        index,
                        || value,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()
        },
    )?;
    cells.try_into().map_err(|_| Error::Synthesis)
}

fn assign_note_values(
    layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    note: Option<ToyNoteWitness>,
    domain_hash: AssignedCell<Fp, Fp>,
    annotation: &'static str,
) -> Result<[AssignedCell<Fp, Fp>; NOTE_LEN], Error> {
    assign_values(
        layouter,
        column,
        [
            Value::known(Fp::from(COMMITMENT_TAG)),
            domain_hash.value().copied(),
            optional_value(note, |value| value.owner),
            optional_value(note, |value| value.nullifier_key),
            optional_value(note, |value| Fp::from(value.collateral)),
            optional_value(note, |value| {
                crate::zk_circuit::position_to_field(value.position)
            }),
            optional_value(note, |value| Fp::from(u64::from(value.leverage))),
            optional_value(note, |value| value.blinding),
        ],
        annotation,
    )
}

fn hash_fixed<const LENGTH: usize>(
    config: &BatchCircuitConfig,
    layouter: &mut impl Layouter<Fp>,
    _domain: ConstantLength<LENGTH>,
    message: [AssignedCell<Fp, Fp>; LENGTH],
    annotation: &'static str,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    Hash::<_, _, P128Pow5T3, ConstantLength<LENGTH>, WIDTH, RATE>::init(
        Pow5Chip::construct(config.poseidon.clone()),
        layouter.namespace(|| format!("initialize {annotation}")),
    )?
    .hash(layouter.namespace(|| format!("hash {annotation}")), message)
}

fn select_value(
    bit: Option<Fp>,
    current: Option<Fp>,
    sibling: Option<Fp>,
    reverse: bool,
) -> Option<Fp> {
    bit.zip(current)
        .zip(sibling)
        .map(|((bit, current), sibling)| {
            if reverse {
                (Fp::from(1) - bit) * sibling + bit * current
            } else {
                (Fp::from(1) - bit) * current + bit * sibling
            }
        })
}

fn value_or_unknown(value: Option<Fp>) -> Value<Fp> {
    value.map_or_else(Value::unknown, Value::known)
}

fn inverse_or_zero(value: Fp) -> Fp {
    Option::<Fp>::from(value.invert()).unwrap_or(Fp::from(0))
}

fn optional_value<T: Copy>(value: Option<T>, map: impl FnOnce(T) -> Fp) -> Value<Fp> {
    value.map_or_else(Value::unknown, |value| Value::known(map(value)))
}

fn margin_values(
    input: Option<BatchInputWitness>,
    output: Option<BatchOutputWitness>,
    policy: Option<BatchPolicy>,
) -> [Value<Fp>; 12] {
    let values = margin_integers(input, output, policy);
    values
        .map(|value| value.map_or_else(Value::unknown, |value| Value::known(Fp::from_u128(value))))
}

fn margin_integers(
    _input: Option<BatchInputWitness>,
    output: Option<BatchOutputWitness>,
    policy: Option<BatchPolicy>,
) -> [Option<u128>; 12] {
    let collateral = output.map(|value| u128::from(value.note.collateral));
    let leverage = output.map(|value| u128::from(value.note.leverage));
    let scale = policy.map(|value| u128::from(value.price_scale));
    let quantity = output.map(|value| u128::from(value.note.position.unsigned_abs()));
    let mark = policy.map(|value| u128::from(value.mark_price));
    let bps = policy.map(|value| u128::from(value.minimum_initial_margin_bps));
    let lev_lhs = collateral
        .zip(leverage)
        .and_then(|(a, b)| a.checked_mul(b))
        .zip(scale)
        .and_then(|(a, b)| a.checked_mul(b));
    let notional = quantity.zip(mark).and_then(|(a, b)| a.checked_mul(b));
    // Keep an invalid-but-known witness representable so the circuit reports
    // an unsatisfied constraint instead of failing during synthesis.
    let lev_slack = lev_lhs.zip(notional).map(|(a, b)| a.saturating_sub(b));
    let bps_lhs = collateral
        .and_then(|a| a.checked_mul(u128::from(BASIS_POINTS)))
        .zip(scale)
        .and_then(|(a, b)| a.checked_mul(b));
    let bps_rhs = notional.zip(bps).and_then(|(a, b)| a.checked_mul(b));
    let bps_slack = bps_lhs.zip(bps_rhs).map(|(a, b)| a.saturating_sub(b));
    [
        collateral, leverage, scale, quantity, mark, bps, lev_lhs, notional, lev_slack, bps_lhs,
        bps_rhs, bps_slack,
    ]
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    fn policy() -> BatchPolicy {
        BatchPolicy {
            mark_price: 100,
            price_scale: 1,
            minimum_initial_margin_bps: 1_000,
            maximum_leverage: 10,
            minimum_fee: 2,
        }
    }

    fn witness() -> BatchWitness {
        let mut witness = BatchWitness::zero_padding(policy());
        let owner_secret = Fp::from(101);
        witness.inputs[0].active = true;
        witness.inputs[0].note = ToyNoteWitness {
            owner: batch_owner_commitment(owner_secret),
            nullifier_key: Fp::from(12),
            collateral: 1_000,
            position: -3,
            leverage: 5,
            blinding: Fp::from(13),
        };
        witness.inputs[0].owner_secret = owner_secret;
        witness.inputs[0].leaf_index = 7;
        witness.inputs[0].siblings = array::from_fn(|index| Fp::from((index + 1) as u64));
        witness.outputs[0].active = true;
        witness.outputs[0].note = ToyNoteWitness {
            owner: Fp::from(21),
            nullifier_key: Fp::from(22),
            collateral: 990,
            position: -3,
            leverage: 5,
            blinding: Fp::from(23),
        };
        witness.fee = 10;
        refresh_anchor(&mut witness);
        witness
    }

    fn refresh_anchor(witness: &mut BatchWitness) {
        let domain_hash = batch_domain_hash(&witness.domain);
        witness.anchor_root = batch_merkle_root(
            batch_note_commitment_with_domain(&witness.inputs[0].note, domain_hash),
            witness.inputs[0].leaf_index,
            witness.inputs[0].siblings,
        );
    }

    #[test]
    fn native_batch_checks_and_circuit_satisfies() {
        let witness = witness();
        witness.validate_native().unwrap();
        let public = witness.public_inputs();
        let prover = MockProver::run(
            BATCH_CIRCUIT_K,
            &BatchCircuit::new(witness),
            vec![public.as_fields().to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn merkle_margin_and_padding_tampering_fail() {
        let witness = witness();
        let public = witness.public_inputs();

        let mut bad_root = public.as_fields().to_vec();
        bad_root[0] += Fp::from(1);
        assert!(
            MockProver::run(BATCH_CIRCUIT_K, &BatchCircuit::new(witness), vec![bad_root])
                .unwrap()
                .verify()
                .is_err()
        );

        let mut bad_sibling = witness;
        bad_sibling.inputs[0].siblings[0] += Fp::from(1);
        assert!(
            MockProver::run(
                BATCH_CIRCUIT_K,
                &BatchCircuit::new(bad_sibling),
                vec![public.as_fields().to_vec()],
            )
            .unwrap()
            .verify()
            .is_err()
        );

        let mut bad_padding = witness;
        bad_padding.inputs[1].active = true;
        assert_eq!(
            bad_padding.validate_native(),
            Err(BatchNativeError::ActiveSlotNotSupported)
        );
        assert!(
            MockProver::run(
                BATCH_CIRCUIT_K,
                &BatchCircuit::new(bad_padding),
                vec![public.as_fields().to_vec()],
            )
            .unwrap()
            .verify()
            .is_err()
        );

        let mut bad_margin = witness;
        bad_margin.inputs[0].note.collateral = 11;
        bad_margin.outputs[0].note.collateral = 1;
        refresh_anchor(&mut bad_margin);
        assert_eq!(
            bad_margin.validate_native(),
            Err(BatchNativeError::InsufficientMargin)
        );
        let bad_public = bad_margin.public_inputs();
        let bad_margin_prover = MockProver::run(
            BATCH_CIRCUIT_K,
            &BatchCircuit::new(bad_margin),
            vec![bad_public.as_fields().to_vec()],
        );
        assert!(bad_margin_prover.unwrap().verify().is_err());
    }
}

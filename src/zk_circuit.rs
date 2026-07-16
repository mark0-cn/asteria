//! Experimental Halo2 building blocks for the future shielded-margin circuit.
//!
//! This module is available only with the `zk-circuit` Cargo feature. The
//! circuit below proves a deliberately small 1-input/1-output relation. It is
//! not connected to consensus, does not prove Merkle inclusion or production
//! ownership, and must not implement the production verifier marker traits.

use std::array;

use halo2_gadgets::poseidon::{
    Hash, Pow5Chip, Pow5Config,
    primitives::{self as poseidon, ConstantLength, P128Pow5T3},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::{Fp, group::ff::PrimeField, vesta},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector, VerifyingKey,
    },
    poly::Rotation,
};
use sha2::{Digest as _, Sha256};

pub const TOY_ZK_PROTOCOL_VERSION: u16 = 1;
pub const TOY_MAX_INPUTS: usize = 1;
pub const TOY_MAX_OUTPUTS: usize = 1;
pub const TOY_PUBLIC_INPUT_COUNT: usize = 4;
pub const TOY_CIRCUIT_K: u32 = 10;
pub const TOY_CIRCUIT_ID: &str = "asteria.shielded.toy.poseidon.1x1.v1";

const WIDTH: usize = 3;
const RATE: usize = 2;
const NOTE_MESSAGE_LEN: usize = 7;
const NULLIFIER_MESSAGE_LEN: usize = 4;
const COMMITMENT_DOMAIN_TAG: u64 = 0x4153_5443;
const NULLIFIER_DOMAIN_TAG: u64 = 0x4153_544e;
const CIRCUIT_ID_HASH_DOMAIN: &[u8] = b"ASTERIA_TOY_HALO2_CIRCUIT_ID_V1\0";
const VERIFYING_KEY_HASH_DOMAIN: &[u8] = b"ASTERIA_TOY_HALO2_VK_HASH_V1\0";
const HALO2_VERSION_BINDING: &[u8] = b"halo2_proofs=0.3.2;halo2_gadgets=0.5.0";

pub type CircuitField = Fp;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ToyCircuitError {
    #[error("field element bytes are not canonical Pasta Fp encoding")]
    NonCanonicalField,
    #[error("toy input commitment does not match its witness")]
    InputCommitmentMismatch,
    #[error("toy nullifier does not match its witness")]
    NullifierMismatch,
    #[error("toy output commitment does not match its witness")]
    OutputCommitmentMismatch,
    #[error("toy fee does not match its witness")]
    FeeMismatch,
    #[error("toy collateral is not conserved")]
    CollateralConservation,
    #[error("toy position is not conserved")]
    PositionConservation,
    #[error("toy proof metadata is not bound to this protocol, circuit, and verifying key")]
    ProofBindingMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToyNoteWitness {
    pub owner: Fp,
    pub nullifier_key: Fp,
    pub collateral: u64,
    pub position: i64,
    pub leverage: u16,
    pub blinding: Fp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToySpendWitness {
    pub input: ToyNoteWitness,
    pub input_leaf_index: u64,
    pub output: ToyNoteWitness,
    pub fee: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToyPublicInputs {
    pub input_commitment: Fp,
    pub nullifier: Fp,
    pub output_commitment: Fp,
    pub fee: Fp,
}

impl ToyPublicInputs {
    pub fn from_witness(witness: &ToySpendWitness) -> Self {
        let input_commitment = toy_note_commitment(&witness.input);
        Self {
            input_commitment,
            nullifier: toy_nullifier(
                input_commitment,
                witness.input.nullifier_key,
                witness.input_leaf_index,
            ),
            output_commitment: toy_note_commitment(&witness.output),
            fee: Fp::from(witness.fee),
        }
    }

    pub fn as_fields(&self) -> [Fp; TOY_PUBLIC_INPUT_COUNT] {
        [
            self.input_commitment,
            self.nullifier,
            self.output_commitment,
            self.fee,
        ]
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(4 + TOY_PUBLIC_INPUT_COUNT * 32);
        encoded.extend_from_slice(&TOY_ZK_PROTOCOL_VERSION.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(TOY_PUBLIC_INPUT_COUNT)
                .expect("toy public input count fits u16")
                .to_be_bytes(),
        );
        for field in self.as_fields() {
            encoded.extend_from_slice(&canonical_field_bytes(field));
        }
        encoded
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToyProofBinding {
    pub protocol_version: u16,
    pub circuit_id_hash: [u8; 32],
    pub verifying_key_hash: [u8; 32],
}

impl ToyProofBinding {
    pub fn for_verifying_key(verifying_key: &VerifyingKey<vesta::Affine>) -> Self {
        Self {
            protocol_version: TOY_ZK_PROTOCOL_VERSION,
            circuit_id_hash: toy_circuit_id_hash(),
            verifying_key_hash: toy_verifying_key_hash(verifying_key),
        }
    }

    pub fn validate(
        &self,
        verifying_key: &VerifyingKey<vesta::Affine>,
    ) -> Result<(), ToyCircuitError> {
        let expected = Self::for_verifying_key(verifying_key);
        if *self == expected {
            Ok(())
        } else {
            Err(ToyCircuitError::ProofBindingMismatch)
        }
    }
}

pub fn canonical_field_bytes(value: Fp) -> [u8; 32] {
    let representation = value.to_repr();
    let mut encoded = [0_u8; 32];
    encoded.copy_from_slice(representation.as_ref());
    encoded
}

pub fn field_from_canonical_bytes(encoded: [u8; 32]) -> Result<Fp, ToyCircuitError> {
    let mut representation = <Fp as PrimeField>::Repr::default();
    representation.as_mut().copy_from_slice(&encoded);
    Option::<Fp>::from(Fp::from_repr(representation)).ok_or(ToyCircuitError::NonCanonicalField)
}

pub fn position_to_field(position: i64) -> Fp {
    if position >= 0 {
        Fp::from(position as u64)
    } else {
        -Fp::from(position.unsigned_abs())
    }
}

pub fn toy_note_commitment(note: &ToyNoteWitness) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<NOTE_MESSAGE_LEN>, WIDTH, RATE>::init()
        .hash(note_message(note))
}

pub fn toy_nullifier(commitment: Fp, nullifier_key: Fp, leaf_index: u64) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<NULLIFIER_MESSAGE_LEN>, WIDTH, RATE>::init()
        .hash([
            Fp::from(NULLIFIER_DOMAIN_TAG),
            commitment,
            nullifier_key,
            Fp::from(leaf_index),
        ])
}

pub fn validate_native_relation(
    witness: &ToySpendWitness,
    public: &ToyPublicInputs,
) -> Result<(), ToyCircuitError> {
    let expected = ToyPublicInputs::from_witness(witness);
    if public.input_commitment != expected.input_commitment {
        return Err(ToyCircuitError::InputCommitmentMismatch);
    }
    if public.nullifier != expected.nullifier {
        return Err(ToyCircuitError::NullifierMismatch);
    }
    if public.output_commitment != expected.output_commitment {
        return Err(ToyCircuitError::OutputCommitmentMismatch);
    }
    if public.fee != expected.fee {
        return Err(ToyCircuitError::FeeMismatch);
    }
    if witness
        .output
        .collateral
        .checked_add(witness.fee)
        .is_none_or(|total| total != witness.input.collateral)
    {
        return Err(ToyCircuitError::CollateralConservation);
    }
    if witness.input.position != witness.output.position {
        return Err(ToyCircuitError::PositionConservation);
    }
    Ok(())
}

pub fn toy_circuit_id_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CIRCUIT_ID_HASH_DOMAIN);
    hasher.update(TOY_ZK_PROTOCOL_VERSION.to_be_bytes());
    hasher.update((TOY_MAX_INPUTS as u64).to_be_bytes());
    hasher.update((TOY_MAX_OUTPUTS as u64).to_be_bytes());
    hasher.update(TOY_CIRCUIT_K.to_be_bytes());
    hash_length_prefixed(&mut hasher, TOY_CIRCUIT_ID.as_bytes());
    hash_length_prefixed(&mut hasher, HALO2_VERSION_BINDING);
    hasher.finalize().into()
}

pub fn toy_verifying_key_hash(verifying_key: &VerifyingKey<vesta::Affine>) -> [u8; 32] {
    // Halo2 0.3 does not expose a stable VK serializer. Its own transcript
    // binding uses this pinned representation; the exact crate versions above
    // make this fingerprint an explicit versioned artifact rather than a
    // cross-version serialization promise.
    let pinned = format!("{:?}", verifying_key.pinned());
    let mut hasher = Sha256::new();
    hasher.update(VERIFYING_KEY_HASH_DOMAIN);
    hasher.update(toy_circuit_id_hash());
    hash_length_prefixed(&mut hasher, HALO2_VERSION_BINDING);
    hash_length_prefixed(&mut hasher, pinned.as_bytes());
    hasher.finalize().into()
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("in-memory metadata length fits u64")
            .to_be_bytes(),
    );
    hasher.update(value);
}

fn note_message(note: &ToyNoteWitness) -> [Fp; NOTE_MESSAGE_LEN] {
    [
        Fp::from(COMMITMENT_DOMAIN_TAG),
        note.owner,
        note.nullifier_key,
        Fp::from(note.collateral),
        position_to_field(note.position),
        Fp::from(u64::from(note.leverage)),
        note.blinding,
    ]
}

fn optional_value<T: Copy>(value: Option<T>, map: impl FnOnce(T) -> Fp) -> Value<Fp> {
    value.map_or_else(Value::unknown, |value| Value::known(map(value)))
}

fn note_message_values(note: Option<ToyNoteWitness>) -> [Value<Fp>; NOTE_MESSAGE_LEN] {
    [
        Value::known(Fp::from(COMMITMENT_DOMAIN_TAG)),
        optional_value(note, |note| note.owner),
        optional_value(note, |note| note.nullifier_key),
        optional_value(note, |note| Fp::from(note.collateral)),
        optional_value(note, |note| position_to_field(note.position)),
        optional_value(note, |note| Fp::from(u64::from(note.leverage))),
        optional_value(note, |note| note.blinding),
    ]
}

fn assign_values<const LENGTH: usize>(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    values: [Value<Fp>; LENGTH],
    annotation: &'static str,
) -> Result<[AssignedCell<Fp, Fp>; LENGTH], Error> {
    let assigned = layouter.assign_region(
        || annotation,
        |mut region| {
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    region.assign_advice(
                        || format!("{annotation}[{index}]"),
                        column,
                        index,
                        || value,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()
        },
    )?;
    assigned.try_into().map_err(|_| Error::Synthesis)
}

#[derive(Clone, Debug)]
pub struct ToyCircuitConfig {
    witness: Column<Advice>,
    conservation: [Column<Advice>; 5],
    conservation_selector: Selector,
    public: Column<Instance>,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ToyShieldedCircuit {
    witness: Option<ToySpendWitness>,
}

impl ToyShieldedCircuit {
    pub fn new(witness: ToySpendWitness) -> Self {
        Self {
            witness: Some(witness),
        }
    }
}

impl Circuit<Fp> for ToyShieldedCircuit {
    type Config = ToyCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state: [Column<Advice>; WIDTH] = array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let round_constants_a: [Column<Fixed>; WIDTH] = array::from_fn(|_| meta.fixed_column());
        let round_constants_b: [Column<Fixed>; WIDTH] = array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(round_constants_b[0]);

        let witness = meta.advice_column();
        meta.enable_equality(witness);
        let conservation: [Column<Advice>; 5] = array::from_fn(|_| meta.advice_column());
        for column in conservation {
            meta.enable_equality(column);
        }
        let public = meta.instance_column();
        meta.enable_equality(public);

        let conservation_selector = meta.selector();
        meta.create_gate("toy collateral and position conservation", |meta| {
            let selector = meta.query_selector(conservation_selector);
            let input_collateral = meta.query_advice(conservation[0], Rotation::cur());
            let output_collateral = meta.query_advice(conservation[1], Rotation::cur());
            let fee = meta.query_advice(conservation[2], Rotation::cur());
            let input_position = meta.query_advice(conservation[3], Rotation::cur());
            let output_position = meta.query_advice(conservation[4], Rotation::cur());
            vec![
                selector.clone() * (input_collateral - output_collateral - fee),
                selector * (input_position - output_position),
            ]
        });

        ToyCircuitConfig {
            witness,
            conservation,
            conservation_selector,
            public,
            poseidon: Pow5Chip::configure::<P128Pow5T3>(
                meta,
                state,
                partial_sbox,
                round_constants_a,
                round_constants_b,
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let input_note = self.witness.map(|witness| witness.input);
        let output_note = self.witness.map(|witness| witness.output);

        let input_message = assign_values(
            layouter.namespace(|| "load input note"),
            config.witness,
            note_message_values(input_note),
            "input note field",
        )?;
        let input_commitment =
            Hash::<_, _, P128Pow5T3, ConstantLength<NOTE_MESSAGE_LEN>, WIDTH, RATE>::init(
                Pow5Chip::construct(config.poseidon.clone()),
                layouter.namespace(|| "initialize input commitment"),
            )?
            .hash(
                layouter.namespace(|| "hash input commitment"),
                input_message,
            )?;

        let nullifier_parts = assign_values(
            layouter.namespace(|| "load nullifier fields"),
            config.witness,
            [
                Value::known(Fp::from(NULLIFIER_DOMAIN_TAG)),
                optional_value(self.witness, |witness| witness.input.nullifier_key),
                optional_value(self.witness, |witness| Fp::from(witness.input_leaf_index)),
            ],
            "nullifier field",
        )?;
        let nullifier_message = [
            nullifier_parts[0].clone(),
            input_commitment.clone(),
            nullifier_parts[1].clone(),
            nullifier_parts[2].clone(),
        ];
        let nullifier =
            Hash::<_, _, P128Pow5T3, ConstantLength<NULLIFIER_MESSAGE_LEN>, WIDTH, RATE>::init(
                Pow5Chip::construct(config.poseidon.clone()),
                layouter.namespace(|| "initialize nullifier"),
            )?
            .hash(layouter.namespace(|| "hash nullifier"), nullifier_message)?;

        let output_message = assign_values(
            layouter.namespace(|| "load output note"),
            config.witness,
            note_message_values(output_note),
            "output note field",
        )?;
        let output_commitment =
            Hash::<_, _, P128Pow5T3, ConstantLength<NOTE_MESSAGE_LEN>, WIDTH, RATE>::init(
                Pow5Chip::construct(config.poseidon.clone()),
                layouter.namespace(|| "initialize output commitment"),
            )?
            .hash(
                layouter.namespace(|| "hash output commitment"),
                output_message,
            )?;

        let fee_cell = layouter.assign_region(
            || "enforce toy conservation",
            |mut region| {
                config.conservation_selector.enable(&mut region, 0)?;
                let values = [
                    optional_value(self.witness, |witness| Fp::from(witness.input.collateral)),
                    optional_value(self.witness, |witness| Fp::from(witness.output.collateral)),
                    optional_value(self.witness, |witness| Fp::from(witness.fee)),
                    optional_value(self.witness, |witness| {
                        position_to_field(witness.input.position)
                    }),
                    optional_value(self.witness, |witness| {
                        position_to_field(witness.output.position)
                    }),
                ];
                let mut assigned = Vec::with_capacity(values.len());
                for (index, value) in values.into_iter().enumerate() {
                    assigned.push(region.assign_advice(
                        || format!("conservation field {index}"),
                        config.conservation[index],
                        0,
                        || value,
                    )?);
                }
                Ok(assigned[2].clone())
            },
        )?;

        layouter.constrain_instance(input_commitment.cell(), config.public, 0)?;
        layouter.constrain_instance(nullifier.cell(), config.public, 1)?;
        layouter.constrain_instance(output_commitment.cell(), config.public, 2)?;
        layouter.constrain_instance(fee_cell.cell(), config.public, 3)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        dev::MockProver,
        plonk::{SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand_core::OsRng;

    use super::*;

    fn note(seed: u64, collateral: u64, position: i64) -> ToyNoteWitness {
        ToyNoteWitness {
            owner: Fp::from(seed),
            nullifier_key: Fp::from(seed + 1),
            collateral,
            position,
            leverage: 5,
            blinding: Fp::from(seed + 2),
        }
    }

    fn valid_witness() -> ToySpendWitness {
        ToySpendWitness {
            input: note(10, 1_000, -7),
            input_leaf_index: 42,
            output: note(20, 990, -7),
            fee: 10,
        }
    }

    #[test]
    fn canonical_field_and_public_input_encoding_round_trip() {
        let witness = valid_witness();
        let public = ToyPublicInputs::from_witness(&witness);
        for field in public.as_fields() {
            let encoded = canonical_field_bytes(field);
            assert_eq!(field_from_canonical_bytes(encoded).unwrap(), field);
        }
        assert_eq!(
            public.canonical_bytes().len(),
            4 + TOY_PUBLIC_INPUT_COUNT * 32
        );
        assert_eq!(
            field_from_canonical_bytes([0xff; 32]),
            Err(ToyCircuitError::NonCanonicalField)
        );
    }

    #[test]
    fn native_and_halo2_relations_agree_and_reject_tampering() {
        let witness = valid_witness();
        let public = ToyPublicInputs::from_witness(&witness);
        validate_native_relation(&witness, &public).unwrap();

        let prover = MockProver::run(
            TOY_CIRCUIT_K,
            &ToyShieldedCircuit::new(witness),
            vec![public.as_fields().to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();

        let mut bad_balance = witness;
        bad_balance.output.collateral += 1;
        let bad_public = ToyPublicInputs::from_witness(&bad_balance);
        assert_eq!(
            validate_native_relation(&bad_balance, &bad_public),
            Err(ToyCircuitError::CollateralConservation)
        );
        let bad_prover = MockProver::run(
            TOY_CIRCUIT_K,
            &ToyShieldedCircuit::new(bad_balance),
            vec![bad_public.as_fields().to_vec()],
        )
        .unwrap();
        assert!(bad_prover.verify().is_err());

        let mut tampered_public = public;
        tampered_public.nullifier += Fp::from(1);
        assert_eq!(
            validate_native_relation(&witness, &tampered_public),
            Err(ToyCircuitError::NullifierMismatch)
        );
        let tampered_prover = MockProver::run(
            TOY_CIRCUIT_K,
            &ToyShieldedCircuit::new(witness),
            vec![tampered_public.as_fields().to_vec()],
        )
        .unwrap();
        assert!(tampered_prover.verify().is_err());

        let mut tampered_fee = public;
        tampered_fee.fee += Fp::from(1);
        assert_eq!(
            validate_native_relation(&witness, &tampered_fee),
            Err(ToyCircuitError::FeeMismatch)
        );
    }

    #[test]
    fn creates_and_verifies_a_real_halo2_proof_with_vk_binding() {
        let params: Params<vesta::Affine> = Params::new(TOY_CIRCUIT_K);
        let empty_circuit = ToyShieldedCircuit::default();
        let verifying_key = keygen_vk(&params, &empty_circuit).unwrap();
        let binding = ToyProofBinding::for_verifying_key(&verifying_key);
        binding.validate(&verifying_key).unwrap();
        let proving_key = keygen_pk(&params, verifying_key, &empty_circuit).unwrap();

        let witness = valid_witness();
        let public = ToyPublicInputs::from_witness(&witness);
        let public_fields = public.as_fields();
        let instance_columns: &[&[Fp]] = &[&public_fields];
        let mut rng = OsRng;
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
        create_proof(
            &params,
            &proving_key,
            &[ToyShieldedCircuit::new(witness)],
            &[instance_columns],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof(
            &params,
            proving_key.get_vk(),
            strategy,
            &[instance_columns],
            &mut transcript,
        )
        .unwrap();

        let mut wrong_binding = binding;
        wrong_binding.verifying_key_hash[0] ^= 1;
        assert_eq!(
            wrong_binding.validate(proving_key.get_vk()),
            Err(ToyCircuitError::ProofBindingMismatch)
        );
    }
}

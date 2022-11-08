use crate::{Fq, Fr, Parameters};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
type ConstraintF = Fq;

use ark_ec::ProjectiveCurve;
use ark_ec_blind_signatures::{
    constraints::{
        BlindSigVerifyGadget, MsgVar, ParametersVar as BlindParametersVar, PublicKeyVar,
        SignatureVar,
    },
    BlindSigScheme, BlindedSignature, Parameters as BlindParameters, PublicKey, SecretKey,
    Signature, UserSecretData,
};
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsParameters, EdwardsProjective, FqParameters};

use ark_ff::{fields::Fp256, to_bytes, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::uint8::UInt8,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::GroupOpsBounds,
    prelude::CurveVar,
    ToBitsGadget,
};
use ark_std::ops::Mul;

use arkworks_native_gadgets::poseidon as poseidon_native;
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};

pub struct ParametersVar {}

pub struct BlindOVOTECircuit<const N_AUTHS: usize, const N_VOTERS: usize> {
    params: Parameters,
    pub poseidon_hash_native: poseidon_native::Poseidon<ConstraintF>,

    // public inputs
    pub chain_id: Option<ConstraintF>,
    pub process_id: Option<ConstraintF>,
    pub result: Option<ConstraintF>,
    pub pks_a: Option<[PublicKey<EdwardsProjective>; N_AUTHS]>,

    // private inputs
    pub pks_v: Option<[PublicKey<EdwardsProjective>; N_VOTERS]>,
    pub weights: Option<[ConstraintF; N_VOTERS]>,
    pub votes: Option<[ConstraintF; N_VOTERS]>,
    pub sigs_a: Option<[Signature<EdwardsProjective>; N_VOTERS]>, // TODO N_VOTERS * N_AUTHS
    pub sigs_v: Option<[Signature<EdwardsProjective>; N_VOTERS]>,
}
impl<const N_AUTHS: usize, const N_VOTERS: usize> BlindOVOTECircuit<N_AUTHS, N_VOTERS> {
    pub fn public_inputs(self) -> Vec<ConstraintF> {
        vec![
            self.chain_id.unwrap(),
            self.process_id.unwrap(),
            self.result.unwrap(),
            // self.pks_a.unwrap(), // TODO unwrap array
        ]
    }
}

impl<const N_AUTHS: usize, const N_VOTERS: usize> ConstraintSynthesizer<ConstraintF>
    for BlindOVOTECircuit<N_AUTHS, N_VOTERS>
{
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let blind_params: BlindParametersVar<EdwardsProjective, EdwardsVar> =
            BlindParametersVar::new_constant(
                ark_relations::ns!(cs, "blind_parameters"),
                &self.params.blind_params,
            )?;

        // public inputs
        let chain_id =
            FpVar::<ConstraintF>::new_witness(ark_relations::ns!(cs, "chain_id"), || {
                self.chain_id.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let process_id =
            FpVar::<ConstraintF>::new_witness(ark_relations::ns!(cs, "process_id"), || {
                self.process_id.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let result = FpVar::<ConstraintF>::new_witness(ark_relations::ns!(cs, "result"), || {
            self.result.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut authority_pks: Vec<PublicKeyVar<EdwardsProjective, EdwardsVar>> = Vec::new();
        for i in 0..N_AUTHS {
            let pk_a = self.pks_a.as_ref().and_then(|pk| pk.get(i));

            let pk_a = PublicKeyVar::<EdwardsProjective, EdwardsVar>::new_witness(
                ark_relations::ns!(cs, "pk_a"),
                || pk_a.ok_or(SynthesisError::AssignmentMissing),
            )?;
            authority_pks.push(pk_a);
        }

        // private inputs
        let mut voter_pks: Vec<PublicKeyVar<EdwardsProjective, EdwardsVar>> = Vec::new();
        for i in 0..N_AUTHS {
            let pk_v = self.pks_a.as_ref().and_then(|pk| pk.get(i));

            let pk_v = PublicKeyVar::<EdwardsProjective, EdwardsVar>::new_witness(
                ark_relations::ns!(cs, "pk_v"),
                || pk_v.ok_or(SynthesisError::AssignmentMissing),
            )?;
            voter_pks.push(pk_v);
        }

        let mut weights: Vec<FpVar<ConstraintF>> = Vec::new();
        for i in 0..N_VOTERS {
            let weight = self.weights.as_ref().and_then(|weight| weight.get(i));

            let weight =
                FpVar::<ConstraintF>::new_witness(ark_relations::ns!(cs, "weight"), || {
                    weight.ok_or(SynthesisError::AssignmentMissing)
                })?;
            weights.push(weight);
        }

        let mut votes: Vec<FpVar<ConstraintF>> = Vec::new();
        for i in 0..N_VOTERS {
            let vote = self.votes.as_ref().and_then(|vote| vote.get(i));

            let vote = FpVar::<ConstraintF>::new_witness(ark_relations::ns!(cs, "vote"), || {
                vote.ok_or(SynthesisError::AssignmentMissing)
            })?;
            votes.push(vote);
        }

        let mut authority_sigs: Vec<SignatureVar<EdwardsProjective, EdwardsVar>> = Vec::new();
        for i in 0..N_AUTHS {
            let signature = self.sigs_a.as_ref().and_then(|s| s.get(i));

            let signature = SignatureVar::<EdwardsProjective, EdwardsVar>::new_witness(
                ark_relations::ns!(cs, "authority_signature"),
                || signature.ok_or(SynthesisError::AssignmentMissing),
            )?;
            authority_sigs.push(signature);
        }

        let mut voter_sigs: Vec<SignatureVar<EdwardsProjective, EdwardsVar>> = Vec::new();
        for i in 0..N_AUTHS {
            let signature = self.sigs_a.as_ref().and_then(|s| s.get(i));

            let signature = SignatureVar::<EdwardsProjective, EdwardsVar>::new_witness(
                ark_relations::ns!(cs, "voter_signature"),
                || signature.ok_or(SynthesisError::AssignmentMissing),
            )?;
            voter_sigs.push(signature);
        }

        #[allow(clippy::redundant_clone)]
        let poseidon_hash =
            PoseidonGadget::<ConstraintF>::from_native(&mut cs.clone(), self.poseidon_hash_native)
                .unwrap();

        Ok(())
    }
}

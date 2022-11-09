use crate::{Fq, Fr, Parameters, VotePackage};
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
use ark_std::ops::{Mul, Sub};
use core::{borrow::Borrow, marker::PhantomData};

use arkworks_native_gadgets::poseidon as poseidon_native;
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};

pub struct VotePackageVar {
    vote: FpVar<ConstraintF>,
    pk_v: PublicKeyVar<EdwardsProjective, EdwardsVar>,
    sig_a: SignatureVar<EdwardsProjective, EdwardsVar>, // WIP will be an array for each N_AUTHS
    sig_v: SignatureVar<EdwardsProjective, EdwardsVar>,
}
impl AllocVar<VotePackage, ConstraintF> for VotePackageVar {
    fn new_variable<T: Borrow<VotePackage>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|val| {
            let vote =
                FpVar::<ConstraintF>::new_variable(cs.clone(), || Ok(val.borrow().vote), mode)?;
            let pk_v = PublicKeyVar::<EdwardsProjective, EdwardsVar>::new_variable(
                cs.clone(),
                || Ok(val.borrow().clone().pk_v),
                mode,
            )?;
            let sig_a = SignatureVar::<EdwardsProjective, EdwardsVar>::new_variable(
                cs.clone(),
                || Ok(val.borrow().clone().sig_a),
                mode,
            )?;
            let sig_v = SignatureVar::<EdwardsProjective, EdwardsVar>::new_variable(
                cs.clone(),
                || Ok(val.borrow().clone().sig_v),
                mode,
            )?;

            Ok(Self {
                vote,
                pk_v,
                sig_a,
                sig_v,
            })
        })
    }
}

#[derive(Clone)]
pub struct BlindOVOTECircuit<const N_AUTHS: usize, const N_VOTERS: usize> {
    params: Parameters,

    // public inputs
    pub chain_id: Option<ConstraintF>,
    pub process_id: Option<ConstraintF>,
    pub result: Option<ConstraintF>,
    pub pks_a: Option<[PublicKey<EdwardsProjective>; N_AUTHS]>,

    // private inputs
    pub vote_packages: Option<[VotePackage; N_VOTERS]>,
}
impl<const N_AUTHS: usize, const N_VOTERS: usize> BlindOVOTECircuit<N_AUTHS, N_VOTERS> {
    pub fn public_inputs(self) -> Vec<ConstraintF> {
        let mut pub_inp = vec![
            self.chain_id.unwrap(),
            self.process_id.unwrap(),
            self.result.unwrap(),
        ];
        for pk in self.pks_a.unwrap().iter() {
            pub_inp.push(pk.x);
            pub_inp.push(pk.y);
        }
        pub_inp
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
        let chain_id = FpVar::<ConstraintF>::new_input(ark_relations::ns!(cs, "chain_id"), || {
            self.chain_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let process_id =
            FpVar::<ConstraintF>::new_input(ark_relations::ns!(cs, "process_id"), || {
                self.process_id.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let result = FpVar::<ConstraintF>::new_input(ark_relations::ns!(cs, "result"), || {
            self.result.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut authority_pks: Vec<PublicKeyVar<EdwardsProjective, EdwardsVar>> = Vec::new();
        for i in 0..N_AUTHS {
            let pk_a = self.pks_a.as_ref().and_then(|pk| pk.get(i));

            let pk_a = PublicKeyVar::<EdwardsProjective, EdwardsVar>::new_input(
                ark_relations::ns!(cs, "pk_a"),
                || pk_a.ok_or(SynthesisError::AssignmentMissing),
            )?;
            authority_pks.push(pk_a);
        }

        // private inputs
        let mut vote_packages: Vec<VotePackageVar> = Vec::new();
        for i in 0..N_VOTERS {
            let vote_package = self.vote_packages.as_ref().and_then(|vp| vp.get(i));

            let vote_package =
                VotePackageVar::new_witness(ark_relations::ns!(cs, "vote_package"), || {
                    vote_package.ok_or(SynthesisError::AssignmentMissing)
                })?;
            vote_packages.push(vote_package);
        }

        #[allow(clippy::redundant_clone)]
        let poseidon_hash =
            PoseidonGadget::<ConstraintF>::from_native(&mut cs.clone(), self.params.hash).unwrap();

        let mut comp_result: FpVar<ConstraintF> = FpVar::Constant(Fp256::from(0));
        for vote_package in vote_packages.iter().take(N_VOTERS) {
            // 1. verify Authority blind signatures over Voters public keys
            let msg = MsgVar::<2, EdwardsProjective, EdwardsVar>::new([
                vote_package.pk_v.pub_key.x.clone(),
                vote_package.pk_v.pub_key.y.clone(),
            ]);
            let v = BlindSigVerifyGadget::<2, EdwardsProjective, EdwardsVar>::verify(
                &blind_params,
                &poseidon_hash,
                &msg,
                &vote_package.sig_a, // WIP
                &authority_pks[0],   // WIP
            )?;
            v.enforce_equal(&Boolean::TRUE)?;

            // 2. verify Voters signatures (non-blind) over vote value
            let msg = MsgVar::<1, EdwardsProjective, EdwardsVar>::new([vote_package.vote.clone()]);
            let v = BlindSigVerifyGadget::<1, EdwardsProjective, EdwardsVar>::verify(
                &blind_params,
                &poseidon_hash,
                &msg,
                &vote_package.sig_v,
                &vote_package.pk_v,
            )?;
            v.enforce_equal(&Boolean::TRUE)?;

            // 3. check vote is binary, v ∈ { 0, 1 } (binary check: v*(v-1)==0))
            let zero: FpVar<ConstraintF> = FpVar::Constant(Fp256::from(0));
            let one: FpVar<ConstraintF> = FpVar::Constant(Fp256::from(1));
            let vote = &vote_package.vote;
            vote.mul(vote.sub(&one)).enforce_equal(&zero)?;

            // 4. compute result, ∑ vᵢ ⋅ wᵢ = R
            comp_result += vote.clone(); // WIP to be add weight (votes[i] * weight[i])

            // 5. ensure that there are no repeated Voter pks (nullifier) TODO
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec_blind_signatures::poseidon_setup_params;
    use ark_relations::r1cs::ConstraintSystem;

    use crate::{Authority, BlindOVOTE, Curve, EthWallet, Fq, One, VotePackage};
    use ark_std::Zero;

    async fn gen_vote_packages<const N_VOTERS: usize>(
        bo: &BlindOVOTE,
    ) -> (Authority, [VotePackage; N_VOTERS], Fq) {
        let mut rng = ark_std::test_rng();

        let mut authority = bo.new_authority(&mut rng, Vec::new());

        let mut vote_packages: Vec<VotePackage> = Vec::new();
        let mut result: Fq = Fq::zero();
        for i in 0..N_VOTERS {
            let voter_eth_wallet = EthWallet::new(&mut rng);
            let mut voter = bo.new_voter(&mut rng, voter_eth_wallet);

            let msg = Fr::one();
            let auth_msg = voter.new_auth_msg(msg).await.unwrap();

            // Voter requests blind parameters to the Authority
            let signer_r = authority.new_request_params(&mut rng, auth_msg).unwrap();
            let auth_msg = voter.blind(&mut rng, signer_r).await.unwrap();

            let s_blinded = authority.blind_sign(auth_msg).unwrap();

            // Voter unblinds the authority signature
            let s_auth = voter.unblind(s_blinded);

            // Voter builds vote_package
            let vote = Fq::one();
            let vp = voter.new_vote_package(&mut rng, &s_auth, vote).unwrap();

            vote_packages.push(vp.clone());

            // verify blind signature
            let verified = BlindOVOTE::verify_authority_sig(
                &bo.params,
                vp.pk_v, // Voter pk
                // weight,
                vp.sig_a,             // Authority sig over Voter's pk
                authority.public_key, // Authority pk
            );
            assert!(verified);

            // verify Voter signature
            let verified = BlindOVOTE::verify_voter_sig(
                &bo.params, vp.vote,  // vote being signed
                vp.sig_v, // Voter sig over vote value
                vp.pk_v,  // Voter pk
            );
            assert!(verified);

            result += vp.vote;
        }
        let vps: [VotePackage; N_VOTERS] = vote_packages.try_into().unwrap();
        (authority, vps, result)
    }

    async fn gen_test_data<const N_AUTHS: usize, const N_VOTERS: usize>(
    ) -> BlindOVOTECircuit<N_AUTHS, N_VOTERS> {
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);

        let bo = BlindOVOTE::setup(poseidon_params);

        let (authority, vote_packages, result) = gen_vote_packages::<N_VOTERS>(&bo).await;

        let circuit = BlindOVOTECircuit::<N_AUTHS, N_VOTERS> {
            params: bo.params.clone(),

            // public inputs
            chain_id: Some(Fq::one()),
            process_id: Some(Fq::one()),
            result: Some(result),
            pks_a: Some([authority.public_key; N_AUTHS]), // WIP

            // private inputs
            vote_packages: Some(vote_packages),
        };
        circuit
    }

    #[tokio::test]
    async fn test_constraint_system() {
        const N_AUTHS: usize = 1;
        const N_VOTERS: usize = 3;
        let circuit = gen_test_data::<N_AUTHS, N_VOTERS>().await;

        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        println!(
            "n_voters={:?}, num_cnstraints={:?}",
            N_VOTERS,
            cs.num_constraints()
        );
    }

    #[tokio::test]
    async fn test_blind_ovote_circuit() {
        const N_AUTHS: usize = 1;
        const N_VOTERS: usize = 3;
        let circuit = gen_test_data::<N_AUTHS, N_VOTERS>().await;
        let circuit_cs = circuit.clone();

        use ark_bn254::Bn254;
        use ark_groth16::Groth16;
        use ark_snark::SNARK;
        let mut rng = ark_std::test_rng();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_cs, &mut rng).unwrap();
        assert_eq!(vk.gamma_abc_g1.len(), 3 + 2 * N_AUTHS + 1);

        let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let public_inputs = circuit.public_inputs();

        let valid_proof = Groth16::verify(&vk, &public_inputs, &proof).unwrap();
        assert!(valid_proof);
    }
}

use crate::{check_vote_packages_sorted, sort_vote_packages, Fq, Fr, Parameters, VotePackage};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
type ConstraintF = Fq;

use ark_ec::ProjectiveCurve;
use ark_ec_blind_signatures::schnorr_blind::{
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
use ark_std::str::FromStr;
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
    pub vote_packages: Option<Vec<VotePackage>>,
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
        let mut prev_nullifier: FpVar<ConstraintF> = FpVar::Constant(Fp256::from(1));
        for vote_package in vote_packages.iter().take(N_VOTERS) {
            // 1. verify Authority blind signatures over Voters public keys
            const AUTHORITY_MSG_LEN: usize = 4;
            let msg = MsgVar::<AUTHORITY_MSG_LEN, EdwardsProjective, EdwardsVar>::new([
                chain_id.clone(),
                process_id.clone(),
                vote_package.pk_v.pub_key.x.clone(),
                vote_package.pk_v.pub_key.y.clone(),
            ]);
            let v =
                BlindSigVerifyGadget::<AUTHORITY_MSG_LEN, EdwardsProjective, EdwardsVar>::verify(
                    &blind_params,
                    &poseidon_hash,
                    &msg,
                    &vote_package.sig_a, // WIP
                    &authority_pks[0],   // WIP
                )?;
            v.enforce_equal(&Boolean::TRUE)?;

            // 2. verify Voters signatures (non-blind) over vote value
            const VOTER_MSG_LEN: usize = 3;
            let msg = MsgVar::<VOTER_MSG_LEN, EdwardsProjective, EdwardsVar>::new([
                chain_id.clone(),
                process_id.clone(),
                vote_package.vote.clone(),
            ]);
            let v = BlindSigVerifyGadget::<VOTER_MSG_LEN, EdwardsProjective, EdwardsVar>::verify(
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

            // 5. ensure that there are no repeated Voter pks (nullifier).
            // The approach for ensuring non-repeated user public keys can be found in the
            // Blind-OVOTE document, on section 3.2.1.
            let to_hash = [
                chain_id.clone(),
                process_id.clone(),
                vote_package.pk_v.pub_key.x.clone(),
                vote_package.pk_v.pub_key.y.clone(),
            ];
            let nullifier = poseidon_hash.hash(&to_hash)?; // Note: this hash is already done for sig_A verification, update ark-ec-blind-signatures to reuse the hash

            let n = Nullifier(nullifier.clone());
            let prev_n = Nullifier(prev_nullifier.clone());
            let is_smaller = prev_n.less_than(&n);
            is_smaller.enforce_equal(&Boolean::TRUE)?;

            let prev_nullifier = nullifier.clone();
        }
        Ok(())
    }
}

pub struct Nullifier(pub FpVar<ConstraintF>);
impl Nullifier {
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn less_than(&self, other: &Self) -> Boolean<ConstraintF> {
        // The trick used in this method is an adaptation from circomlib trick for LessThan
        // circuit: https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom#L62
        // We explain it in the Blind-OVOTE document, in the last part of section 3.2.1.

        let one: FpVar<ConstraintF> = FpVar::Constant(Fp256::from(1));
        let n = 252_usize; // 252 = ConstraintF max .num_bits - 1

        // Note: nullifiers should be cropped to be less or equal to 252 bits length
        let self_bits = self.0.to_bits_le().unwrap();
        let other_bits = other.0.to_bits_le().unwrap();

        let self_252 = Boolean::le_bits_to_fp_var(&self_bits[..n]).unwrap();
        let other_252 = Boolean::le_bits_to_fp_var(&other_bits[..n]).unwrap();

        let upper = FpVar::Constant(
            Fp256::from_str(
                //  1<<252 (for 252 bits), where 252 = ConstraintF max num_bits - 1
                "7237005577332262213973186563042994240829374041602535252466099000494570602496",
            )
            .unwrap(),
        );
        let c = self_252 + upper - other_252;
        let c_bits = c.to_bits_le().unwrap();
        c_bits[n].not()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec_blind_signatures::schnorr_blind::poseidon_setup_params;
    use ark_relations::r1cs::ConstraintSystem;

    use crate::{Authority, BlindOVOTE, Curve, EthWallet, Fq, One, VotePackage};
    use ark_std::Zero;

    async fn gen_vote_packages<const N_VOTERS: usize>(
        bo: &BlindOVOTE,
        chain_id: Fq,
        process_id: Fq,
    ) -> (Authority, Vec<VotePackage>, Fq) {
        let mut rng = ark_std::test_rng();

        let mut authority = bo.new_authority(&mut rng, Vec::new());

        let mut vote_packages: Vec<VotePackage> = Vec::new();
        let mut result: Fq = Fq::zero();
        for i in 0..N_VOTERS {
            let voter_eth_wallet = EthWallet::new(&mut rng);
            let mut voter = bo.new_voter(&mut rng, chain_id, voter_eth_wallet);

            let msg = Fr::one();
            let auth_msg = voter.new_auth_msg(msg).await.unwrap();

            // Voter requests blind parameters to the Authority
            let signer_r = authority.new_request_params(&mut rng, auth_msg).unwrap();
            let auth_msg = voter
                .blind(&mut rng, process_id, authority.public_key, signer_r)
                .await
                .unwrap();

            let s_blinded = authority.blind_sign(auth_msg).unwrap();

            // Voter unblinds the authority signature
            let s_auth = voter.unblind(s_blinded);

            // Voter builds vote_package
            let vote = Fq::one();
            let vp = voter
                .new_vote_package(&mut rng, process_id, &s_auth, vote)
                .unwrap();

            vote_packages.push(vp.clone());

            // verify blind signature
            let verified = BlindOVOTE::verify_authority_sig(
                &bo.params,
                chain_id,
                process_id,
                vp.pk_v, // Voter pk
                // weight,
                vp.sig_a,             // Authority sig over Voter's pk
                authority.public_key, // Authority pk
            );
            assert!(verified);

            // verify Voter signature
            let verified = BlindOVOTE::verify_voter_sig(
                &bo.params, chain_id, process_id, vp.vote,  // vote being signed
                vp.sig_v, // Voter sig over vote value
                vp.pk_v,  // Voter pk
            );
            assert!(verified);

            result += vp.vote;
        }
        // sort vote_packages by nullifier
        let vote_packages_sorted =
            sort_vote_packages(bo.params.hash.clone(), chain_id, process_id, vote_packages);
        assert!(check_vote_packages_sorted(
            bo.params.hash.clone(),
            chain_id,
            process_id,
            vote_packages_sorted.clone()
        ));

        (authority, vote_packages_sorted, result)
    }

    async fn gen_test_data<const N_AUTHS: usize, const N_VOTERS: usize>(
    ) -> BlindOVOTECircuit<N_AUTHS, N_VOTERS> {
        let chain_id = Fq::from(42);
        let process_id = Fq::from(1);
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 5);

        let bo = BlindOVOTE::setup(poseidon_params);

        let (authority, vote_packages, result) =
            gen_vote_packages::<N_VOTERS>(&bo, chain_id, process_id).await;

        let circuit = BlindOVOTECircuit::<N_AUTHS, N_VOTERS> {
            params: bo.params.clone(),

            // public inputs
            chain_id: Some(chain_id),
            process_id: Some(process_id),
            result: Some(result),
            pks_a: Some([authority.public_key; N_AUTHS]), // WIP

            // private inputs
            vote_packages: Some(vote_packages),
        };
        circuit
    }

    #[test]
    fn test_nullifier_less_than() {
        let a: Nullifier = Nullifier(FpVar::Constant(Fp256::from(35)));
        let b: Nullifier = Nullifier(FpVar::Constant(Fp256::from(36)));
        let r = a.less_than(&b);
        assert_eq!(r, Boolean::TRUE);
        let r = b.less_than(&a);
        assert_eq!(r, Boolean::FALSE);

        let a: Nullifier = Nullifier(FpVar::Constant(Fp256::from(36)));
        let b: Nullifier = Nullifier(FpVar::Constant(Fp256::from(36)));
        let r = a.less_than(&b);
        assert_eq!(r, Boolean::FALSE);

        let a: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "3881967462682375489551153299716698538183749083234973749905987531968358459485",
            )
            .unwrap(),
        ));
        let b: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "3881967462682375489551153299716698538183749083234973749905987531968358459486",
            )
            .unwrap(),
        ));
        let r = a.less_than(&b);
        assert_eq!(r, Boolean::TRUE);
        let r = b.less_than(&a);
        assert_eq!(r, Boolean::FALSE);

        // note: in this case, although a>b, when comparing the first 252 bits of a & b, a<b.
        let a: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "10601522748347301882190920919472579195149194487170401972607812044001636589468",
            )
            .unwrap(),
        ));
        let b: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "3881967462682375489551153299716698538183749083234973749905987531968358459486",
            )
            .unwrap(),
        ));
        let r = a.less_than(&b);
        assert_eq!(r, Boolean::TRUE);
        let r = b.less_than(&a);
        assert_eq!(r, Boolean::FALSE);

        let a: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            )
            .unwrap(),
        ));
        let b: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                // Note: does not overflow BN254's Fr, because we're using the Fp256 type
                "21888242871839275222246405745257275088548364400416034343698204186575808495618",
            )
            .unwrap(),
        ));
        let r = a.less_than(&b);
        assert_eq!(r, Boolean::TRUE);
        let r = b.less_than(&a);
        assert_eq!(r, Boolean::FALSE);

        let a: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "7237005577332262213973186563042994240829374041602535252466099000494570602496",
            )
            .unwrap(),
        ));
        let b: Nullifier = Nullifier(FpVar::Constant(
            Fp256::from_str(
                "7237005577332262213973186563042994240829374041602535252466099000494570602497",
            )
            .unwrap(),
        ));
        let r = a.less_than(&b);
        assert_eq!(r, Boolean::TRUE);
        let r = b.less_than(&a);
        assert_eq!(r, Boolean::FALSE);
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
            "n_voters={:?}, num_constraints={:?}",
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

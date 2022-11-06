#![allow(unused)] // TMP

use ark_ec_blind_signatures::{
    BlindSigScheme, BlindedSignature, Parameters as BlindParameters, PublicKey, SecretKey,
    Signature, UserSecretData,
};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_std::{rand::Rng, One, UniformRand};
use arkworks_native_gadgets::poseidon;

use arkworks_utils::Curve;

use ethers::signers::{LocalWallet as EthWallet, Signer as EthSigner};
use ethers::types::{Address as EthAddress, Signature as EthSignature};

type Fq = ark_ed_on_bn254::Fq; // base field
type Fr = ark_ed_on_bn254::Fr; // scalar field
type S = BlindSigScheme<EdwardsProjective>;

pub struct Authority {
    secret_key: SecretKey<EdwardsProjective>,
    public_key: PublicKey<EdwardsProjective>,
    list_ethaddrs: Vec<EthAddress>,
}

impl Authority {
    pub fn new<R: Rng>(params: &Parameters, rng: &mut R, list_ethaddrs: Vec<EthAddress>) -> Self {
        let (pk, sk) = S::keygen(&params.blind_params, rng);
        Self {
            secret_key: sk,
            public_key: pk,
            list_ethaddrs,
        }
    }
    fn ethaddr_in_list(&self, ethaddr: EthAddress) -> bool {
        unimplemented!();
    }
    pub fn new_request_params<R: Rng>(&self, rng: &mut R) -> EdwardsAffine {
        unimplemented!();
    }
    pub fn blind_sign(&self) -> BlindedSignature<EdwardsProjective> {
        unimplemented!();
    }
}

pub struct Voter {
    eth_wallet: EthWallet,
    secret_key: SecretKey<EdwardsProjective>,
    public_key: PublicKey<EdwardsProjective>,
    secret_data: UserSecretData<EdwardsProjective>, // data related to the blinded message
}

impl Voter {
    pub fn new<R: Rng>(params: &Parameters, rng: &mut R) -> Self {
        unimplemented!();
    }

    pub fn blind(&self) -> Fr {
        // TODO
        // blind public_key + [weight (?)]
        // compute EthSignature

        unimplemented!();
    }

    pub fn unblind(&self, s_blinded: Fr) -> Signature<EdwardsProjective> {
        unimplemented!();
    }
}

pub struct Parameters {
    blind_params: BlindParameters<EdwardsProjective>,
    hash: poseidon::Poseidon<Fq>,
    bs: BlindSigScheme<EdwardsProjective>,
}

pub struct BlindOVOTE {
    params: Parameters,
}

impl BlindOVOTE {
    pub fn setup() -> Self {
        unimplemented!();
    }
    pub fn new_authority<R: Rng>(&self, rng: &mut R, list_ethaddrs: Vec<EthAddress>) -> Authority {
        Authority::new(&self.params, rng, list_ethaddrs)
    }
    pub fn new_voter<R: Rng>(&self, rng: &mut R) -> Voter {
        Voter::new(&self.params, rng)
    }
    pub fn verify_blind_sig(
        params: &Parameters,
        pk_voter: PublicKey<EdwardsProjective>,
        weight: Fq,
        s_auth: Signature<EdwardsProjective>,
        pk_auth: PublicKey<EdwardsProjective>,
    ) -> bool {
        let msg: [Fq; 3] = [pk_voter.x, pk_voter.y, weight];
        S::verify(&params.blind_params, &params.hash, &msg, s_auth, pk_auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec_blind_signatures::poseidon_setup_params;

    #[test]
    fn test_flow() {
        unimplemented!();
    }
}

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
    blind_params: BlindParameters<EdwardsProjective>,
    hash: poseidon::Poseidon<Fq>,

    secret_key: SecretKey<EdwardsProjective>,
    public_key: PublicKey<EdwardsProjective>,
    list_ethaddrs: Vec<EthAddress>,
}

pub struct EthAuthenticatedMsg {
    msg: Fr,
    ethaddr: EthAddress,
    ethsig: EthSignature,
}
impl EthAuthenticatedMsg {
    fn check(&self) -> bool {
        // verifies signature
        unimplemented!();
    }
}

impl Authority {
    pub fn new<R: Rng>(params: &Parameters, rng: &mut R, list_ethaddrs: Vec<EthAddress>) -> Self {
        let (pk, sk) = S::keygen(&params.blind_params, rng);
        Self {
            blind_params: params.blind_params.clone(), // WIP
            hash: params.hash.clone(),                 // WIP
            secret_key: sk,
            public_key: pk,
            list_ethaddrs,
        }
    }
    fn ethaddr_in_list(&self, ethaddr: EthAddress) -> bool {
        unimplemented!();
    }
    fn authenticate(&self, auth: EthAuthenticatedMsg) -> bool {
        // verify eth signature
        let check1 = auth.check();
        // check that ethaddr is in Authority's list
        let check2 = self.ethaddr_in_list(auth.ethaddr);
        unimplemented!();
    }
    pub fn new_request_params<R: Rng>(
        &self,
        rng: &mut R,
        auth: EthAuthenticatedMsg,
    ) -> EdwardsAffine {
        let (k, signer_r) = S::new_request_params(&self.blind_params, rng);
        // TODO authenticate voter EthAddress
        // auth.check(auth.ethaddr);
        // TODO store k in db/kv
        signer_r
    }
    pub fn blind_sign(&self, auth_msg: EthAuthenticatedMsg) -> BlindedSignature<EdwardsProjective> {
        // TODO authenticate voter EthAddress
        // TODO k would be retrieved from db/kv
        let k: Fr = Fr::one();
        let s_blinded = S::blind_sign(self.secret_key, k, auth_msg.msg);
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

    pub fn new_auth_msg(&self, msg: Fr) -> EthAuthenticatedMsg {
        // TODO EthSign over msg
        // let auth_msg = EthAuthenticatedMsg { msg: msg };
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
    fn test_single_voter_flow() {
        let mut rng = ark_std::test_rng();
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);

        let bo = BlindOVOTE::setup();

        let authority = bo.new_authority(&mut rng, Vec::new());
        let voter = bo.new_voter(&mut rng);
        let weight = Fq::from(5_u64);

        let msg = Fr::one();
        let auth_msg = voter.new_auth_msg(msg);

        // Voter requests blind parameters to the Authority
        let signer_r = authority.new_request_params(&mut rng, auth_msg);
        let m_blinded = voter.blind();

        let auth_msg = voter.new_auth_msg(m_blinded);
        let s_blinded = authority.blind_sign(auth_msg);

        let s_auth = voter.unblind(s_blinded);

        let verified = BlindOVOTE::verify_blind_sig(
            &bo.params,
            voter.public_key,
            weight,
            s_auth,
            authority.public_key,
        );
        assert!(verified);
    }
}

#![allow(unused)] // TMP

use ark_ec_blind_signatures::{
    BlindSigScheme, BlindedSignature, Parameters as BlindParameters, PublicKey, SecretKey,
    Signature, UserSecretData,
};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_std::{rand::Rng, One, UniformRand};
use arkworks_native_gadgets::poseidon;

use arkworks_utils::Curve;

use ethers::prelude::WalletError as EthWalletError;
use ethers::signers::{LocalWallet as EthWallet, Signer as EthSigner};
use ethers::types::{
    Address as EthAddress, Signature as EthSignature, SignatureError as EthSignatureError, U256,
};

use std::collections::HashMap;

type Fq = ark_ed_on_bn254::Fq; // base field
type Fr = ark_ed_on_bn254::Fr; // scalar field
type S = BlindSigScheme<EdwardsProjective>;

pub struct Authority {
    blind_params: BlindParameters<EdwardsProjective>,
    hash: poseidon::Poseidon<Fq>,

    secret_key: SecretKey<EdwardsProjective>,
    public_key: PublicKey<EdwardsProjective>,
    list_ethaddrs: Vec<EthAddress>, // allowed eth_addrs
    req_params_db: HashMap<EthAddress, Fr>,
}

#[derive(Clone, Debug)]
pub struct EthAuthenticatedMsg {
    msg: Fr,
    ethaddr: EthAddress,
    ethsig: EthSignature,
}
impl EthAuthenticatedMsg {
    fn check(&self) -> Result<(), EthSignatureError> {
        // verifies eth signature
        self.ethsig.verify(self.msg.to_string(), self.ethaddr)
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
            req_params_db: HashMap::new(),
        }
    }
    fn ethaddr_in_list(&self, ethaddr: EthAddress) -> bool {
        // TODO
        unimplemented!();
    }
    fn authenticate(&self, auth_msg: EthAuthenticatedMsg) -> Result<(), EthSignatureError> {
        // verify eth signature
        auth_msg.check()?;

        // TODO check that ethaddr is in Authority's list
        // let check2 = self.ethaddr_in_list(auth_msg.ethaddr);
        Ok(())
    }
    pub fn new_request_params<R: Rng>(
        &mut self,
        rng: &mut R,
        auth_msg: EthAuthenticatedMsg,
    ) -> Result<EdwardsAffine, EthSignatureError> {
        // WIP: the ethsigned msg would come from a previous challenge from Authority to Voter,
        // which would be the msg signed for the auth_msg

        // authenticate voter EthAddress
        self.authenticate(auth_msg.clone())?;

        let (k, signer_r) = S::new_request_params(&self.blind_params, rng);

        // store k in db/kv
        self.req_params_db.insert(auth_msg.ethaddr, k);

        Ok(signer_r)
    }
    pub fn blind_sign(
        &self,
        auth_msg: EthAuthenticatedMsg,
    ) -> Result<BlindedSignature<EdwardsProjective>, EthSignatureError> {
        // authenticate voter EthAddress
        self.authenticate(auth_msg.clone())?;

        // retreive k from db/kv
        let k = self.req_params_db.get(&auth_msg.ethaddr).unwrap();
        let s_blinded = S::blind_sign(self.secret_key, *k, auth_msg.msg);

        Ok(s_blinded)
    }
}

pub struct Voter {
    params: Parameters,
    eth_wallet: EthWallet,
    secret_key: SecretKey<EdwardsProjective>,
    public_key: PublicKey<EdwardsProjective>,
    secret_data: Option<UserSecretData<EdwardsProjective>>, // data related to the blinded message
}

impl Voter {
    pub fn new<R: Rng>(params: Parameters, rng: &mut R, eth_wallet: EthWallet) -> Self {
        let (pk, sk) = S::keygen(&params.blind_params, rng);
        Self {
            params,
            eth_wallet,
            secret_key: sk,
            public_key: pk,
            secret_data: None,
        }
    }

    pub async fn new_auth_msg(&self, msg: Fr) -> Result<EthAuthenticatedMsg, EthWalletError> {
        // EthSign over msg
        // TODO msg as bytes instead of string
        let eth_sig = self.eth_wallet.sign_message(msg.to_string()).await?;
        Ok(EthAuthenticatedMsg {
            msg,
            ethaddr: self.eth_wallet.address(),
            ethsig: eth_sig,
        })
    }

    pub async fn blind<R: Rng>(
        &mut self,
        rng: &mut R,
        signer_r: EdwardsAffine,
    ) -> Result<EthAuthenticatedMsg, EthWalletError> {
        // blind public_key + [weight (?)]
        let (m_blinded, u) = S::blind(
            &self.params.blind_params,
            rng,
            &self.params.hash,
            &[self.public_key.x, self.public_key.y], // TODO add weight
            signer_r,
        )
        .unwrap();
        self.secret_data = Some(u);

        // compute auth_msg (which includes m_blinded with the ethsignature)
        let auth_msg = self.new_auth_msg(m_blinded).await?;
        Ok(auth_msg)
    }

    pub fn unblind(&self, s_blinded: Fr) -> Signature<EdwardsProjective> {
        S::unblind(s_blinded, self.secret_data.as_ref().unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct Parameters {
    blind_params: BlindParameters<EdwardsProjective>,
    hash: poseidon::Poseidon<Fq>,
}

pub struct BlindOVOTE {
    params: Parameters,
}

impl BlindOVOTE {
    pub fn setup(poseidon_params: poseidon::PoseidonParameters<Fq>) -> Self {
        let poseidon_hash = poseidon::Poseidon::new(poseidon_params);

        Self {
            params: Parameters {
                blind_params: S::setup(),
                hash: poseidon_hash,
            },
        }
    }
    pub fn new_authority<R: Rng>(&self, rng: &mut R, list_ethaddrs: Vec<EthAddress>) -> Authority {
        Authority::new(&self.params, rng, list_ethaddrs)
    }
    pub fn new_voter<R: Rng>(&self, rng: &mut R, eth_wallet: EthWallet) -> Voter {
        Voter::new(self.params.clone(), rng, eth_wallet)
    }
    pub fn verify_blind_sig(
        params: &Parameters,
        pk_voter: PublicKey<EdwardsProjective>,
        // weight: Fq,
        s_auth: Signature<EdwardsProjective>,
        pk_auth: PublicKey<EdwardsProjective>,
    ) -> bool {
        // let msg: [Fq; 3] = [pk_voter.x, pk_voter.y, weight];
        let msg: [Fq; 2] = [pk_voter.x, pk_voter.y];
        S::verify(&params.blind_params, &params.hash, &msg, s_auth, pk_auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec_blind_signatures::poseidon_setup_params;

    #[tokio::test]
    async fn test_auth_msg() {
        let mut rng = ark_std::test_rng();
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);
        let bo = BlindOVOTE::setup(poseidon_params);
        let voter_eth_wallet = EthWallet::new(&mut rng);
        let voter = bo.new_voter(&mut rng, voter_eth_wallet);

        let msg = Fr::from(42_u64);
        let mut auth_msg = voter.new_auth_msg(msg).await.unwrap();
        // verify augh_msg signature
        auth_msg.check().unwrap();

        // now with an invalid msg for the signature, it should return an error
        auth_msg.msg = Fr::from(41_u64);
        auth_msg.check().unwrap_err();
    }

    #[tokio::test]
    async fn test_single_voter_flow() {
        let mut rng = ark_std::test_rng();
        let poseidon_params = poseidon_setup_params::<Fq>(Curve::Bn254, 5, 4);

        let bo = BlindOVOTE::setup(poseidon_params);

        let mut authority = bo.new_authority(&mut rng, Vec::new());

        let voter_eth_wallet = EthWallet::new(&mut rng);
        // let weight = Fq::from(5_u64);
        let mut voter = bo.new_voter(&mut rng, voter_eth_wallet);

        let msg = Fr::one();
        let auth_msg = voter.new_auth_msg(msg).await.unwrap();

        // Voter requests blind parameters to the Authority
        let signer_r = authority.new_request_params(&mut rng, auth_msg).unwrap();
        let auth_msg = voter.blind(&mut rng, signer_r).await.unwrap();

        let s_blinded = authority.blind_sign(auth_msg).unwrap();

        let s_auth = voter.unblind(s_blinded);

        let verified = BlindOVOTE::verify_blind_sig(
            &bo.params,
            voter.public_key,
            // weight,
            s_auth,
            authority.public_key,
        );
        assert!(verified);
    }
}

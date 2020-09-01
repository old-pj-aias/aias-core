use crate::crypto::RSAPubKey;


use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter, EncryptedMessage, Unblinder };

use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


pub struct Signer {
    pub signer: FBSSigner<RSAPubKey>
}

impl Signer {
    pub fn new(signer_privkey: String, signer_pubkey: String, judge_pubkey: String) -> Self {
        let signer_privkey = pem::parse(signer_privkey).expect("failed to parse signer private key pem");
        let signer_privkey = RSAPrivateKey::from_pkcs1(&signer_privkey.contents).expect("failed to parse signer private key pkcs1");

        let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse signer public key pem");
        let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse signer public key pkcs8");

        let judge_pubkey = pem::parse(judge_pubkey).expect("failed to parse judge public keypem");
        let judge_pubkey = RSAPublicKey::from_pkcs8(&judge_pubkey.contents).expect("failed to parse judge public keypkcs8");

        let judge_pubkey = RSAPubKey {
            public_key: judge_pubkey
        };

        let parameters = FBSParameters {
            signer_pubkey: signer_pubkey,
            judge_pubkey: judge_pubkey,
            k: 40,
            id: 10
        };

        Signer {
            signer: FBSSigner::new(parameters, signer_privkey)
        }
    }

    pub fn new_from_params(signer_privkey: String, signer_pubkey: String, judge_pubkey: String, blinded_digest: String, subset: String) -> Self {
        let mut signer = Signer::new(signer_privkey, signer_pubkey, judge_pubkey);
        signer.signer.subset = Some(serde_json::from_str(&subset).unwrap());
        signer.signer.blinded_digest = Some(serde_json::from_str(&blinded_digest).unwrap());

        signer
    }

    pub fn set_blinded_digest(&mut self, blinded_digest: String) -> serde_json::Result<()> {
        let data: BlindedDigest = serde_json::from_str(&blinded_digest)?;

        self.signer.set_blinded_digest(data);

        Ok(())
    }

    pub fn setup_subset(&mut self) -> String {
        let subset = self.signer.setup_subset();
        serde_json::to_string(&subset).unwrap()
    }

    pub fn check(&mut self, check_parameter: String) -> bool {
        let check_parameter: CheckParameter = serde_json::from_str(&check_parameter).expect("failed to parse json");
        self.signer.check(check_parameter)
    }

    pub fn sign(&self) -> String {
        let signature = self.signer.sign().unwrap();

        serde_json::to_string(&signature)
            .unwrap()
    }
}

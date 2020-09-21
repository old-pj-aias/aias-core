use crate::crypto::RSAPubKey;
use crate::DEFAULT_K;

use fair_blind_signature::{FBSParameters, FBSVerifyer, Signature, VerifyError};

use rsa::RSAPublicKey;

pub fn verify(
    signature: String,
    message: String,
    signer_pubkey: String,
    judge_pubkeys: String,
) -> Result<(), VerifyError> {
    let signature: Signature = serde_json::from_str(&signature).expect("Parsing json error");

    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey =
        RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkey = pem::parse(judge_pubkeys).expect("failed to parse pem");
    let judge_pubkey =
        RSAPublicKey::from_pkcs8(&judge_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkey = RSAPubKey {
        public_key: judge_pubkey,
    };

    let k = DEFAULT_K;
    let id = 114514; // this id is just placeholder

    let parameters = FBSParameters {
        signer_pubkey,
        judge_pubkey,
        k,
        id,
    };

    let verifyer = FBSVerifyer::new(parameters);
    verifyer.verify(signature, message)
}

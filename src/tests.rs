use crate::crypto::TestCipherPubkey;
use crate::client;
use crate::server;


use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


fn generate_signer() -> FBSSigner<TestCipherPubkey> {
    let n = BigUint::from(882323119 as u32);
    let e = BigUint::from(7 as u32);
    let d = BigUint::from(504150583 as u32);
    let primes = [BigUint::from(27409 as u32), BigUint::from(32191 as u32)].to_vec();

    let signer_pubkey = RSAPublicKey::new(n.clone(), e.clone()).unwrap();
    let signer_privkey = RSAPrivateKey::from_components(n, e, d, primes);

    let judge_pubkey = TestCipherPubkey {};

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkey,
        k: 40,
        id: 10
    };
    
    FBSSigner::new(parameters.clone(), signer_privkey)
}


#[test]
fn test_init_and_destroy() {
    client::new();
    server::new();

    let mut signer = generate_signer();
    
    let blinded_digest = client::blind("aaa".to_string());
    server::set_blinded_digest(blinded_digest.clone());

    let blinded_digest: BlindedDigest = serde_json::from_str(&blinded_digest).expect("Parsing json error");
    signer.set_blinded_digest(blinded_digest);

    let subset = signer.setup_subset();
    let serialized = serde_json::to_string(&subset).unwrap();
    
    client::set_subset(serialized);

    let check_parameters = client::generate_check_parameters();
    let check_parameters: CheckParameter = serde_json::from_str(&check_parameters).expect("Parsing json error");

    signer.check(check_parameters);

    let blind_signature = signer.sign().unwrap();
    let blind_signature = serde_json::to_string(&blind_signature).unwrap();
    let signature = client::unblind(blind_signature);

    client::destroy();
    server::destroy();
}

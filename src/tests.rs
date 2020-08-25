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

    let blinded_digest = client::blind("aaa".to_string());
    server::set_blinded_digest(blinded_digest.clone());

    let subset = server::setup_subset();
    client::set_subset(subset);

    let check_parameters = client::generate_check_parameters();
    server::check(check_parameters.clone());

    let blind_signature = server::sign();
    let signature = client::unblind(blind_signature);
    
    client::destroy();
    server::destroy();
}

use crate::crypto::TestCipherPubkey;
use crate::signer;
use crate::sender;
use crate::verifyer;


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
    sender::new();
    signer::new();
    verifyer::new_verifyer();

    let blinded_digest = sender::blind("aaa".to_string());
    signer::set_blinded_digest(blinded_digest.clone());

    let subset = signer::setup_subset();
    sender::set_subset(subset);

    let check_parameters = sender::generate_check_parameters();
    signer::check(check_parameters.clone());

    let blind_signature = signer::sign();
    let signature = sender::unblind(blind_signature);
    
    sender::destroy();
    signer::destroy();
    verifyer::destroy_verifyer();
}

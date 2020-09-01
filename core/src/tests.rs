use crate::crypto::{RSAPubKey, DistributedRSAPrivKey};
use crate::judge;
use crate::signer::{Signer, EjAndId};
use crate::sender;
use crate::verifyer;

use crate::utils;
use crate::crypto;

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};



#[test]
fn test_all() {
    let pk1 = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxXo2zWkciUEZBcm/Exk8
Zac8NWskP59EAVFlO218xIXOV0FfphPB/tnbQh7GDXddo7XVEptHdHXyJlXXLihb
9vXbUZF2NDFLOhgDv7pa72VNLbw+jKR/FlsDtwv/bv7ZDqq+n79uavuJ8giX3qCf
+mtBmro7hG5AVve3JImhvA0FvTKJ0xCYUYw02st08He5RwFAXQK8G2cwahp+5ECH
MDdfFUaoxMfRN/+Hl9iqiJovKUJQ3545N2fDYdd0eqSlqL1N5xJxYX1GDMtGZgME
hHR6ntdfm7r43HDB4hk/MJIsNay6+K9tJBiz1qXG40G4NjMKzVrX9pi1Bv8G2RnP
/wIDAQAB
-----END PUBLIC KEY-----"#;

    let sk1 = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxXo2zWkciUEZBcm/Exk8Zac8NWskP59EAVFlO218xIXOV0Ff
phPB/tnbQh7GDXddo7XVEptHdHXyJlXXLihb9vXbUZF2NDFLOhgDv7pa72VNLbw+
jKR/FlsDtwv/bv7ZDqq+n79uavuJ8giX3qCf+mtBmro7hG5AVve3JImhvA0FvTKJ
0xCYUYw02st08He5RwFAXQK8G2cwahp+5ECHMDdfFUaoxMfRN/+Hl9iqiJovKUJQ
3545N2fDYdd0eqSlqL1N5xJxYX1GDMtGZgMEhHR6ntdfm7r43HDB4hk/MJIsNay6
+K9tJBiz1qXG40G4NjMKzVrX9pi1Bv8G2RnP/wIDAQABAoIBAC3nRMnmvw1gpnJj
/Rhxa0qt3x8Dsr9fRC2SQBfaUYBVIivCNHukaBnXhlIOWTdUId4mLEtQ8QEvUYR7
u7MtCoOTjtGdIH7tXnE4l9Z/eRfg0lnpQhjrO+d0bJ6mGVAxyT7RjdIQa5hOtDgg
qzzC1a0eNXfEBoW4IxiUKGxD2eaeL2NEuwdysO8MrxvbpPLrK4KaQwansh5EdrvL
QmWtSSuB2rYVwWbp7Rs+NuKS4w7CRm9Zp6kN6yjBum+x2o3Wdj33Ww0HayeaRZ1i
nmVTyphfajKuDLYUavCo4tBE67LK/VHesxeFNM+6PjONUVmcRnT1eoATeLVE4vOO
M9kFUQECgYEA9WD+s2HpETsXxyWPp2wv1G8b2kZq0h85Vb971PwgRciHkBccHFHR
0Hgc/hFTHg86V0iVBbcsWtTNTsNbH7aXGNvWJVQiMPDNdKmavgAl3tpGRP7iffLF
503he0GQmVaDEBH4LqCi4Ix0u7wnOND9ie8hMzxtC+2cZyLY8y13o78CgYEAzgZu
JPMgD2BvSKDJYlP7j4OKj0+mQIdpW+ONuLZsbtTDs5GiggTeeeyQDvlESUMSypMj
rmS/GUHAnYft27YWjk48vlzrvrnLyzWLalGYLsUigQIf2BRJG43j8iXuuBKciOrf
P8dkByYXatkiA57CJXOJGJLPvMOfkr+p3i2L48ECgYA9eY52HIqKoZZkczmZRVZ6
T1fYCJpMiDwSCoYYpw3izcmAxPlq8uiw5NbGpEqBlmkUYv/KzchT/UpueC0FNfaG
6NSux3RFdJ7UooU9IsZaHa9LK9xMl50TRQS/n359nBn71bSq4d3MigPY4NumtV0/
yGQ19OaQ/XeYszdNPU/i+wKBgQCXSbeGIJaRVBJD9fYL43nd+A0+kZGW3xjqJh5C
3oqflFOlQDNiYKryQ1nB9R9E4SEiaowQGuENbfBAfbmX1o2XsDIA5AElTBAvx8D5
sLMc3RwqOeIibTsGJdqWTW6P8vLJxBduIT/90+XsS0gj+me80quAxQYRKmG6hE37
3dxUwQKBgQC2onc1n35vGlZ2HxWdnPOUyRnA8HNVXcskprR07ZqFQu36LxI8hHvz
O+zc6JPZDWBppJDWot9d5HeNEjDBMcSqcpeXXYU8XvxA+uECLPctLgNMWxyKFx95
0sVQIY0n9eLL7sg5aCUpGKf4Qc88wF8OPYnBzjCeiJusjkGhQ5rqdQ==
-----END RSA PRIVATE KEY-----"#;

    let judge_pubkey = pk1.to_string();
    let judge_privkey = judge::divide_keys(sk1.to_string(), judge_pubkey.clone());

    let signer_pubkey = pk1.to_string();
    let signer_privkey = sk1.to_string();

    let message = "hoge".to_string();

    sender::new(signer_pubkey.clone(), judge_pubkey.clone(), 10);
    let ej_and_id = EjAndId {judge_pubkey: judge_pubkey.clone(), id: 10};
    let ej_and_id = serde_json::json!(ej_and_id).to_string();
    let test_map: serde_json::Value = serde_json::from_str(&ej_and_id).expect("failed to get map");

    println!("{:?}", ej_and_id);
    println!("map: {:?}", test_map);

    let mut signer = Signer::new(signer_privkey.clone(), signer_pubkey.clone(), ej_and_id.clone());

    let blinded_digest = sender::blind(message.clone());
    signer.set_blinded_digest(blinded_digest.clone()).unwrap();

    let subset = signer.setup_subset();
    sender::set_subset(subset.clone());

    let mut signer = Signer::new_from_params(signer_privkey, signer_pubkey.clone(), ej_and_id, blinded_digest, subset);


    let check_parameters = sender::generate_check_parameters();
    let is_valid = signer.check(check_parameters);
    assert!(is_valid);

    let blind_signature = signer.sign();
    let signature = sender::unblind(blind_signature);

    let result = verifyer::verify(signature.clone(), message, signer_pubkey, judge_pubkey);
    assert!(result);

    sender::destroy();

    let result = judge::open(signature, judge_privkey);

    assert_eq!(result[0].as_bytes()[0], "1".as_bytes()[0]);
    assert_eq!(result[0].as_bytes()[1], "0".as_bytes()[0]);
}

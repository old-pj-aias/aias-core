use crate::judge;
use crate::sender;
use crate::signer::Signer;
use crate::verifyer;

use fair_blind_signature::Signature;

use rsa::BigUint;

#[test]
fn test_all() {
    let (pk1, sk1) = read_keys(1);
    let judge_pubkey = pk1.clone();
    let judge_privkey = judge::divide_keys(sk1, pk1, 10);

    let (signer_pubkey, signer_privkey) = read_keys(2);

    let message = "hoge".to_string();
    let id = 10;

    sender::new(signer_pubkey.clone(), judge_pubkey.clone(), id);

    let mut signer = Signer::new(
        signer_privkey.clone(),
        signer_pubkey.clone(),
        judge_pubkey.clone(),
        id,
    );

    let blinded_digest = sender::blind(message.clone());
    signer.set_blinded_digest(blinded_digest.clone()).unwrap();

    let subset = signer.setup_subset();
    sender::set_subset(subset.clone());

    let mut signer = Signer::new_from_params(
        signer_privkey,
        signer_pubkey.clone(),
        judge_pubkey.clone(),
        id,
        blinded_digest,
        subset,
    );

    let check_parameters = sender::generate_check_parameters();
    let is_valid = signer.check(check_parameters);
    assert_eq!(is_valid, Ok(()));

    let blind_signature = signer.sign();
    let signature_str = sender::unblind(blind_signature);
    let signature: Signature = serde_json::from_str(&signature_str).unwrap();

    let encrypted_id = &signature.encrypted_id.v[0];
    let id_int: BigUint = serde_json::from_str(&encrypted_id).unwrap();

    let plain_shares = judge_privkey
        .private_key_set
        .private_keys
        .iter()
        .map(|k| {
            let share = k.generate_share(id_int.clone());
            serde_json::to_string(&share).unwrap()
        })
        .collect();

    let result = verifyer::verify(signature_str.clone(), message, signer_pubkey, judge_pubkey);
    assert_eq!(result, Ok(()));

    sender::destroy();

    let result = judge::open(plain_shares).unwrap();

    assert_eq!(&result, "10");
}

#[test]
#[ignore]
fn test_ready_params() {
    let (pk1, sk1) = read_keys(1);
    let judge_pubkey = pk1;
    let judge_privkey = judge::divide_keys(sk1, judge_pubkey.clone(), 10);

    let (pk2, sk2) = read_keys(2);
    let signer_pubkey = pk2.to_string();
    let signer_privkey = sk2.to_string();

    let message = "hoge".to_string();
    let id = 10;

    sender::new(signer_pubkey.clone(), judge_pubkey.clone(), id);

    let ready_params = sender::generate_ready_parameters(message.clone(), judge_pubkey.clone());
    let blinded_digest = sender::blind(message.clone());

    let mut signer = Signer::new_with_blinded_digest(
        signer_privkey.clone(),
        signer_pubkey.clone(),
        ready_params,
        id,
    );

    let subset = signer.setup_subset();
    sender::set_subset(subset.clone());

    let mut signer = Signer::new_from_params(
        signer_privkey,
        signer_pubkey.clone(),
        judge_pubkey.clone(),
        id,
        blinded_digest,
        subset,
    );

    let check_parameters = sender::generate_check_parameters();
    let is_valid = signer.check(check_parameters);
    assert_eq!(is_valid, Ok(()));

    let blind_signature = signer.sign();
    let signature = sender::unblind(blind_signature);

    let result = verifyer::verify(signature.clone(), message, signer_pubkey, judge_pubkey);
    assert_eq!(result, Ok(()));

    sender::destroy();

    let signature: Signature = serde_json::from_str(&signature).unwrap();
    let encrypted_id = &signature.encrypted_id.v[0];

    let id_int: BigUint = serde_json::from_str(&encrypted_id).unwrap();

    let plain_shares = judge_privkey
        .private_key_set
        .private_keys
        .iter()
        .map(|k| {
            let share = k.generate_share(id_int.clone());
            serde_json::to_string(&share).unwrap()
        })
        .collect();

    let result = judge::open(plain_shares).unwrap();

    assert_eq!(&result, "10");
}

fn read_keys(key_idx: usize) -> (String, String) {
    use std::fs::File;
    use std::io::Read;

    let pk_path = format!("./secrets/pk{}.pem", key_idx);
    let sk_path = format!("./secrets/sk{}.pem", key_idx);

    let mut pf = File::open(pk_path).unwrap();
    let mut sf = File::open(sk_path).unwrap();

    let mut pk = String::new();
    pf.read_to_string(&mut pk).unwrap();

    let mut sk = String::new();
    sf.read_to_string(&mut sk).unwrap();

    (pk, sk)
}
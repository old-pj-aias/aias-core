extern crate rsa;
extern crate rand;


use fair_blind_signature::EJPubKey;
use fair_blind_signature::EJPrivKey;
use distributed_rsa::{DistributedRSAPrivateKeySet, PlainShareSet};

use rsa::{ BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PublicKeyParts };

use serde::{ Serialize, Deserialize };

use std::str::FromStr;


pub struct DistributedRSAPrivKey {
    pub private_key_set: DistributedRSAPrivateKeySet
}

#[derive(Clone)]
pub struct RSAPubKey {
    pub public_key: RSAPublicKey
}


impl RSAPubKey {
    pub fn encrypt_core(&self, plain: BigUint) -> BigUint {
        let e = self.public_key.e();
        let n = self.public_key.n();

        return plain.modpow(e, n);
    } 
}

impl EJPubKey for RSAPubKey {
    fn encrypt(&self, plain: String) -> String  {
        let plain = BigUint::from_bytes_le(plain.as_bytes());
        let cipher = self.encrypt_core(plain);
        serde_json::to_string(&cipher).unwrap()
    }
}

impl DistributedRSAPrivKey {
    pub fn new (
            private_key: &RSAPrivateKey,
            public_key: &RSAPublicKey,
            count: u32) -> Self {

        let private_key_set = DistributedRSAPrivateKeySet::from_rsa_private_key(private_key, public_key, count, 1024).unwrap();

        DistributedRSAPrivKey { private_key_set: private_key_set }
    }

    pub fn decrypt_core(&self, cipher: BigUint) -> BigUint {
        let mut shares = Vec::new();

        for key in &self.private_key_set.private_keys {
            let share = key.generate_share(cipher.clone());
            shares.push(share);
        }

        let share_set = PlainShareSet { plain_shares: shares };
        share_set.decrypt()
    }
}

impl EJPrivKey for DistributedRSAPrivKey {
    fn decrypt(&self, cipher: String) -> String {
        let c : BigUint = serde_json::from_str(&cipher).unwrap();
        let plain = self.decrypt_core(c);
        String::from_utf8(plain.to_bytes_le()).unwrap()
    }
}



#[test]
fn test_encrypt_and_decrypt_rsa0() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let bits = 2048;
    let priv_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RSAPublicKey::from(&priv_key);

    let m = BigUint::from_bytes_le(b"!!");
    let n = pub_key.n();
    let e = pub_key.e();

    let c = m.modpow(e, n);

    let keys = DistributedRSAPrivateKeySet::from_rsa_private_key(&priv_key, &pub_key, 30, 1024).unwrap();

    let mut shares = Vec::new();
    for key in keys.private_keys {
        let share = key.generate_share(c.clone());
        shares.push(share);
    }

    let share_set = PlainShareSet { plain_shares: shares };

    let plain = share_set.decrypt();
    println!("{}", plain);

    assert_eq!(plain, m);
}


#[test]
fn test_encrypt_and_decrypt_rsa1() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let bits = 2048;

    let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);

    let data = BigUint::from_bytes_be(b"!!");
    
    let private_key = DistributedRSAPrivKey::new(&private_key, &public_key, 10);
    let public_key = RSAPubKey { public_key: public_key };

    let encrypted = public_key.encrypt_core(data.clone());
    let decrypted = private_key.decrypt_core(encrypted);

    assert_eq!(data, decrypted);
}

#[test]
fn test_encrypt_and_decrypt_rsa2() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let bits = 2048;

    let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);
    
    let private_key = DistributedRSAPrivKey::new(&private_key, &public_key, 10);
    let public_key = RSAPubKey { public_key: public_key };

    let data = "aaa".to_string();

    let encrypted = public_key.encrypt(data.clone());
    let decrypted = private_key.decrypt(encrypted);

    assert_eq!(data, decrypted);
}

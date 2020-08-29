extern crate rsa;
extern crate rand;


use fair_blind_signature::EJPubKey;
use fair_blind_signature::EJPrivKey;

use rsa::{ BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PublicKeyParts };

use serde::{ Serialize, Deserialize };
use crypto::{ symmetriccipher, buffer, aes, blockmodes };

use ::aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

pub struct DistributedRSAPubKey {
    pub public_keys: Vec<RSAPublicKey>
}

pub struct DistributedRSAPrivKey {
    pub private_keys: Vec<RSAPrivateKey>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Cipher {
    encrypted_msg: Vec<u8>,
    encrypted_key: Vec<u8>,
    iv: Vec<u8>
}

impl DistributedRSAPubKey {
    pub fn new(public_keys: Vec<RSAPublicKey>) -> Self {
        DistributedRSAPubKey {
            public_keys
        }
    }

    pub fn from_json(json_str: String) -> Self {
        use serde_json::Value;

        let pks = match serde_json::from_str(&json_str).unwrap() {
            Value::Array(arr) =>
                arr
                    .into_iter()
                    .map(|v| {
                        if let Value::String(s) = v { s }
                        else { panic!("failed to parse json") }
                    }),
            _ => panic!("failed to get judge's public key")
        };

        let public_keys = pks
            .map(|pk| {
                let pkcs8 = pem::parse(pk).expect("failed to parse pem");
                RSAPublicKey::from_pkcs8(&pkcs8.contents)
                    .expect("failed to parse pkcs8")
            })
            .collect();

        Self::new(public_keys)
    }
}


// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;


fn encrypto_aes(key: Vec<u8>, iv: Vec<u8>, plain: Vec<u8>) -> Vec<u8>{
    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();

    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 32];

    // copy message to the buffer
    let ciphertext = cipher.encrypt_vec(&plain);

    return ciphertext.to_vec();
}

fn decrypt_aes(encrypted_data: Vec<u8>, key: Vec<u8>, iv:Vec<u8>) -> Vec<u8> {
    extern crate crypto;
    extern crate rand;

    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
    cipher.decrypt_vec(&encrypted_data).unwrap()
}


#[test]
fn test_encrypt_and_decrypt_aes() {
    let mut key: Vec<u8> = (0..16).map(|_| { rand::random::<u8>() }).collect();
    let iv: Vec<u8> = (0..16).map(|_| { rand::random::<u8>() }).collect();
    let plain = "hogehoge";

    let msg = encrypto_aes(key.clone(), iv.clone(), plain.as_bytes().to_vec());
    let msg = decrypt_aes(msg, key.clone(), iv.clone());
    
    assert_eq!(msg, plain.as_bytes().to_vec());
}


fn encrypt_rsa(plain: &[u8], pubkey: RSAPublicKey) -> Vec<u8>  {
    extern crate num_bigint_dig as num_bigint;
    extern crate num_traits;

    let plain = num_bigint::BigUint::from_bytes_le(&plain);

    let e = pubkey.e();
    let e = num_bigint::BigUint::from_bytes_le(&e.to_bytes_le());

    let n = pubkey.n();
    let n = num_bigint::BigUint::from_bytes_le(&n.to_bytes_le());

    let crypto = plain.modpow(&e, &n);
    crypto.to_bytes_le()
}


fn decrypt_rsa(plain: &[u8], privkey: &RSAPrivateKey) -> Vec<u8>  {
    extern crate num_bigint_dig as num_bigint;
    extern crate num_traits;

    let plain = num_bigint::BigUint::from_bytes_le(&plain);

    let d = privkey.d();
    let d = num_bigint::BigUint::from_bytes_le(&d.to_bytes_le());

    let n = privkey.n();
    let n = num_bigint::BigUint::from_bytes_le(&n.to_bytes_le());

    let crypto = plain.modpow(&d, &n);
    crypto.to_bytes_le()
}


impl EJPubKey for DistributedRSAPubKey {
    fn encrypt(&self, plain: String) -> String {
        let mut key: Vec<u8> = (0..16).map(|_| { rand::random::<u8>() }).collect();
        let mut iv: Vec<u8> = (0..16).map(|_| { rand::random::<u8>() }).collect();

        key[0] = 0;
        iv[0] = 0;

        key[1] = 0;
        iv[1] = 0;
        
        key[2] = 0;
        iv[2] = 0;


        println!("iv: {:?}", iv);
        println!("key {:?}", key);

        let plain = plain.as_bytes();
        let msg = encrypto_aes(key.clone(), iv.clone(), plain.to_vec());
        let msg_cloned = msg.clone();

        for pubkey in self.public_keys.clone() {
            key = encrypt_rsa(&key, pubkey);
        }

        let cipher = Cipher {
           encrypted_msg: msg_cloned,
           encrypted_key: key, 
           iv: iv
        };

        serde_json::to_string(&cipher).unwrap()
    }
}

impl EJPrivKey for DistributedRSAPrivKey {
    fn decrypt(&self, cipher: String) -> String {
        let cipher: Cipher = serde_json::from_str(&cipher).expect("Parsing json error");
        
        let mut key = cipher.encrypted_key;

        for privkey in &self.private_keys {
            key = decrypt_rsa(&key, privkey);
        }

        println!("iv: {:?}", cipher.iv);
        println!("key {:?}", key);

        let plain = decrypt_aes(cipher.encrypted_msg, key, cipher.iv);
        return String::from_utf8_lossy(&plain).to_string();
    }
}
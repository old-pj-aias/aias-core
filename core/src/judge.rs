use crate::crypto::{DistributedRSAPrivKey, RSAPubKey};

use fair_blind_signature::{ Signature, Judge };
use serde_json;

use rsa::{RSAPrivateKey, RSAPublicKey, BigUint};
use std::cell::RefCell; 
use rand::rngs::OsRng;
use fair_blind_signature::EJPrivKey;
use distributed_rsa::{PlainShare,PlainShareSet};

thread_local!(static ODB: RefCell<Option<Judge<DistributedRSAPrivKey>>> = RefCell::new(None)); 


pub struct ShareSet {
    pub share_set: PlainShareSet
}

impl ShareSet {
    pub fn from_shares_vec(src: Vec<String>) -> serde_json::Result<Self> {
        let mut plain_shares = Vec::new();
        for share in &src {
            plain_shares.push(serde_json::from_str(share)?)
        }

        let share_set = PlainShareSet { plain_shares };
        Ok(ShareSet { share_set })
    }

    pub fn open_id(&self) -> Result<Vec<u8>, String> {
        let decrypted = self.share_set.decrypt();
        let decrypted_bytes = decrypted.to_bytes_le();
        /*
        let decrypted_str = String::from_utf8(decrypted_bytes)
            .map_err(|e| format!("failed to convert decrypted data into string: {}", e))?;
        
        let id_and_beta = serde_json::from_str(&decrypted_str)
            .map_err(|e| format!("failde to serde json: {}", e))?;
            */
        
        Ok(decrypted_bytes)
    }
}


pub fn divide_keys(prevkey: String, pubkey: String) -> DistributedRSAPrivKey {
    let rng = OsRng;
    let bits = 2048;

    let privkey = pem::parse(prevkey).expect("failed to parse pem");
    let privkey = RSAPrivateKey::from_pkcs1(&privkey.contents).expect("failed to parse pkcs1");

    let pubkey = pem::parse(pubkey).expect("failed to parse pem");
    let pubkey = RSAPublicKey::from_pkcs8(&pubkey.contents).expect("failed to parse pkcs8");

    let privkey = DistributedRSAPrivKey::new(&privkey, &pubkey);

    return privkey;
}

pub fn open(plain_shares: Vec<String>) -> Result<Vec<u8>, String> {
    //eprintln!("{:?}", plain_shares);
    let share_set = ShareSet::from_shares_vec(plain_shares)
        .map_err(|e| format!("failed to create share set: {}", e))?;
    share_set.open_id()
}

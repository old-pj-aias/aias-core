use fair_blind_signature::EJPubKey;
use threshold_crypto::{DecryptionShare};

#[derive(Clone)]
pub struct TestCipherPubkey {}

impl EJPubKey for TestCipherPubkey {
    fn encrypt(&self, message: String) -> String {
        return message;
    }

    fn dencrypt(&self, message: String) -> String {
        return message;
    }
}

#[derive(Clone)]
pub struct ThresholdPubKey {
    pub pk_set: threshold_crypto::PublicKeySet,
    pub dec_shares: std::collections::HashMap<usize, DecryptionShare>
}

impl ThresholdPubKey {
    pub fn new(pk_set: threshold_crypto::PublicKeySet) -> Self {
        ThresholdPubKey {
            pk_set,
            dec_shares: std::collections::HashMap::new(),
        }
    }

    pub fn add_dec_share(&mut self, dec_share: DecryptionShare) {
        self.dec_shares.insert(self.dec_shares.len(), dec_share);
    }
}

impl EJPubKey for ThresholdPubKey {
    fn encrypt(&self, message: String) -> String {
        let pubkey = self.pk_set.public_key();
        let ciphertext = pubkey.encrypt(message.as_bytes());
        serde_json::to_string(&ciphertext).unwrap()
    }

    fn dencrypt(&self, message: String) -> String {
        let data: threshold_crypto::Ciphertext = serde_json::from_str(&message).unwrap();
        let bytes = self.pk_set
            .decrypt(&self.dec_shares, &data)
            .unwrap();

        String::from_utf8(bytes).expect("failed to convert to string")
    }
}
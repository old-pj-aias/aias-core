
use fair_blind_signature::EJPubKey;

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
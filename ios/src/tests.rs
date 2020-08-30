use super::{new_ios, blind_ios, set_subset_ios, generate_check_parameter_ios, unblind_ios, destroy_ios};

use aias_core::signer;
use aias_core::verifyer;

use aias_core::utils;
use aias_core::crypto::{RSAPubKey};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


use serde_json::json;


fn generate_signer() -> FBSSigner<RSAPubKey> {
    let n = BigUint::from(882323119 as u32);
    let e = BigUint::from(7 as u32);
    let d = BigUint::from(504150583 as u32);
    let primes = [BigUint::from(27409 as u32), BigUint::from(32191 as u32)].to_vec();

    let signer_pubkey = RSAPublicKey::new(n.clone(), e.clone()).unwrap();
    let signer_privkey = RSAPrivateKey::from_components(n.clone(), e.clone(), d.clone(), primes.clone());

    let judge_pubkey = RSAPublicKey::new(n.clone(), e.clone()).unwrap();

    let judge_pubkey = RSAPubKey {
        public_key: judge_pubkey
    };

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkey,
        k: 40,
        id: 10
    };
    
    FBSSigner::new(parameters, signer_privkey)
}


#[test]
fn test_init_and_destroy() {
    let signer = generate_signer();
    let (signer_pubkey, signer_privkey) = keys(0);
    let (judge_pubkey, judge_privkey) = keys(1);

    let signer_pubkey = signer_pubkey.to_string();
    let signer_privkey = signer_privkey.to_string();

    let judge_pubkey = judge_pubkey.to_string();

    signer::new(signer_privkey.clone(), signer_pubkey.clone(), judge_pubkey.clone());

    let signer_pubkey = utils::to_c_str(signer_pubkey.to_string());
    let signer_privkey = utils::to_c_str(signer_privkey.to_string());
    let judge_pubkey = utils::to_c_str(judge_pubkey.to_string());

    new_ios(signer_pubkey, judge_pubkey);
    
    let message = utils::to_c_str("aaa".to_string());

    let blinded_digest = blind_ios(message);
    let blinded_digest = utils::from_c_str(blinded_digest);

    signer::set_blinded_digest(blinded_digest);

    let subset = signer::setup_subset();
    let subset = utils::to_c_str(subset.to_string());

    set_subset_ios(subset);

    let check_parameters = generate_check_parameter_ios();
    let check_parameters = utils::from_c_str(check_parameters);

    signer::check(check_parameters);

    let blind_signature = signer::sign();
    let blind_signature = utils::to_c_str(blind_signature);
    let signature = unblind_ios(blind_signature);

    let signature = utils::from_c_str(signature);
    let message = utils::from_c_str(message);
    
    let signer_pubkey = utils::from_c_str(signer_pubkey);
    let judge_pubkey = utils::from_c_str(judge_pubkey);
    let result = verifyer::verify(signature, message, signer_pubkey, judge_pubkey.clone());

    assert!(result);

    destroy_ios();
    signer::destroy();
}


fn keys(i: usize) -> (&'static str, &'static str) {
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

    let pk2 = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA516+OuSktv7e9WvBIY4E
mtFDSrEhjq9uLw4AgEBLz0j8OcP/MRDkxRZPlt4R1Pec0dipymDHekPIcGOQ4SYb
BFLcjN0ZmpPELOusNAvdfKqTSfs8jWEkmgwebe3+SHsgjYESitLDpDBi9gxaA8J5
O07FWbNIn9hIh6mOl8JyOplYsWuyzVx6duk791B/Lvz8rU7B1GpSwUodmk0vJESM
vS5cUJQJiDs0DhkPcK/rnQu7CVnPoiwdmRobxUdaz2RnxWDvpZbb0HLX1Jth1eOR
VuN3JnYagYsLXA96nymLeO3RP8FYpbGZO+Dk07de3RRnVGPYHziRwdQ5p+msENfh
FQIDAQAB
-----END PUBLIC KEY-----
"#;
    let sk2 = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA516+OuSktv7e9WvBIY4EmtFDSrEhjq9uLw4AgEBLz0j8OcP/
MRDkxRZPlt4R1Pec0dipymDHekPIcGOQ4SYbBFLcjN0ZmpPELOusNAvdfKqTSfs8
jWEkmgwebe3+SHsgjYESitLDpDBi9gxaA8J5O07FWbNIn9hIh6mOl8JyOplYsWuy
zVx6duk791B/Lvz8rU7B1GpSwUodmk0vJESMvS5cUJQJiDs0DhkPcK/rnQu7CVnP
oiwdmRobxUdaz2RnxWDvpZbb0HLX1Jth1eORVuN3JnYagYsLXA96nymLeO3RP8FY
pbGZO+Dk07de3RRnVGPYHziRwdQ5p+msENfhFQIDAQABAoIBAQCZ+xPfXgvBPh5k
dzIxgrLN1jdSnlAXBenupwLuV9wcOBak2ywbG4MlJ5QQc/qqIaDch7V4WrBnTnU3
Vww0y4dveTYPCZbgqTcGLlKM0Ni2/07HDc1eyifx3d7iimGRG2CuzBfrDBnoS8uQ
tOezWNoV/naZHBhZSTf8EXw0w9QB6oiJTe2XZeUhFgs9EowXZuGS/CO5K2e5r5Wb
Q87mCdJQRATjI0yTXD1E8UjvcNAMD4Fv87NymviRaEZbIkSeiYnAjbRTLD5F7dCb
b+6EwecZYDDZKxMWAMIH02TS9A0R4J2LF/lfVfG0GlJejU0ulT29HspFMy68xpAo
+tqPeGQBAoGBAPTrbvqvHIjbksTGgA0K+9sX9hYh7u+VZcvZeUC8G8qFrLzVCxNk
GwlwKttpMBKrkJn6ZaMuO2Ms+FrEF1dniPqz5UAT+Hek8YfpWfK4ABf5ZhMMlhhm
kKuyx3Dr243hDUuMYspuxdK8LpDOaKj/s0hjOZ6sasGrP2M5Rl0ZJ5btAoGBAPHW
YjIrqJSYLFJD/CeEbtwgKNS0dY9HjXTP5GZd3y1/T4nXVNfE2UKmrDJVq2zG2SXx
58Hr35In8qjBdzLrb8GHTAtoe4rBIKPSFZ0C7wylAb6rddFD/o1wbwfI8iVgY7f3
zDd+A+d/EANMrm4kLHVrdO8MRMY6VIbkhlz+VsXJAoGBAOs31TziwpfZsSpUrZRZ
MSro50m4Sz5DkCFn+mCmiFZHbW9peBqmcKTu2eohKq8zoEuRRN2kQBrujJK3cudZ
ox+LeCfDRkS539G01dMazdQ4jMTMuLY0gsqzh4G2swSe2GLvL83U9x595obiBXgR
I0DpMuRmGJ1pdxY3YpF04CW9AoGBALFvLdTJm4KKs9oX72W/EOeI4OxPCwH46ZyO
+3Dv5tMm2WC1EJbO4ui4CRdVK9U/gAsLFZN+UCaYEL4oVCCUBQblEbI9EoeXcy8+
8ISmpmWMm18dxe+oB5gWqh/4G1G5CvDranY8ivjKjSEencxJ1iTAlqbdRYh7O5FN
Ehggs+GhAoGBAK/7EnryimXbu+Hn5m+gxV+1TM17n5XsHC/TlRLRv0U/i1K6s8Iq
XpQGF+6cTqxNRLVSVIWb7YMhXr5E+p8nbEaWhnScgH8DPrCA5BEOSPoleCpWXjpN
BgllpXPdrOk2OJHLduFFsuepE7ywwYZBc+WLUIGQUDmLx0kB5vJl2rnL
-----END RSA PRIVATE KEY-----
"#;

    let pk3 = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyba7cPAMUSMSfS4Tq7L4
1mZ/irv8k/p6pJCE6V5NqRvEuoFTt6AvnSxVO49JynKGL23uQLkiGxVuef/lxUC7
qgpe2CMghHmXle4K87SvO3IF+pkk4xBm5JO+fMUjO5tnZ7HaAjI/l/6SKOzLSZAl
C2Jo6eJfKZjxKY2/z+t03hEPqi5qS4z0pj0pYgtV+8vqDSC8xq0sRAzUNSVDNw09
IoQLElMWYeWxs3cfFTOtl6pogVd+eHvQOx1VNm6iFneUC1CHLD2pRXzOiwEwRqgf
8jx+XsZnzRQN8RX+cK3HEm8gGmssf8oKWC2ORVKAKkpE9WSpIBvXH5yospu2LjH9
4wIDAQAB
-----END PUBLIC KEY-----"#;
    let sk3 = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyba7cPAMUSMSfS4Tq7L41mZ/irv8k/p6pJCE6V5NqRvEuoFT
t6AvnSxVO49JynKGL23uQLkiGxVuef/lxUC7qgpe2CMghHmXle4K87SvO3IF+pkk
4xBm5JO+fMUjO5tnZ7HaAjI/l/6SKOzLSZAlC2Jo6eJfKZjxKY2/z+t03hEPqi5q
S4z0pj0pYgtV+8vqDSC8xq0sRAzUNSVDNw09IoQLElMWYeWxs3cfFTOtl6pogVd+
eHvQOx1VNm6iFneUC1CHLD2pRXzOiwEwRqgf8jx+XsZnzRQN8RX+cK3HEm8gGmss
f8oKWC2ORVKAKkpE9WSpIBvXH5yospu2LjH94wIDAQABAoIBAEe6xFL3+dlMeIGt
Re9zuEs9rbMfAEV69+vXPHxkPYeaSU3tOWD+BJCGuFRystHcAd2R4PyBGSC6cUvO
9N09FL716x4+94xEVORK/vgE0592/6tKlDRum7hC1aU20T2cGJxmQVkwly6spzsI
YY3qRVIUD6zEBAUdzvxw3LnKSAfDNNOS5KkC/5uRZeydmjzXiGhT3tFD1CFmq28v
3oOH9Zk6DPN8zZ/o63scs6gr5Sgm1l+shVpYB/YWUlSumaJtKsqmIY4kren/FlgE
MdPbn5QhTHCgCgH8DTmudh1TkWhFjG70119uu6Sc2x9BPcN79g3DuVrGFX+okUaR
8/uy9IECgYEA/W2ERWkct6C1ksAT79hUQuK0dU0qelxeRdrPOruBFWnlJfJhMY8U
o9uhPeSWqxXBHfGtRH14DhnQ/4HnL8twFgqyczSWYi4Ibox7VzijLOqQn5PgPSOk
C1a1uJnfY7wXA0XWCnqpT6hcVr8PJyW4HVBSzbmuf4EZ1h1o+EVd+SMCgYEAy8LY
vSgKqplzUOxWpkYSaiWY/FC9LGpkTQRdrovBfBqnENPHev0JPKNLFvNjnyv0nyvW
J36hQ/rN8ICjR0P1Dq9PINPZ+5X89LGicWQUfOypQrjKemOYgjob5+ZR92y4fDdx
Q5Yi+CSMATm9PAg1u+5icKI5LwAWhkUmUq4VFEECgYEAml9I0EMsFAsYL7FDM7mR
8kBIbp+3vVtgraqQyxUGl3Wu+QOBAwBGMV4LBTmmMccJoOTjh7HqHKTLM6j8m5eP
yk1v0E97P4kM59I5G7NLaoPj3uDkGjoIpkOGZFGOyyD636p9rFp1oilLPigZ4d3P
HkQcfGacDd0lUNEPbRRMHwMCgYADn0IVErol0DaBkMH1kLdRFbwDeDf0qyt/Rv2X
VbqpxxuDLBCWuhrI7ioujUMPGEvv7GqRJyocuD+i79Z3NNkNWsZwUfPFCiSGAQZf
N6U5l0dm/Tv0MwMKBZhrZee9GzyoUJ/90JRsjtHCT9FyWL8DyTgMwoV7tWexGVeW
DqwnQQKBgB0tcuRjhPl7J3g8kpI5+RRor+odaZkBYMH6BlX9EMsdvl0zUpCuyGaZ
zZb4R0h8xVYSGXh1N6dCWiC2wzRmvprgddxW9sQCFokEZU3wj8jr1rabV7E+G7Cj
dF7ctu04I3hHeBt58imNoKRWeK4Lh48NPTmgpnvJGSk90qzUx7Vl
-----END RSA PRIVATE KEY-----"#;

    let pk4 = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA74r/cXCUTvEBRez/sk6y
JnzwHCgNT0qHjA9jYsUR2ZBCZi/K4Nlnkqaou1y05BmhLv3iDh4noegHgy1dHPoY
STyb7WbOkFLryuTfQUYue4aejspQN2NTV5/g2oPYFmlw37J+hasHfPVEZ8cJu4yl
Qf55w3YjG/RF6J3ZQhOERXtQAL3GWlxoHVYYX4ecMkU8SX434Y6REE91a33leqMy
Ag27dsxp5x13WP3gLtUPv2I75iCYGy4fS4NhK48IoeAyTUGWgTaRWJpLDncsDoiY
kaaWjPZJ0AB5T7l9xVJJoBNcUOpZL9a2EYFaHsnID2ZF5fN2aTLdpi7PvzfmlSNG
MwIDAQAB
-----END PUBLIC KEY-----"#;
    let sk4 = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA74r/cXCUTvEBRez/sk6yJnzwHCgNT0qHjA9jYsUR2ZBCZi/K
4Nlnkqaou1y05BmhLv3iDh4noegHgy1dHPoYSTyb7WbOkFLryuTfQUYue4aejspQ
N2NTV5/g2oPYFmlw37J+hasHfPVEZ8cJu4ylQf55w3YjG/RF6J3ZQhOERXtQAL3G
WlxoHVYYX4ecMkU8SX434Y6REE91a33leqMyAg27dsxp5x13WP3gLtUPv2I75iCY
Gy4fS4NhK48IoeAyTUGWgTaRWJpLDncsDoiYkaaWjPZJ0AB5T7l9xVJJoBNcUOpZ
L9a2EYFaHsnID2ZF5fN2aTLdpi7PvzfmlSNGMwIDAQABAoIBAQCo7FSHIuTzZnGH
ZkJK88Qd8C1DLdt09xHva0qi9GZKDrlEZp+jQK0RdgW3WwEVeh14jgFEA2/fdUkW
8H6hWJyXyO4M1FsG2/L7+bqWxW8yHRTjjThUVu8G8/AVKLTR2TmIBs/CY4G8VRoQ
NQRgBibkCxjDBiRsKi7Cg84aErlMZPQH6H1JLarnnX5H+RoLN9++IykTB/v6iXbE
LfvFSM1SMeHVv6cehmhol78x3Jn0eRcyAuYAUMgqhkKyr86sfihoYUjaEOv1yoQC
GvlGvh3esHyOCAuzO/q4IncbTh1YBR7n9GIeIWn3zhXOdQ/mECTofdklhjnN0AVl
VJvM6juBAoGBAPy59h/lp1rT8n0ZGcahD9LdDKBxJaYvtKnWI+mNOXdsl5V1t4oa
x7JCVatoS7+4hi9WVg4bregUAzu20++/vSqIStnTudQArPo0Ywhg8Qv/DeKDGXqv
kRUBM3T/uzd3Pq/hfkat/6s0UF0TaKHJ+BKK9llcs6/56aKecPgMIndrAoGBAPKl
Uff72Pe4keG0G9fCTCwxcjdgiiiA8hX/xD+e3SbH+8awBgvmfmlSCVfGP90dk1q2
uzTajMxQXocS31aWpNebyXxngZSrsDKEBvWgbydgwLNWdJLi4p5hD/FMRlPuaWVq
qZFzrzQzsPrCYQaR07Tsz0i5MMqQsm+c+ibwIcZZAoGAJCENn4e8Qg7Utq+U8MFr
urBhMrqaMETXpgP4BFZtJbZ/gR1gDL1BWSmEh8mUMqdVf4TvLnskhG3//FRpvfeC
OodbdAKBqV4jXG2KztLVAusGeCBXzyM0MXWHfq1kfUxtyMUKwV30k+wZpQS2S5LN
BRGaoDHRelHW5amS6tMJRlsCgYEA7bTtbz4nWM9VAsLaP+2Vh/nMxdlqn7Fq+Ag/
boAocRSbYBMTaVcd4fm/M2EBMZIGyGiZT3cHViUp5bOkXgRoatywb5JLDKWBkIts
8faAzhfn0AjTXQ6uKbA22RH7F8BJOlRa2CZ3rnExYQdJ3BDCUM1pZ/ochWVpmRQ0
sC6xN8kCgYA/LBoQLrs80+BZQhCMgX57IXKP8pXaIBl9J57Y4y4fp7GweOgEYynz
kP/yNGtYJ6xzSyoY8ugYX04g+8XZruOW+r+72AZsyDSE4GwmIWyN1dfpfRT0OKrO
D1p7TEpGfOPlKMqL41ZLyMJCHiaf/V59QdMeKurEJtqtrO+eKZsqew==
-----END RSA PRIVATE KEY-----"#;

    // 128 bits
    let pk5 = r#"-----BEGIN PUBLIC KEY-----
MCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAKw35TrGu3NiwVxvl8H4QvECAwEAAQ==
-----END PUBLIC KEY-----"#;
    let sk5 = r#"-----BEGIN RSA PRIVATE KEY-----
MGMCAQACEQCsN+U6xrtzYsFcb5fB+ELxAgMBAAECEHSIVgpRk2HdYv0v1c9meSkC
CQDVA6ZVm3ZilwIJAM74uOR/RJ+3AgkAs/cea4sprMcCCQCwKub9nxJjOwIIcoMt
JX7ER4Q=
-----END RSA PRIVATE KEY-----"#;


    let mut v = Vec::new();

    v.push((pk1, sk1));
    v.push((pk2, sk2));
    v.push((pk3, sk3));
    v.push((pk4, sk4));
    v.push((pk5, sk5));

    return v[i];
}

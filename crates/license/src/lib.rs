use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};

#[derive(Debug)]
pub struct License {
    domain: String,
    created_at: DateTime<Utc>,
    expired_at: DateTime<Utc>,
    sign: Vec<u8>,
}

impl License {
    pub fn encode(&self) -> String {
        format!("{},{},{}", self.domain, self.created_at, self.expired_at)
    }
    pub fn to_string(&self) -> String {
        let data = format!("{},{},{},{}", self.domain, self.created_at.to_rfc3339(), self.expired_at.to_rfc3339(), hex::encode(&self.sign));
        bs58::encode(data.as_bytes()).into_string()
    }

    pub fn from_string(s: String) -> Result<Self> {
        let a = bs58::decode(&s).into_vec()?;
        let b = String::from_utf8(a)?;
        let arr = b.split(",").collect::<Vec<_>>();
        if arr.len() < 4 {
            return Err(anyhow!("Bad Data: {}", &s));
        }

        let created_at = DateTime::parse_from_rfc3339(arr[1])?;
        let expired_at = DateTime::parse_from_rfc3339(arr[2])?;
        let created_at = DateTime::<Utc>::from_utc(created_at.naive_utc(), Utc);
        let expired_at = DateTime::<Utc>::from_utc(expired_at.naive_utc(), Utc);

        let sign = hex::decode(arr[3])?;
        Ok(License {
            domain: arr[0].to_string(),
            created_at,
            expired_at,
            sign,
        })
    }
}

#[derive(Debug)]
pub struct LicenseGenerator {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

// generate new
impl LicenseGenerator {
    pub fn new(private_key: RsaPrivateKey, public_key: RsaPublicKey) -> Self {
        LicenseGenerator {
            private_key,
            public_key,
        }
    }

    pub fn gen(&self, domain: &str, expired_at: DateTime<Utc>) -> License {
        let created_at = Utc::now();
        let mut license = License {
            domain: domain.to_string(),
            created_at,
            expired_at,
            sign: vec![],
        };
        let data = license.encode();
        let sign = rsa_sign(data.as_bytes(), &self.private_key);
        license.sign = sign;
        license
    }

    pub fn check(&self, license_str: &str) -> Result<()> {
        let license = License::from_string(license_str.to_string())?;
        if license.expired_at < Utc::now() {
            return Err(anyhow!("License expired at {}!", license.expired_at));
        }
        let data = license.encode();
        if !rsa_check_sign(data.as_bytes(), &license.sign, &self.public_key) {
            return Err(anyhow!("Invalid sign!"));
        }
        Ok(())
    }

}

fn gen_rsa_pair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

fn rsa_sign(digest_in: &[u8], private_key: &RsaPrivateKey) -> Vec<u8> {
    let padding = PaddingScheme::new_pkcs1v15_sign(None);
    let sign_data = private_key.sign(padding, digest_in).unwrap();
    sign_data
}

fn rsa_check_sign(hashed: &[u8], sig: &[u8], public_key: &RsaPublicKey) -> bool {
    let r = public_key.verify(PaddingScheme::new_pkcs1v15_sign(None), hashed, sig);
    r.is_ok()
}

#[cfg(test)]
mod test {
    use std::ops::Add;
    use super::*;

    #[test]
    fn test_license() {
        let (private_key, public_key) = gen_rsa_pair();
        let licensegen = LicenseGenerator::new(private_key, public_key);
        let expired_at = Utc::now().add(chrono::Duration::seconds(365 * 86400));
        let license = licensegen.gen("www.domain.com", expired_at);
        assert_eq!(license.domain, "www.domain.com");
        assert_eq!(license.expired_at, expired_at);
        let b = licensegen.check(&license.to_string());
        assert_eq!(b.is_ok(), true);
    }
}
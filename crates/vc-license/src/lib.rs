use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use pkcs1::EncodeRsaPrivateKey;
use rsa::{
    pkcs1::{EncodeRsaPublicKey, LineEnding},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};

#[derive(Debug)]
pub struct License {
    pub domains: Vec<String>,
    pub user_limit: u32,
    pub created_at: DateTime<Utc>,
    pub expired_at: DateTime<Utc>,
    pub sign: Vec<u8>,
}

impl Default for License {
    fn default() -> Self {
        License {
            domains: vec![],
            user_limit: 0,
            created_at: DateTime::<Utc>::MIN_UTC,
            expired_at: DateTime::<Utc>::MIN_UTC,
            sign: vec![],
        }
    }
}

impl License {
    pub fn encode(&self) -> String {
        format!(
            "{},{},{}",
            self.domains.join("|"),
            self.created_at,
            self.expired_at
        )
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let data = format!(
            "{},{},{},{},{}",
            self.domains.join("|"),
            self.user_limit,
            self.created_at.to_rfc3339(),
            self.expired_at.to_rfc3339(),
            hex::encode(&self.sign)
        );
        bs58::encode(data.as_bytes()).into_string()
    }

    pub fn from_string(s: String) -> Result<Self> {
        let a = bs58::decode(&s).into_vec()?;
        let b = String::from_utf8(a)?;
        let arr = b.split(',').collect::<Vec<_>>();
        if arr.len() < 5 {
            return Err(anyhow!("Bad Data: {}", &s));
        }

        let user_limit = arr[1].parse::<u32>().unwrap_or_default();
        let created_at = DateTime::parse_from_rfc3339(arr[2])?;
        let expired_at = DateTime::parse_from_rfc3339(arr[3])?;
        let created_at = DateTime::<Utc>::from_utc(created_at.naive_utc(), Utc);
        let expired_at = DateTime::<Utc>::from_utc(expired_at.naive_utc(), Utc);

        let sign = hex::decode(arr[4])?;
        Ok(License {
            domains: arr[0].split('|').map(|v| v.to_string()).collect::<Vec<_>>(),
            user_limit,
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

    pub fn new_from_pem(private_key_pem: &str, public_key_pem: &str) -> Result<Self> {
        let private_key = pkcs1::DecodeRsaPrivateKey::from_pkcs1_pem(private_key_pem)?;
        let public_key = pkcs1::DecodeRsaPublicKey::from_pkcs1_pem(public_key_pem)?;
        Ok(LicenseGenerator {
            private_key,
            public_key,
        })
    }

    pub fn gen(&self, domains: &str, expired_at: DateTime<Utc>, user_limit: u32) -> License {
        let created_at = Utc::now();
        let mut license = License {
            domains: domains
                .split('|')
                .map(|v| v.to_string())
                .collect::<Vec<_>>(),
            user_limit,
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
        if rsa_check_sign(data.as_bytes(), &license.sign, &self.public_key).is_err() {
            return Err(anyhow!("Invalid sign!"));
        }
        Ok(())
    }
}

pub fn gen_rsa_pair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn gen_rsa_pem_pair() -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let a = private_key.to_pkcs1_pem(LineEnding::CRLF)?.to_string();
    let public_key = RsaPublicKey::from(&private_key);
    let b = public_key.to_pkcs1_pem(LineEnding::CRLF)?;
    Ok((a, b))
}

fn rsa_sign(digest_in: &[u8], private_key: &RsaPrivateKey) -> Vec<u8> {
    let padding = PaddingScheme::new_pkcs1v15_sign(None);
    private_key.sign(padding, digest_in).unwrap()
}

fn rsa_check_sign(hashed: &[u8], sig: &[u8], public_key: &RsaPublicKey) -> Result<()> {
    Ok(public_key.verify(PaddingScheme::new_pkcs1v15_sign(None), hashed, sig)?)
}

pub fn rsa_check_license_bs58(license_bs58: &str, public_key_pem: &str) -> Result<()> {
    let public_key: RsaPublicKey = pkcs1::DecodeRsaPublicKey::from_pkcs1_pem(public_key_pem)?;
    let license = License::from_string(license_bs58.to_string())?;
    let data = license.encode();
    rsa_check_sign(data.as_bytes(), license.sign.as_slice(), &public_key)
}

pub fn rsa_check_license(license: &License, public_key_pem: &str) -> Result<()> {
    let public_key: RsaPublicKey = pkcs1::DecodeRsaPublicKey::from_pkcs1_pem(public_key_pem)?;
    let data = license.encode();
    rsa_check_sign(data.as_bytes(), license.sign.as_slice(), &public_key)
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
        let license = licensegen.gen("www.domain.com|www.domain2.com", expired_at, 10);
        assert_eq!(license.domains[0], "www.domain.com");
        assert_eq!(license.domains[1], "www.domain2.com");
        assert_eq!(license.expired_at, expired_at);
        let b = licensegen.check(&license.to_string());
        assert!(b.is_ok());
    }

    #[test]
    fn test_check_license() {
        let (private_key, public_key) = gen_rsa_pair();
        let licensegen = LicenseGenerator::new(private_key, public_key.clone());
        let expired_at = Utc::now().add(chrono::Duration::seconds(365 * 86400));
        let license = licensegen.gen("www.domain.com|www.domain2.com", expired_at, 20);

        let license_bs58 = license.to_string();

        let public_key_pem = public_key.to_pkcs1_pem(LineEnding::CRLF).unwrap();
        let a = rsa_check_license_bs58(&license_bs58, &public_key_pem);
        assert!(a.is_ok());
    }

    #[test]
    fn test_gen_license() {
        let private_key_pem = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApqGLPAiVzx42qRkjDGqCT4+BrS3BReJA7UAXQt3YNfw2HIB+
CJSDF22KnpqmnsaLWmxrUP1Q+ttb+fZhMZ569s5ZLs9h6pq2oTBK8kBUKz127rpw
HSpGVnuGbkPB4NUcTOYiDTLT7iD9NSN38Cr1ITTD3+4EiSiCuf9aUpggfo06fqF6
9ebDC0pPSTRvIDgKrJiku93c3d1uDq1DWfYKu3GP23ie5+3WwQcsd/XG/0xyMk1h
fVQJqTf5Z2rVdmhVGt0XjV6cmaVshJOxGeoAubPLJX4G4DLTvXKGy/WlQlQTqIBz
8xUBdnwtOymXGQpaS/Vfo0q1kGzZoXsCx3v7BQIDAQABAoIBAQClK0fakB//F9HS
uCn3qrPUrUk7IjmMTgNRqM/l5gTlLkVs5ykG1D9FP73CDUXP6LpFPWb69r4IituW
4FPjXVZBwrTAI6zJYeZZzIbdrkpAOkLjzEZJgpgKLZNJRTyu4k+VIiDquFE+n9Cd
lbTTiaFF8wmdtE8mrdM3Dxi2+jhrd3Snp3kVvFniV7EQTwC6SEOQkyMP01aQgc1B
ydxxZFqEO2oQ/uBdjovLEy6rAo18d1EZ5p2j/75oIPfVvtTELlnqLen/FKBmfaxz
vHmaALJahAa1LYnqpr4Mn+SOmkf3lgtfz0H0yneN+9GfTNYcBePReOkcXFmkpE4p
DG0J8QxBAoGBANX5Z8+wxrhHBcEPXS9/y/EWrLyM37HYoxUPfROgPrxACwxMdlIN
QPtnGPdwW6qstIL8D63RCwHKADhUGd4BHnUyTiWjW0fQP3lJDj5HStU6/Iptec7t
ZHggSSqPfhy5xQvRKVIxEDOYMEc4p7O/Lgocst8fK2g1USkT0mD3pPgNAoGBAMdb
un9jhsV8O3ZufTrANF7IPAQqxk9i7A+zQM7DDXG1zYg/HDWWEh8OHTy8sOz7bbDt
XpfhWqLxCldJZ5OkeIx27lejGbV7Fkmr7IyoEXVlM6pz4zbaKG7g/YC3xSoGyg03
ijJ9fLhltCIeKW+df/lNFqeehwv3gGeSq0epVpjZAoGACzSMYyv2vB+8BWgwkRQ4
Md/mG9mkvUODBs9Q1X5GysTvzy0R5SochQ3ZGNwhcMaqjVF14LxZvzY83LZKxH16
gtinjwEG/rPBHzDcNha1rITyRK2G+3cjE8ddDYWGLSrtTrkdWNiI6KrHnHMzFQ6l
8pGeLGENfN+N6IDJO5q8YOECgYAGkICtnStc6WBT4AODobyXumQvhvEMwCchxTdH
F6kjq2bfK6TUJuLl3uMbkuMIiqbsAoTw31zKrME4apRcijfl+CyU+ivoi+sJ9f1O
DGK2yORQooxCzCA0tnfieyqk3aBdmwyT6QnoUIED9pZKtJb4MI+kaVXtEPNLdcrq
Cyts0QKBgQCJY+aRSa7x/WYjotQmwZDfMmABqUTjxWInv2VC6TID4qTR//5ZLWGD
PGaAcyhCpEW7oh2++dvgy2L5ERToqfbKt0G7gFVdg5fMNExG5xKB1Z8BAe2JrVO7
3HPF/Sk36ickz/3zXaBWSnoZUqzrMlJeXoSyLYFC+opQKatRRP5vQw==
-----END RSA PRIVATE KEY-----"#;

        let public_key_pem = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEApqGLPAiVzx42qRkjDGqCT4+BrS3BReJA7UAXQt3YNfw2HIB+CJSD
F22KnpqmnsaLWmxrUP1Q+ttb+fZhMZ569s5ZLs9h6pq2oTBK8kBUKz127rpwHSpG
VnuGbkPB4NUcTOYiDTLT7iD9NSN38Cr1ITTD3+4EiSiCuf9aUpggfo06fqF69ebD
C0pPSTRvIDgKrJiku93c3d1uDq1DWfYKu3GP23ie5+3WwQcsd/XG/0xyMk1hfVQJ
qTf5Z2rVdmhVGt0XjV6cmaVshJOxGeoAubPLJX4G4DLTvXKGy/WlQlQTqIBz8xUB
dnwtOymXGQpaS/Vfo0q1kGzZoXsCx3v7BQIDAQAB
-----END RSA PUBLIC KEY-----"#;

        let licensegen = LicenseGenerator::new_from_pem(private_key_pem, public_key_pem).unwrap();

        let expired_at = chrono::NaiveDate::parse_from_str("2025-01-01", "%Y-%m-%d")
            .expect("Date format error: %Y-%m-%d, just like: 2024-02-01");
        let expired_at = chrono::NaiveDateTime::new(
            expired_at,
            chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
        );
        let expired_at = chrono::DateTime::<Utc>::from_utc(expired_at, Utc);
        let license = licensegen.gen("www.domain.com|www.domain2.com", expired_at, 20);

        let license_bs58 = license.to_string();
        // dbg!(license_bs58);
        // assert_eq!(&license_bs58,
        // "2RvN4krfyQbvuLcXzz4PwoJfckRFptqLKKXSP7f4Np7AGqgixrfdUzZ5qk2iT2gFwCntivyYnSaumyao7QF2SfQ3TKyLAgGDYeYeJcbBri9re5esG2PMrxZBjq68eR94yYqdTg6LAP9oc5WtLAaBX25RkVu2zt59kdgRzk5CbnnmZnMAHgZEDnsVJfCQa6HKnb3p1cpZa6LTANrKh1VuvCAerdCHCoc1YHNwUipg5JJXmxJQadFShv1sYREUHHzLuPMb8xHb7GkPJ6MJpQBzHfDnTySRG7BGxNz5GKCutFp1o7YjkQqZvKBTvWQ8ic4HmbHErLHw4aJ5CAMyugX4v2GAgxS8Z4zi9tjdzRtbbqzncnXSNBTumBxobBskNAbEaQC9HgBavgcAw4wHrHSyG3v2rTdsDUJZgTtanEfxnxZhSpKtXZRFzVNdjmo66GeLhvWwMZSXKzH89uTvMcEokmbUyLz9mKXzRP9dhTJ4bC6YWNrbDueYX9pqrsmXm3Z4aYP7DjknXwPCMKZbsCXZi2YQVUjggCyRarR4eThY6gZ8iWGkvi1ybAADooh8KXSAFNGSRRTGC5La6Atug7y6e6QnFmaRndLHdCyxqyq9LM1Ly2icYAFa2ZspXyL3MyBTLFvgQeqTmL1KQVHzhjwtkTvcFsUxScYNXhVgCkyD5vkSZpcwixGJYyYtkrF27XpMcq8mR6dAyi3Zqt2w68X3xA748a8ofky1KYwHmA1U4BaDpXbbVKSu6wtonMhzvQ6xMssyWJVhrzeymPnMwM8Xiut3pZcpC77Ri"
        // );

        let license = License::from_string(license_bs58).unwrap();
        // dbg!(license.domain);
    }
}

use std::time::Duration;

use futures_util::Stream;
use poem::listener::{RustlsCertificate, RustlsConfig};
use rcgen::{Certificate, CertificateParams, KeyPair, RcgenError, SanType};

const CA_CERT: &str = include_str!("../cert/ca.crt");
const CA_KEY: &str = include_str!("../cert/ca.key");

fn create_certificate() -> Result<(String, String), RcgenError> {
    let key = KeyPair::from_pem(CA_KEY)?;
    let params = CertificateParams::from_ca_cert_pem(CA_CERT, key)?;
    let ca_cert = Certificate::from_params(params)?;

    let mut params = CertificateParams::default();
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    params
        .subject_alt_names
        .push(SanType::IpAddress("0.0.0.0".parse().unwrap()));
    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".to_string()));
    let gen_cert = Certificate::from_params(params)?;

    let server_crt = gen_cert.serialize_pem_with_signer(&ca_cert)?;
    let server_key = gen_cert.serialize_private_key_pem();

    Ok((server_crt, server_key))
}

pub fn create_self_signed_config() -> impl Stream<Item = RustlsConfig> {
    async_stream::stream! {
        loop {
            if let Ok((cert, key)) = create_certificate() {
                yield RustlsConfig::new().fallback(RustlsCertificate::new().cert(cert).key(key));
            }
            tokio::time::sleep(Duration::from_secs(60 * 5)).await;
        }
    }
}

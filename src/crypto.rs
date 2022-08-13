use std::fmt::Write as _;

use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::{X509NameBuilder, X509},
};

pub struct Crypto {
    pub key: PKey<Private>,
    pub x509: X509,
    pub fingerprint: String,
    pub ssl_acceptor: SslAcceptor,
}

impl Crypto {
    pub fn init() -> Result<Crypto, ErrorStack> {
        const X509_DAYS_NOT_BEFORE: u32 = 0;
        const X509_DAYS_NOT_AFTER: u32 = 365;

        // TODO: Let the user pick the public key algorithm and x509 digest algorithm.

        let rsa = Rsa::generate(2048)?;
        let key = PKey::from_rsa(rsa)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, "webrtc-unreliable")?;
        let name = name_builder.build();

        let mut x509_builder = X509::builder()?;
        x509_builder.set_version(0)?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(&name)?;
        let not_before = Asn1Time::days_from_now(X509_DAYS_NOT_BEFORE)?;
        let not_after = Asn1Time::days_from_now(X509_DAYS_NOT_AFTER)?;
        x509_builder.set_not_before(&not_before)?;
        x509_builder.set_not_after(&not_after)?;
        x509_builder.set_pubkey(&key)?;
        x509_builder.sign(&key, MessageDigest::sha256())?;
        let x509 = x509_builder.build();

        let x509_digest = x509.digest(MessageDigest::sha256())?;
        let mut fingerprint = String::new();
        for i in 0..x509_digest.len() {
            write!(fingerprint, "{:02X}", x509_digest[i]).unwrap();
            if i != x509_digest.len() - 1 {
                write!(fingerprint, ":").unwrap();
            }
        }

        let mut ssl_acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;

        // `webrtc-unreliable` does not bother to verify client certificates because it is designed
        // to be used as a dedicated server with arbitrary clients.  The client will verify the
        // server's certificate via the fingerprint provided inside the SDP descriptor, so if the
        // descriptor is delivered over a verified channel (such as HTTPS with a valid server
        // certificate), the resulting DTLS connection should have the same level of verification.
        // This should prevent MITM attacks against the DTLS connection (tricking the client to
        // connect to some other server than the verified one).  Client authentication (such as
        // username / password) can then be handled through the resulting WebRTC data channel.
        //
        // TODO: Somebody who is actually good at this stuff should verify this.
        ssl_acceptor_builder.set_verify(SslVerifyMode::NONE);

        ssl_acceptor_builder.set_private_key(&key)?;
        ssl_acceptor_builder.set_certificate(&x509)?;
        let ssl_acceptor = ssl_acceptor_builder.build();

        Ok(Crypto {
            key,
            x509,
            fingerprint,
            ssl_acceptor,
        })
    }
}

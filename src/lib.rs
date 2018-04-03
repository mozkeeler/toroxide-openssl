extern crate openssl;
extern crate toroxide;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslMethod, SslStream,
                   SslVerifyMode};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use std::io::{Error, ErrorKind, Read, Write};
use toroxide::Async;

pub struct PendingTlsOpensslImpl<T: Read + Write> {
    ssl: Option<Ssl>,
    stream: Option<T>,
    mid_handshake_stream: Option<MidHandshakeSslStream<T>>,
}

impl<T: Read + Write> PendingTlsOpensslImpl<T> {
    pub fn new(stream: T) -> Result<Self, Error> {
        let mut ssl_context_builder = match SslContext::builder(SslMethod::tls()) {
            Ok(ssl_context_builder) => ssl_context_builder,
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        };
        ssl_context_builder.set_verify_callback(SslVerifyMode::PEER, |_, _| {
            // We're do the "in-protocol" handshake, so we don't verify the peer's TLS certificate.
            true
        });
        let ssl_context = ssl_context_builder.build();
        let ssl = match Ssl::new(&ssl_context) {
            Ok(ssl) => ssl,
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        };
        Ok(PendingTlsOpensslImpl {
            ssl: Some(ssl),
            stream: Some(stream),
            mid_handshake_stream: None,
        })
    }

    fn handle_connect_or_handshake_result(
        &mut self,
        result: Result<SslStream<T>, HandshakeError<T>>,
    ) -> Result<Async<TlsOpensslImpl<T>>, Error> {
        match result {
            Ok(ssl_connected) => Ok(Async::Ready(TlsOpensslImpl {
                stream: ssl_connected,
            })),
            Err(e) => match e {
                HandshakeError::SetupFailure(e) => Err(Error::new(ErrorKind::Other, e)),
                HandshakeError::Failure(_) => Err(Error::new(ErrorKind::Other, "handshake error")),
                HandshakeError::WouldBlock(mid_handshake_stream) => {
                    self.mid_handshake_stream = Some(mid_handshake_stream);
                    Ok(Async::NotReady)
                }
            },
        }
    }

    pub fn poll(&mut self) -> Result<Async<TlsOpensslImpl<T>>, Error> {
        if let Some(ssl) = self.ssl.take() {
            if let Some(stream) = self.stream.take() {
                self.handle_connect_or_handshake_result(ssl.connect(stream))
            } else {
                Err(Error::new(
                    ErrorKind::Other,
                    "library error: ssl and stream should both be Some here",
                ))
            }
        } else if let Some(mid_handshake_stream) = self.mid_handshake_stream.take() {
            self.handle_connect_or_handshake_result(mid_handshake_stream.handshake())
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "library error: shouldn't reach this point",
            ))
        }
    }
}

pub struct TlsOpensslImpl<T: Read + Write> {
    stream: SslStream<T>,
}

impl<T: Read + Write> toroxide::TlsImpl for TlsOpensslImpl<T> {
    fn get_peer_cert_hash(&self) -> Result<[u8; 32], Error> {
        let peer_cert = match self.stream.ssl().peer_certificate() {
            Some(peer_cert) => peer_cert,
            None => return Err(Error::new(ErrorKind::Other, "no peer certificate?")),
        };
        let fingerprint = match peer_cert.fingerprint(MessageDigest::sha256()) {
            Ok(fingerprint) => fingerprint,
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        };
        if fingerprint.len() != 32 {
            return Err(Error::new(
                ErrorKind::Other,
                "OpenSSL SHA256 implementation not 32 bytes?",
            ));
        }
        let mut result: [u8; 32] = [0; 32];
        result.copy_from_slice(&fingerprint);
        Ok(result)
    }

    fn get_tls_secrets(&self, label: &str, context_key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::with_capacity(32);
        buf.resize(32, 0);
        match self.stream
            .ssl()
            .export_keying_material(&mut buf, label, Some(context_key))
        {
            Ok(()) => Ok(buf),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }
}

impl<T: Read + Write> Read for TlsOpensslImpl<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.stream.read(buf)
    }
}

impl<T: Read + Write> Write for TlsOpensslImpl<T> {
    fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.stream.write(data)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.stream.flush()
    }
}

pub struct RsaVerifierOpensslImpl {}

impl toroxide::RsaVerifierImpl for RsaVerifierOpensslImpl {
    fn verify_signature(&self, cert: &[u8], data: &[u8], signature: &[u8]) -> bool {
        let openssl_cert = match X509::from_der(cert) {
            Ok(openssl_cert) => openssl_cert,
            Err(_) => return false,
        };
        let key = match openssl_cert.public_key() {
            Ok(key) => key,
            Err(_) => return false,
        };
        let rsa = key.rsa().unwrap();
        let mut decrypted_data: Vec<u8> = Vec::with_capacity(rsa.size() as usize);
        decrypted_data.resize(rsa.size() as usize, 0);
        let decrypted_data_len =
            match rsa.public_decrypt(signature, &mut decrypted_data, Padding::PKCS1) {
                Err(_) => return false,
                Ok(len) => len,
            };
        if decrypted_data_len != data.len() {
            return false;
        }
        for i in 0..decrypted_data_len {
            if decrypted_data[i] != data[i] {
                return false;
            }
        }
        true
    }

    /// Returns the sha-256 hash of the DER encoding of the key in the given DER-encoded certificate
    /// as an ASN.1 RSA public key as specified in PKCS #1.
    fn get_key_hash(&self, cert: &[u8]) -> [u8; 32] {
        let openssl_cert = X509::from_der(cert).unwrap();
        let key = openssl_cert.public_key().unwrap();
        let bytes = key.rsa().unwrap().public_key_to_der_pkcs1().unwrap();
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(&bytes).unwrap();
        let mut hash: [u8; 32] = [0; 32];
        hash.copy_from_slice(&hasher.finish().unwrap());
        hash
    }
}

pub struct RsaSignerOpensslImpl {
    key: PKey<Private>,
    der: Vec<u8>,
}

impl RsaSignerOpensslImpl {
    pub fn new() -> RsaSignerOpensslImpl {
        let key = PKey::from_rsa(Rsa::generate(1024 as u32).unwrap()).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let mut random_bytes = [0; 20];
        rand_bytes(&mut random_bytes).unwrap();
        // this might be unnecessary, depending on how BigNum/ASN.1 impl works.
        random_bytes[0] &= 0x7f; // make sure the higest bit isn't set
        random_bytes[0] |= 0x01; // make sure at least one bit is set in the first ocetet
        let serial_number = BigNum::from_slice(&random_bytes).unwrap();
        let serial_number = serial_number.to_asn1_integer().unwrap();
        builder.set_serial_number(&serial_number).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "www.randomizeme.test")
            .unwrap();
        let name = name_builder.build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        // So unfortunately if there's a lot of clock skew this might not work. TODO: improve the
        // ASN1Time api (docs reference setting the value with a string, but I can't find any actual
        // implementation evidence to support this).
        let not_before = Asn1Time::days_from_now(0).unwrap();
        builder.set_not_before(&not_before).unwrap();
        let not_after = Asn1Time::days_from_now(1000).unwrap();
        builder.set_not_after(&not_after).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let x509 = builder.build();
        let der = x509.to_der().unwrap();
        RsaSignerOpensslImpl { key: key, der: der }
    }
}

impl toroxide::RsaSignerImpl for RsaSignerOpensslImpl {
    fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        let rsa_key = &self.key.rsa().unwrap();
        let mut signature: Vec<u8> = Vec::with_capacity(rsa_key.size() as usize);
        signature.resize(rsa_key.size() as usize, 0);
        rsa_key
            .private_encrypt(data, &mut signature, Padding::PKCS1)
            .unwrap();
        signature
    }

    fn get_cert_bytes(&self) -> &[u8] {
        &self.der
    }
}

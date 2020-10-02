use once_cell::sync::Lazy;
use rustls::Session;
use std::{
    io::{Read, Write},
    sync::Arc,
};

fn main() {
    println!("-- first message --");
    one_message();
    /*
    println!("-- second message --");
    one_message();
    println!("-- third message --");
    one_message();
    */

    let _c = &**ROOT_CERT;
    let (_c, _p, _i) = &**CERT;
    let _c = &**SERVER_CONFIG;
    let _c = &**CLIENT_CONFIG;
}

fn one_message() {
    let (_, _, id) = CERT.as_ref();

    let nr = webpki::DNSNameRef::try_from_ascii_str(id).unwrap();
    let mut cli = rustls::ClientSession::new(&CLIENT_CONFIG, nr);
    let mut srv = rustls::ServerSession::new(&SERVER_CONFIG);

    srv.set_resumption_data(b"test-resume");

    cli.write_all(b"cli-to-srv").unwrap();
    srv.write_all(b"srv-to-cli").unwrap();

    let mut cli_post = Vec::new();
    let mut cli_pre = std::io::Cursor::new(Vec::new());

    let mut srv_post = Vec::new();
    let mut srv_pre = std::io::Cursor::new(Vec::new());

    let mut buf = [0_u8; 4096];
    for i in 0..5 {
        if let Some(s) = srv.received_resumption_data() {
            println!("resumption-data: {}", String::from_utf8_lossy(&s));
        }
        if let Some(sni) = srv.get_sni_hostname() {
            println!("sni: {}", sni);
        }

        // process cipher data coming from srv
        if cli.wants_read()
            && cli_pre.position() < cli_pre.get_ref().len() as u64
        {
            cli.read_tls(&mut cli_pre).unwrap();
            cli.process_new_packets().unwrap();
        }
        let size = cli.read(&mut buf).unwrap();
        cli_post.extend_from_slice(&buf[..size]);

        // process cipher data coming from cli
        if srv.wants_read()
            && srv_pre.position() < srv_pre.get_ref().len() as u64
        {
            srv.read_tls(&mut srv_pre).unwrap();
            srv.process_new_packets().unwrap();
        }
        let size = srv.read(&mut buf).unwrap();
        srv_post.extend_from_slice(&buf[..size]);

        // send any cipher data from cli to srv
        if cli.wants_write() {
            cli.write_tls(srv_pre.get_mut()).unwrap();
        }

        // send any cipher data from srv to cli
        if srv.wants_write() {
            srv.write_tls(cli_pre.get_mut()).unwrap();
        }

        println!(
            "{}: c_1: {}, c_2: {}, s_1: {}, s_2: {}",
            i,
            cli_pre.get_ref().len(),
            cli_post.len(),
            srv_pre.get_ref().len(),
            srv_post.len(),
        );
    }
    println!("srv got client cert: {}", cert_digest(srv.get_peer_certificates().unwrap().get(0).unwrap().as_ref()));
    println!("cli got server cert: {}", cert_digest(cli.get_peer_certificates().unwrap().get(0).unwrap().as_ref()));

    println!("cli got: {}", String::from_utf8_lossy(&cli_post));
    println!("srv got: {}", String::from_utf8_lossy(&srv_post));
}

const ALPN_HOLO_TNL: &'static [u8] = b"holo-tnl/0";

const CERT_KEYPAIR_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkxOEyiRyocjLRpQk
RE7/bOwmHtkdLLGQrlz23m4aKQOhRANCAATUDekPM40vfqOMxf00KZwRk6gSciHx
xkzPZovign1qmbu0vZstKoVLXoGvlA/Kral9txqhSEGqIL7TdbKyMMQz
-----END PRIVATE KEY-----"#;

static ROOT_CERT: Lazy<Arc<rcgen::Certificate>> = Lazy::new(|| {
    let id = "aKdjnmYOn1HVc_RwSdxR6qa.aQLW3d5D1nYiSSO2cOrcT7a";
    let mut params = rcgen::CertificateParams::new(vec![id.into()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::Any);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "KitsuneP2p Public CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Holochain Foundation");
    params.key_pair = Some(rcgen::KeyPair::from_pem(CERT_KEYPAIR_PEM).unwrap());
    let cert = rcgen::Certificate::from_params(params).unwrap();
    Arc::new(cert)
});

static CERT: Lazy<Arc<(rustls::Certificate, rustls::PrivateKey, String)>> =
    Lazy::new(|| {
        let root_cert = &**ROOT_CERT;

        let id = format!("a{}a.a{}a", nanoid::nanoid!(), nanoid::nanoid!());
        let mut params = rcgen::CertificateParams::new(vec![id.clone().into()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::Any);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "KitsuneP2p AutoGen Cert");
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let priv_key = cert.serialize_private_key_der();
        let priv_key = rustls::PrivateKey(priv_key);
        let cert = cert.serialize_der_with_signer(root_cert).unwrap();

        println!("cert: {}", cert.len());
        let cert = rustls::Certificate(cert);
        Arc::new((cert, priv_key, id))
    });

static SERVER_CONFIG: Lazy<Arc<rustls::ServerConfig>> = Lazy::new(|| {
    let (cert, priv_key, _) = CERT.as_ref();

    let root_cert = ROOT_CERT.as_ref();
    let root_cert = rustls::Certificate(root_cert.serialize_der().unwrap());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(&root_cert).unwrap();

    let mut server_conf = rustls::ServerConfig::with_ciphersuites(
        rustls::AllowAnyAuthenticatedClient::new(root_store),
        &[
            // restrict to tls 1.3 ciphers
            &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
            &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
            &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
        ],
    );
    server_conf
        .set_single_cert(vec![cert.clone()], priv_key.clone())
        .unwrap();
    server_conf.set_protocols(&[ALPN_HOLO_TNL.to_vec()]);

    // seems to require the same back-n-forth count
    // and adds slightly to the byte-count
    server_conf.ticketer = rustls::Ticketer::new();

    Arc::new(server_conf)
});

static CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let (cert, priv_key, _) = CERT.as_ref();

    let mut client_conf = rustls::ClientConfig::with_ciphersuites(&[
        // restrict to tls 1.3 ciphers
        &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
        &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
        &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
    ]);
    client_conf
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    client_conf
        .set_single_client_cert(vec![cert.clone()], priv_key.clone())
        .unwrap();
    client_conf.set_protocols(&[ALPN_HOLO_TNL.to_vec()]);

    // seems to require the same back-n-forth count
    // and adds slightly to the byte-count
    client_conf.enable_tickets = true;
    client_conf.enable_early_data = true;

    Arc::new(client_conf)
});

fn cert_digest(data: &[u8]) -> String {
    let cert_digest = blake2b_simd::Params::new()
        .hash_length(15)
        .to_state()
        .update(data)
        .finalize();
    base64::encode_config(cert_digest, base64::URL_SAFE_NO_PAD)
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        for c in presented_certs {
            println!("CHECK CERT: {} digest {:?}", c.0.len(), cert_digest(&c.0));
        }

        Ok(rustls::ServerCertVerified::assertion())
    }
}

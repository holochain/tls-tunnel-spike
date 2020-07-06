use once_cell::sync::Lazy;
use rustls::{
    Session,
};
use std::{
    io::{Read, Write},
    sync::Arc,
};

fn main() {
    println!("-- first message --");
    one_message();
    println!("-- second message --");
    one_message();
    println!("-- third message --");
    one_message();
}

fn one_message() {
    let nr = webpki::DNSNameRef::try_from_ascii_str("bla.com").unwrap();
    let mut cli = rustls::ClientSession::new(&CLIENT_CONFIG, nr);
    let mut srv = rustls::ServerSession::new(&SERVER_CONFIG);

    cli.write_all(b"cli-to-srv").unwrap();
    srv.write_all(b"srv-to-cli").unwrap();

    let mut cli_post = Vec::new();
    let mut cli_pre = std::io::Cursor::new(Vec::new());

    let mut srv_post = Vec::new();
    let mut srv_pre = std::io::Cursor::new(Vec::new());

    let mut buf = [0_u8; 4096];
    for i in 0..5 {
        // process cipher data coming from srv
        if cli.wants_read() && cli_pre.position() < cli_pre.get_ref().len() as u64 {
            cli.read_tls(&mut cli_pre).unwrap();
            cli.process_new_packets().unwrap();
        }
        let size = cli.read(&mut buf).unwrap();
        cli_post.extend_from_slice(&buf[..size]);

        // process cipher data coming from cli
        if srv.wants_read() && srv_pre.position() < srv_pre.get_ref().len() as u64 {
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

    println!("cli got: {}", String::from_utf8_lossy(&cli_post));
    println!("srv got: {}", String::from_utf8_lossy(&srv_post));
}

const ALPN_HOLO_TNL: &'static [u8] = b"holo-tnl/0";

static SERVER_CONFIG: Lazy<Arc<rustls::ServerConfig>> = Lazy::new(|| {
    let cert = rcgen::generate_simple_self_signed(
        vec!["bla.com".into()]
    ).unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert = cert.serialize_der().unwrap();
    let cert = rustls::Certificate(cert);

    let mut server_conf = rustls::ServerConfig::with_ciphersuites(
        rustls::NoClientAuth::new(),
        &[
            // restrict to tls 1.3 ciphers
            &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
            &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
            &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
        ],
    );
    server_conf.set_single_cert(vec![cert], priv_key).unwrap();
    server_conf.set_protocols(&[ALPN_HOLO_TNL.to_vec()]);

    // seems to require the same back-n-forth count
    // and adds slightly to the byte-count
    server_conf.ticketer = rustls::Ticketer::new();

    Arc::new(server_conf)
});

static CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut client_conf = rustls::ClientConfig::with_ciphersuites(
        &[
            // restrict to tls 1.3 ciphers
            &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
            &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
            &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
        ],
    );
    client_conf
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    client_conf.set_protocols(&[ALPN_HOLO_TNL.to_vec()]);

    // seems to require the same back-n-forth count
    // and adds slightly to the byte-count
    client_conf.enable_tickets = true;
    client_conf.enable_early_data = true;

    Arc::new(client_conf)
});

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
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

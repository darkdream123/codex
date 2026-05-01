//! Subprocess coverage for custom CA behavior that must build a real reqwest client.
//!
//! These tests intentionally run through `custom_ca_probe` and
//! `build_reqwest_client_for_subprocess_tests` instead of calling the helper in-process. The
//! detailed explanation of what "hermetic" means here lives in `codex_client::custom_ca`; these
//! tests add the process-level half of that contract by scrubbing inherited CA environment
//! variables before each subprocess launch. Most assertions here cover CA file selection, PEM
//! parsing, and user-facing errors. The TLS 1.3 probe goes further and performs a real HTTPS POST
//! against a test server using a certificate signed by the configured CA.

use codex_utils_cargo_bin::cargo_bin;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tempfile::TempDir;

const CODEX_CA_CERT_ENV: &str = "CODEX_CA_CERTIFICATE";
const PROBE_TLS13_ENV: &str = "CODEX_CUSTOM_CA_PROBE_TLS13";
const PROBE_URL_ENV: &str = "CODEX_CUSTOM_CA_PROBE_URL";
const SSL_CERT_FILE_ENV: &str = "SSL_CERT_FILE";

const TEST_CERT_1: &str = include_str!("fixtures/test-ca.pem");
const TEST_CERT_2: &str = include_str!("fixtures/test-intermediate.pem");
const TEST_TLS_CA_CERT: &str = include_str!("fixtures/test-tls-ca.pem");
const TEST_TLS_SERVER_CERT: &[u8] = include_bytes!("fixtures/test-tls-server.pem");
const TEST_TLS_SERVER_KEY: &[u8] = include_bytes!("fixtures/test-tls-server-key.pem");
const TRUSTED_TEST_CERT: &str = include_str!("fixtures/test-ca-trusted.pem");

struct Tls13TestServer {
    request_rx: mpsc::Receiver<Result<String, String>>,
    url: String,
}

fn write_cert_file(temp_dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = temp_dir.path().join(name);
    fs::write(&path, contents).unwrap_or_else(|error| {
        panic!("write cert fixture failed for {}: {error}", path.display())
    });
    path
}

fn probe_command() -> Command {
    let mut cmd = Command::new(
        cargo_bin("custom_ca_probe")
            .unwrap_or_else(|error| panic!("failed to locate custom_ca_probe: {error}")),
    );
    // `Command` inherits the parent environment by default, so scrub CA-related variables first or
    // these tests can accidentally pass/fail based on the developer shell or CI runner.
    cmd.env_remove(CODEX_CA_CERT_ENV);
    cmd.env_remove(PROBE_TLS13_ENV);
    cmd.env_remove(PROBE_URL_ENV);
    cmd.env_remove(SSL_CERT_FILE_ENV);
    cmd
}

fn run_probe(envs: &[(&str, &Path)]) -> std::process::Output {
    let mut cmd = probe_command();
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output()
        .unwrap_or_else(|error| panic!("failed to run custom_ca_probe: {error}"))
}

fn run_probe_posting_to_tls13_server(envs: &[(&str, &Path)], url: &str) -> std::process::Output {
    let mut cmd = probe_command();
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.env(PROBE_TLS13_ENV, "1");
    cmd.env(PROBE_URL_ENV, url);
    cmd.output()
        .unwrap_or_else(|error| panic!("failed to run custom_ca_probe: {error}"))
}

fn spawn_tls13_test_server() -> Tls13TestServer {
    codex_utils_rustls_provider::ensure_rustls_crypto_provider();
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .unwrap_or_else(|error| panic!("bind TLS test server: {error}"));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|error| panic!("set TLS test server nonblocking: {error}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("TLS test server addr: {error}"))
        .port();
    let certificate = CertificateDer::from_pem_slice(TEST_TLS_SERVER_CERT)
        .unwrap_or_else(|error| panic!("server certificate fixture: {error}"));
    let private_key = PrivateKeyDer::from_pem_slice(TEST_TLS_SERVER_KEY)
        .unwrap_or_else(|error| panic!("server key fixture: {error}"));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap_or_else(|error| panic!("TLS 1.3 server config: {error}")),
    );
    let (request_tx, request_rx) = mpsc::channel();

    thread::spawn(move || {
        let result = accept_tls13_request(listener, config);
        let _ = request_tx.send(result.map_err(|error| error.to_string()));
    });

    Tls13TestServer {
        request_rx,
        url: format!("https://127.0.0.1:{port}/oauth/token"),
    }
}

fn accept_tls13_request(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
) -> io::Result<String> {
    let stream = accept_with_timeout(listener, Duration::from_secs(5))?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let connection = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let request = read_http_request(&mut tls)?;
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
    tls.flush()?;
    Ok(request)
}

fn accept_with_timeout(listener: TcpListener, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for TLS test client",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_http_request(stream: &mut impl Read) -> io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
        if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = header_end + 4;
            let headers = String::from_utf8_lossy(&buffer[..body_start]);
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if buffer.len() >= body_start + content_length {
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

#[test]
fn uses_codex_ca_cert_env() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(&temp_dir, "ca.pem", TEST_CERT_1);

    let output = run_probe(&[(CODEX_CA_CERT_ENV, cert_path.as_path())]);

    assert!(output.status.success());
}

#[test]
fn falls_back_to_ssl_cert_file() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(&temp_dir, "ssl.pem", TEST_CERT_1);

    let output = run_probe(&[(SSL_CERT_FILE_ENV, cert_path.as_path())]);

    assert!(output.status.success());
}

#[test]
fn prefers_codex_ca_cert_over_ssl_cert_file() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(&temp_dir, "ca.pem", TEST_CERT_1);
    let bad_path = write_cert_file(&temp_dir, "bad.pem", "");

    let output = run_probe(&[
        (CODEX_CA_CERT_ENV, cert_path.as_path()),
        (SSL_CERT_FILE_ENV, bad_path.as_path()),
    ]);

    assert!(output.status.success());
}

#[test]
fn handles_multi_certificate_bundle() {
    let temp_dir = TempDir::new().expect("tempdir");
    let bundle = format!("{TEST_CERT_1}\n{TEST_CERT_2}");
    let cert_path = write_cert_file(&temp_dir, "bundle.pem", &bundle);

    let output = run_probe(&[(CODEX_CA_CERT_ENV, cert_path.as_path())]);

    assert!(output.status.success());
}

#[test]
fn posts_to_tls13_server_using_custom_ca_bundle() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(&temp_dir, "tls-ca.pem", TEST_TLS_CA_CERT);
    let server = spawn_tls13_test_server();

    let output =
        run_probe_posting_to_tls13_server(&[(CODEX_CA_CERT_ENV, cert_path.as_path())], &server.url);
    let server_result = server.request_rx.recv_timeout(Duration::from_secs(5));

    assert!(
        output.status.success(),
        "custom_ca_probe failed\nstdout:\n{}\nstderr:\n{}\nserver:\n{server_result:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let request = server_result
        .expect("TLS test server should report a request")
        .expect("TLS test server should accept the probe request");
    assert!(
        request.starts_with("POST /oauth/token HTTP/1.1"),
        "unexpected request:\n{request}"
    );
    assert!(
        request.contains("grant_type=authorization_code&code=test"),
        "unexpected request body:\n{request}"
    );
}

#[test]
fn rejects_empty_pem_file_with_hint() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(&temp_dir, "empty.pem", "");

    let output = run_probe(&[(CODEX_CA_CERT_ENV, cert_path.as_path())]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no certificates found in PEM file"));
    assert!(stderr.contains("CODEX_CA_CERTIFICATE"));
    assert!(stderr.contains("SSL_CERT_FILE"));
}

#[test]
fn rejects_malformed_pem_with_hint() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(
        &temp_dir,
        "malformed.pem",
        "-----BEGIN CERTIFICATE-----\nMIIBroken",
    );

    let output = run_probe(&[(CODEX_CA_CERT_ENV, cert_path.as_path())]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to parse PEM file"));
    assert!(stderr.contains("CODEX_CA_CERTIFICATE"));
    assert!(stderr.contains("SSL_CERT_FILE"));
}

#[test]
fn accepts_openssl_trusted_certificate() {
    let temp_dir = TempDir::new().expect("tempdir");
    let cert_path = write_cert_file(&temp_dir, "trusted.pem", TRUSTED_TEST_CERT);

    let output = run_probe(&[(CODEX_CA_CERT_ENV, cert_path.as_path())]);

    assert!(output.status.success());
}

#[test]
fn accepts_bundle_with_crl() {
    let temp_dir = TempDir::new().expect("tempdir");
    let crl = "-----BEGIN X509 CRL-----\nMIIC\n-----END X509 CRL-----";
    let bundle = format!("{TEST_CERT_1}\n{crl}");
    let cert_path = write_cert_file(&temp_dir, "bundle_crl.pem", &bundle);

    let output = run_probe(&[(CODEX_CA_CERT_ENV, cert_path.as_path())]);

    assert!(output.status.success());
}

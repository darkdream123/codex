//! Helper binary for exercising shared custom CA environment handling in tests.
//!
//! The shared reqwest client honors `CODEX_CA_CERTIFICATE` and `SSL_CERT_FILE`, but those
//! environment variables are process-global and unsafe to mutate in parallel test execution. This
//! probe keeps the behavior under test while letting integration tests (`tests/ca_env.rs`) set
//! env vars per-process, proving:
//!
//! - env precedence is respected,
//! - multi-cert PEM bundles load,
//! - error messages guide users when CA files are invalid.
//! - optional HTTPS probes can complete a request through the constructed client.
//!
//! The detailed explanation of what "hermetic" means here lives in `codex_client::custom_ca`.
//! This binary exists so the tests can exercise
//! [`codex_client::build_reqwest_client_for_subprocess_tests`] in a separate process without
//! duplicating client-construction logic.

use std::env;
use std::process;
use std::time::Duration;

const PROBE_TLS13_ENV: &str = "CODEX_CUSTOM_CA_PROBE_TLS13";
const PROBE_URL_ENV: &str = "CODEX_CUSTOM_CA_PROBE_URL";

fn main() {
    let target_url = env::var(PROBE_URL_ENV).ok();
    let mut builder = reqwest::Client::builder();
    if target_url.is_some() {
        builder = builder.timeout(Duration::from_secs(5));
    }
    if env::var_os(PROBE_TLS13_ENV).is_some() {
        builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_3);
    }

    match codex_client::build_reqwest_client_for_subprocess_tests(builder) {
        Ok(client) => {
            if let Some(url) = target_url
                && let Err(error) = post_probe_request(&client, &url)
            {
                eprintln!("{error}");
                process::exit(1);
            }
            println!("ok");
        }
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn post_probe_request(client: &reqwest::Client, url: &str) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to create probe runtime: {error}"))?;

    runtime.block_on(async {
        let response = client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=authorization_code&code=test")
            .send()
            .await
            .map_err(|error| format!("probe request failed: {error:?}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("failed to read probe response body: {error}"))?;
        if !status.is_success() {
            return Err(format!("probe request returned {status}: {body}"));
        }
        if body != "ok" {
            return Err(format!("probe response body mismatch: {body}"));
        }
        Ok(())
    })
}

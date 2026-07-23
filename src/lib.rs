// Copyright (c) 2026 Privasys.
// Licensed under the MIT License. See LICENSE file for details.

//! # WASM Example App
//!
//! A minimal first app for the Enclave OS WASM runtime. Nine exported
//! functions exercise the core host capabilities — no configuration
//! step, no freeze gate, so it deploys and runs straight away.
//!
//! For the configure-then-freeze pattern (inject a secret at deploy
//! time, advertise its hash on the RA-TLS leaf, gate every other
//! export until configured) see the companion repository
//! `wasm-app-example-with-config`.
//!
//! | Function | Tests |
//! |----------|-------|
//! | `hello` | Basic smoke test — no host imports |
//! | `get-random` | `wasi:random` → RDRAND inside SGX |
//! | `get-time` | `wasi:clocks/wall-clock` → OCALL |
//! | `kv-store` | `wasi:filesystem` → sealed KV store |
//! | `kv-read` | `wasi:filesystem` → sealed KV store |
//! | `fetch-headlines` | `privasys:enclave-os/https` → TLS egress |
//! | `analyse-data` | Records, enums, options — MCP tool demo |
//! | `auth-hello` | Authenticated-only endpoint (OIDC / FIDO2) |
//! | `role-hello` | Role-gated endpoint (requires "hello-role") |

#[allow(warnings)]
mod bindings;

use bindings::Guest;

struct TestApp;

impl Guest for TestApp {
    // ── 1. Hello World ────────────────────────────────────────────

    fn hello() -> String {
        "Hello, World!".to_string()
    }

    // ── 2. Get Random ─────────────────────────────────────────────

    fn get_random() -> u32 {
        let bytes = bindings::wasi::random::random::get_random_bytes(4);
        let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // Map to 1..=100
        (raw % 100) + 1
    }

    // ── 3. Get Time ───────────────────────────────────────────────

    fn get_time() -> String {
        let dt = bindings::wasi::clocks::wall_clock::now();
        format!("{}.{:09}", dt.seconds, dt.nanoseconds)
    }

    // ── 4. Store data in KV ───────────────────────────────────────

    fn kv_store(key: String, value: String) -> String {
        match kv::write(&key, &value) {
            Ok(()) => format!("stored: {key}"),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── 5. Read from KV ─────────────────────────────────────────

    fn kv_read(key: String) -> String {
        kv::read(&key).unwrap_or_else(|| format!("error: key not found: {key}"))
    }

    // ── 6. Fetch headlines from lemonde.fr ─────────────────────────

    fn fetch_headlines() -> String {
        use bindings::privasys::enclave_os::https;

        // HTTPS GET — TLS terminates inside the enclave.
        // No RA-TLS policy, Mozilla root bundle.
        let request = https::Request {
            method: https::Method::Get,
            url: "https://www.lemonde.fr".into(),
            headers: vec![
                ("User-Agent".into(), "wasm-test-app/1.0".into()),
                ("Accept".into(), "text/html".into()),
            ],
            body: None,
            ratls: None,
            ca_roots_der: None,
        };
        let resp = match https::fetch(&request) {
            Ok(r) => r,
            Err(e) => return format!("error: {e}"),
        };

        if resp.status != 200 {
            return format!("error: HTTP {}", resp.status);
        }

        let html = String::from_utf8_lossy(&resp.body);
        let titles = extract_titles(&html, 10);

        if titles.is_empty() {
            "No titles found".to_string()
        } else {
            titles
                .iter()
                .enumerate()
                .map(|(i, t)| format!("{}. {}", i + 1, t))
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    // ── 7. Analyse numeric data ───────────────────────────────────

    fn analyse_data(values: Vec<f64>, config: bindings::AnalysisConfig) -> String {
        if values.is_empty() {
            return match config.format {
                bindings::OutputFormat::Json => r#"{"error":"empty input"}"#.to_string(),
                _ => "error: empty input".to_string(),
            };
        }

        let count = values.len();
        let sum: f64 = values.iter().sum();
        let mean = sum / count as f64;
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        let label = config.label.as_deref().unwrap_or("result");

        match config.format {
            bindings::OutputFormat::Text => {
                if config.include_stats {
                    format!(
                        "{label}: count={count}, sum={sum:.4}, mean={mean:.4}, min={min:.4}, max={max:.4}"
                    )
                } else {
                    format!("{label}: count={count}, sum={sum:.4}")
                }
            }
            bindings::OutputFormat::Json => {
                if config.include_stats {
                    format!(
                        r#"{{"label":"{label}","count":{count},"sum":{sum:.4},"mean":{mean:.4},"min":{min:.4},"max":{max:.4}}}"#
                    )
                } else {
                    format!(
                        r#"{{"label":"{label}","count":{count},"sum":{sum:.4}}}"#
                    )
                }
            }
            bindings::OutputFormat::Csv => {
                if config.include_stats {
                    format!("label,count,sum,mean,min,max\n{label},{count},{sum:.4},{mean:.4},{min:.4},{max:.4}")
                } else {
                    format!("label,count,sum\n{label},{count},{sum:.4}")
                }
            }
        }
    }

    // ── 8. Auth Hello (authenticated-only) ─────────────────────────

    fn auth_hello() -> bindings::AuthHelloResult {
        use bindings::privasys::enclave_os::auth;

        // Auth is enforced by the runtime before this function is called.
        // Use the auth import to read back the caller's identity and roles.
        let caller = auth::get_caller_id().unwrap_or_else(|e| format!("unknown ({e})"));
        let roles = auth::get_my_roles().unwrap_or_else(|_| Vec::new());
        let ts = bindings::wasi::clocks::wall_clock::now();
        bindings::AuthHelloResult {
            caller,
            roles,
            message: "Hello from inside the enclave — you are authenticated".to_string(),
            timestamp_seconds: ts.seconds,
            timestamp_nanos: ts.nanoseconds,
            enclave: "sgx".to_string(),
        }
    }

    // ── 8b. Priced Hello (paid API — x-privasys.price) ──────────────

    fn priced_hello() -> bindings::AuthHelloResult {
        use bindings::privasys::enclave_os::auth;

        // Payment is enforced by the attested runtime, not by this code:
        // the @price annotation rides the measured configuration, the
        // runtime requires an authenticated caller, and the fee is
        // recorded only when this function returns successfully.
        let caller = auth::get_caller_id().unwrap_or_else(|e| format!("unknown ({e})"));
        let roles = auth::get_my_roles().unwrap_or_else(|_| Vec::new());
        let ts = bindings::wasi::clocks::wall_clock::now();
        bindings::AuthHelloResult {
            caller,
            roles,
            message: "Hello from inside the enclave — this call charged you 5,000 credits (the developer earns 85%)".to_string(),
            timestamp_seconds: ts.seconds,
            timestamp_nanos: ts.nanoseconds,
            enclave: "sgx".to_string(),
        }
    }

    // ── 8c. Priced Hello, wallet-exempt (x-privasys.price) ──────────

    fn priced_hello_exempt_wallet() -> bindings::AuthHelloResult {
        use bindings::privasys::enclave_os::auth;

        // The fee and the wallet exemption are both enforced by the attested
        // runtime before this function runs: a wallet-class caller is charged
        // nothing, anyone else must have pre-approved exactly 10,000 credits.
        let caller = auth::get_caller_id().unwrap_or_else(|e| format!("unknown ({e})"));
        let roles = auth::get_my_roles().unwrap_or_else(|_| Vec::new());
        let ts = bindings::wasi::clocks::wall_clock::now();
        bindings::AuthHelloResult {
            caller,
            roles,
            message: "Hello from inside the enclave — this call charges 10,000 credits, but wallet users are exempt".to_string(),
            timestamp_seconds: ts.seconds,
            timestamp_nanos: ts.nanoseconds,
            enclave: "sgx".to_string(),
        }
    }

    // ── 9. Role Hello (requires "hello-role") ───────────────────────

    fn role_hello() -> bindings::AuthHelloResult {
        use bindings::privasys::enclave_os::auth;

        // Auth + role check is enforced by the runtime before this function
        // is called.  Use the auth import to confirm our identity.
        let caller = auth::get_caller_id().unwrap_or_else(|e| format!("unknown ({e})"));
        let roles = auth::get_my_roles().unwrap_or_else(|_| Vec::new());
        let ts = bindings::wasi::clocks::wall_clock::now();
        bindings::AuthHelloResult {
            caller,
            roles,
            message: "Hello from inside the enclave — you have the hello-role".to_string(),
            timestamp_seconds: ts.seconds,
            timestamp_nanos: ts.nanoseconds,
            enclave: "sgx".to_string(),
        }
    }
}

// ── Sealed-KV helpers ─────────────────────────────────────────────
//
// Every preopened directory the enclave exposes to the app is a
// per-app sealed KV store, so there is no observable difference
// between "secret" and "non-secret" reads/writes at this layer —
// one pair of helpers serves both. They live in their own module
// to avoid shadowing the exported `kv_store` / `kv_read` methods
// (the exported names are forced by the WIT contract).

mod kv {
    use crate::bindings::wasi::filesystem::{preopens, types as fs};

    pub fn write(key: &str, value: &str) -> Result<(), String> {
        // Get the preopened root directory (backed by sealed KV store)
        let dirs = preopens::get_directories();
        if dirs.is_empty() {
            return Err("no preopened directories".into());
        }
        let root = &dirs[0].0;

        // Open (or create) the file — each "file" is a KV entry
        let fd = root.open_at(
            fs::PathFlags::empty(),
            key,
            fs::OpenFlags::CREATE | fs::OpenFlags::TRUNCATE,
            fs::DescriptorFlags::WRITE,
        ).map_err(|e| format!("open failed: {e:?}"))?;

        // Write the value
        fd.write(value.as_bytes(), 0).map_err(|e| format!("write failed: {e:?}"))?;

        // Sync flushes the encrypted data to the host KV store
        fd.sync_data().map_err(|e| format!("sync failed: {e:?}"))?;

        Ok(())
    }

    pub fn read(key: &str) -> Option<String> {
        let dirs = preopens::get_directories();
        if dirs.is_empty() {
            return None;
        }
        let root = &dirs[0].0;

        let fd = root.open_at(
            fs::PathFlags::empty(),
            key,
            fs::OpenFlags::empty(),
            fs::DescriptorFlags::READ,
        ).ok()?;

        let stat = fd.stat().ok()?;
        let (data, _) = fd.read(stat.size, 0).ok()?;
        String::from_utf8(data).ok()
    }
}

// ── HTML title extraction (minimal, no dependencies) ──────────────

/// Extract up to `max` text contents from `<h3>…</h3>` tags.
fn extract_titles(html: &str, max: usize) -> Vec<String> {
    let mut titles = Vec::new();
    let mut pos = 0;

    while titles.len() < max {
        // Find next <h3
        let tag_start = match html[pos..].find("<h3") {
            Some(i) => pos + i,
            None => break,
        };
        // Find the closing > of the opening tag
        let content_start = match html[tag_start..].find('>') {
            Some(i) => tag_start + i + 1,
            None => break,
        };
        // Find </h3>
        let content_end = match html[content_start..].find("</h3>") {
            Some(i) => content_start + i,
            None => break,
        };

        let raw = &html[content_start..content_end];
        let text = strip_tags(raw);
        let text = text.trim();

        if !text.is_empty() {
            titles.push(text.to_string());
        }

        pos = content_end + 5; // skip past </h3>
    }

    titles
}

/// Strip HTML tags from a string fragment.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

bindings::export!(TestApp with_types_in bindings);

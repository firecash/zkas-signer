//! Embedded ZKas wallet engine for a native mobile shell.
//!
//! Runs `zkas_walletd::serve()` in-process on a loopback port, exactly as the Tauri
//! desktop shell does — the Capacitor WebView then talks to `http://127.0.0.1:<port>`.
//! The seed and full viewing key never leave the device; the engine pulls compact
//! block records from a public node's gRPC and trial-decrypts locally.

uniffi::setup_scaffolding!();

use once_cell::sync::Lazy;
use std::net::{SocketAddr, TcpListener};
use std::sync::Mutex;

struct Running {
    shutdown: tokio::sync::oneshot::Sender<()>,
    runtime: tokio::runtime::Runtime,
    port: u16,
}

static ENGINE: Lazy<Mutex<Option<Running>>> = Lazy::new(|| Mutex::new(None));

/// Start the engine against `node_addr` (host:port gRPC), storing wallet data under
/// `wallet_dir`, optionally unlocked with `secret`. Returns the bound loopback port,
/// or 0 on failure. Idempotent: a second call while running returns the live port.
#[uniffi::export]
pub fn start(node_addr: String, wallet_dir: String, secret: Option<String>) -> u16 {
    let mut guard = ENGINE.lock().unwrap();
    if let Some(r) = guard.as_ref() {
        return r.port;
    }
    // Bind a free loopback port up front so the caller has the port immediately.
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return 0,
    };
    drop(listener);
    let listen: SocketAddr = ([127, 0, 0, 1], port).into();

    // Use every core: the wallet is the only thing running, so there is no reason to
    // hold cores back the way a shared server would. Trial-decryption, page ingest and
    // proving all scale with this.
    let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(2);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cores.max(2))
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return 0,
    };

    let cfg = zkas_walletd::Config {
        rpc_server: node_addr,
        listen,
        wallet_dir,
        network: "mainnet".to_string(),
        allow_origin: vec![
            "http://localhost".into(),
            "https://localhost".into(),
            "capacitor://localhost".into(),
        ],
        allow_default_token: false,
        wallet_secret: secret,
        tls: None,
        require_bearer: None,
        allow_custodial: true,
        max_concurrent_proves: 1,
        // Single wallet on a phone: nobody borrows a shared chain tree, and building it
        // from genesis is a multi-minute grind that only delays the first send. The
        // wallet's own near-tip frontier tree serves its spends directly.
        build_shared_tree: false,
        auto_consolidate: None,
        // Max-performance profile for a single on-device wallet. `default()` clamps
        // page_decode_threads to 8 for a many-wallet server; here one wallet owns the
        // machine, so give trial-decryption every core. The other fields stay at the
        // sensible single-wallet defaults.
        resources: {
            let mut r = zkas_walletd::ResourceLimits::default();
            r.page_decode_threads = cores.max(1);
            r.sync_wallets = 1;
            r.load_wallets = 1;
            r.warm_wallets = 1;
            r.page_cache_entries = 256;
            // Concurrent page read-ahead: hide node round-trip latency on a fetch-bound
            // phone by keeping several full pages in flight at once (default is 1).
            r.prefetch_depth = 8;
            // Keep prefetched pages warm long enough for a slow device to reach them.
            r.page_cache_ttl_secs = 60;
            r
        },
        idle_timeout: None,
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    runtime.spawn(async move {
        let _ = zkas_walletd::serve(cfg, rx).await;
    });
    *guard = Some(Running { shutdown: tx, runtime, port });
    port
}

/// Stop the engine and release its port. Safe to call when not running.
#[uniffi::export]
pub fn stop() {
    if let Some(r) = ENGINE.lock().unwrap().take() {
        let _ = r.shutdown.send(());
        r.runtime.shutdown_background();
    }
}

/// The engine's current loopback port, or 0 if not running.
#[uniffi::export]
pub fn port() -> u16 {
    ENGINE.lock().unwrap().as_ref().map(|r| r.port).unwrap_or(0)
}

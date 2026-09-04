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

// ---------------------------------------------------------------------------
// In-memory ring-buffer logger. The daemon logs through the `log` facade, but a
// mobile shell installs no logger, so every message is dropped and a stuck engine
// is a black box. Capture the recent lines here and hand them to the app on demand.
const LOG_RING_CAP: usize = 3000;
static LOG_RING: Lazy<Mutex<std::collections::VecDeque<String>>> =
    Lazy::new(|| Mutex::new(std::collections::VecDeque::with_capacity(256)));
static LOGGER_SET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct RingLogger;
impl log::Log for RingLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::max_level()
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("{secs} [{}] {}: {}", record.level(), record.target(), record.args());
        if let Ok(mut r) = LOG_RING.lock() {
            while r.len() >= LOG_RING_CAP {
                r.pop_front();
            }
            r.push_back(line);
        }
    }
    fn flush(&self) {}
}

/// Install the ring logger once; later calls only adjust the level.
fn install_logger() {
    if LOGGER_SET.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let _ = log::set_boxed_logger(Box::new(RingLogger));
    log::set_max_level(log::LevelFilter::Info);
}

/// Recent engine log lines (oldest first), for the app's debug view.
#[uniffi::export]
pub fn logs() -> String {
    LOG_RING
        .lock()
        .map(|r| r.iter().cloned().collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

/// Turn debug-level logging on or off at runtime (default info).
#[uniffi::export]
pub fn set_debug_logs(on: bool) {
    log::set_max_level(if on { log::LevelFilter::Debug } else { log::LevelFilter::Info });
}

/// Start the engine against `node_addr` (host:port gRPC), storing wallet data under
/// `wallet_dir`, optionally unlocked with `secret`. Returns the bound loopback port,
/// or 0 on failure. Idempotent: a second call while running returns the live port.
#[uniffi::export]
pub fn start(node_addr: String, wallet_dir: String, secret: Option<String>, socks: Option<String>) -> u16 {
    install_logger();
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
        // Tor: route the node connection through Orbot's SOCKS when the app asked for it.
        node_socks_proxy: socks,
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

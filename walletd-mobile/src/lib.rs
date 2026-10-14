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

/// Make a panic inside the engine say so, once, to the Android log and the engine's own
/// ring buffer.
///
/// The engine is native threads in the app's process, so a panic here produces no Java
/// stack trace and nothing in the app's log view — the thread dies, or the process does,
/// and the only report is "it closed during the sync". Three releases were spent reasoning
/// about which layer that came from. The default hook writes to stderr, which on Android
/// goes nowhere a user can retrieve.
///
/// `log::error!` reaches both the logcat bridge and `logs()`, which the app already shows
/// and users already send, so a panic becomes a line someone can paste.
fn install_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let where_ = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "unknown location".to_string());
            // `payload_as_str` is not stable here; handle the two shapes panics actually use.
            let what = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            log::error!("ENGINE PANIC at {where_}: {what}");
            previous(info);
        }));
    });
}

/// Take the engine lock without caring whether a previous panic poisoned it.
///
/// Every call site used `.lock().unwrap()`, so one panic while the lock was held made the
/// mutex poisoned for the life of the process — and then `start`, `stop` and `port` all
/// panicked on every later call. `port()` is polled about once a second by the app, so a
/// single unlucky panic turned into a permanent one, and the engine could never be
/// restarted to recover. The guarded state is a plain `Option<Running>` whose invariants
/// do not depend on the panicking section having completed, so recovering it is correct;
/// refusing to is what makes one fault terminal.
fn engine_lock() -> std::sync::MutexGuard<'static, Option<Running>> {
    ENGINE.lock().unwrap_or_else(|poisoned| {
        log::error!("engine lock was poisoned by an earlier panic; recovering it");
        poisoned.into_inner()
    })
}

/// How much memory this app is actually allowed, in MB, as the Android layer reports it.
///
/// `walletd` sizes its resident-wallet cache from `/proc/meminfo` MemAvailable, which is
/// the right signal on a server and the wrong one here: on Android the limit that gets you
/// killed is the PER-APP heap cap, which is a fraction of the device's free memory. A phone
/// with 2 GB free therefore sized the cache as if it had 2 GB to spend, and the clamp's
/// floor of 4 meant even a starved device kept four wallets resident — the exact count in
/// the "app closes during the sync, once per wallet" report.
static MEM_BUDGET_MB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Tell the engine this app's memory ceiling (ActivityManager.getMemoryClass, or the large
/// class when largeHeap is set). 0 = unknown, keep walletd's own sizing.
#[uniffi::export]
pub fn set_memory_budget_mb(mb: u32) {
    MEM_BUDGET_MB.store(mb, std::sync::atomic::Ordering::Relaxed);
    log::info!("memory budget for this app: {mb} MB");
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
    install_panic_hook();
    let mut guard = engine_lock();
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
        // Off, per the field's own guidance: the multi-party coordinator role sees
        // every participant's viewing key, so it is a deployment decision and not
        // something a phone should offer by accident. The embedded engine links
        // walletd as a library, so a new Config field breaks this build until it
        // is set here — which is how the security-fork rebuild surfaced it.
        enable_multiparty: false,
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
            // Residency is a CACHE of the on-disk checkpoint, so capping it costs a
            // reload when the user switches wallets and nothing else. Budget ~192 MB per
            // resident wallet, matching walletd's own divisor, against the app's ceiling
            // rather than the device's free memory — and keep at least one, since the
            // wallet being used has to be resident. Only one wallet syncs at a time here
            // (`sync_wallets = 1`), so holding three more buys reopen speed on the one
            // platform that cannot afford it.
            let budget = MEM_BUDGET_MB.load(std::sync::atomic::Ordering::Relaxed);
            if budget > 0 {
                // Leave half the ceiling for everything else in the process: the WebView,
                // the decoded-leaf caches and the checkpoint being serialised, which is
                // the whole leaf stream until a wallet first catches up.
                r.max_resident_wallets = ((budget / 2) / 192).max(1) as usize;
                log::info!(
                    "resident wallet cap {} (from a {} MB app budget, not device free memory)",
                    r.max_resident_wallets, budget
                );
            } else {
                // No budget reported: 2 is the safe default for a phone. walletd's formula
                // floors at 4, which is more than a memory-starved device can hold.
                r.max_resident_wallets = 2;
            }
            r.warm_wallets = 1;
            // Concurrent page read-ahead: hide node round-trip latency on a fetch-bound
            // phone by keeping several full pages in flight at once (default is 1).
            r.prefetch_depth = 8;
            // Keep prefetched pages warm long enough for a slow device to reach them.
            r.page_cache_ttl_secs = 60;
            // The cache exists to share decoded pages BETWEEN wallets; this daemon has
            // one, which reads each page exactly once. It only needs the pages in flight
            // (the read-ahead plus the one being ingested and its one-page prefetch): the
            // old 256 held ~118 MB of dead decoded pages through a restore, on top of the
            // loaded checkpoint, which is the moment Android low-memory-kills the app.
            r.page_cache_entries = r.prefetch_depth + 2;
            // A phone must never be handed a whole-chain scan: refuse and explain.
            r.max_full_scan_blocks = Some(1_500_000);
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
    if let Some(r) = engine_lock().take() {
        let _ = r.shutdown.send(());
        // `shutdown_background()` dropped the serve task at its next await point — which
        // was BEFORE `flush_checkpoints_on_exit` ran — so every stop (node switch, Tor
        // toggle, the background worker) threw away up to CHECKPOINT_EVERY blocks of scan
        // progress that the next start then redid. Give the graceful path (a bounded ≤5 s
        // connection drain, then the checkpoint flush) time to finish before tearing the
        // runtime down.
        r.runtime.shutdown_timeout(std::time::Duration::from_secs(15));
    }
}

/// The engine's current loopback port, or 0 if not running.
/// Give back everything the engine can rebuild, and report how many decoded leaves went.
///
/// Call this from Android's onTrimMemory. The system warns before it starts killing, and an
/// engine that ignores the warning is the one that gets killed — losing the user's scan
/// progress and forcing a cold restore on the next open, which is a median 8.8 s and a p90
/// of 93.6 s of "Opening your wallet".
///
/// What it drops is the decoded leaf cache: ~32 bytes per leaf, tens to hundreds of MB, and
/// pure cache — rebuilt lazily on the next witness climb. Nothing persisted, nothing the
/// wallet cannot recreate. Non-blocking: a wallet mid-scan is skipped rather than waited
/// on, because stalling while the system is deciding whether to kill you is the one thing
/// that must not happen here.
#[uniffi::export]
pub fn release_memory() -> u64 {
    zkas_walletd::release_memory() as u64
}

#[uniffi::export]
pub fn port() -> u16 {
    engine_lock().as_ref().map(|r| r.port).unwrap_or(0)
}

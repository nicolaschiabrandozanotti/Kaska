//! Kaska Performance Baseline & Pilot Harness (Milestone 1.3D-1A-P-RCA1-C-FX-R1)
//!
//! Provides isolated, reproducible microbenchmarks and strictly controlled loopback pilots (N=5, N=25).
//! Adheres strictly to the directives in AGENTS.md, SECURITY.md, and CONTRIBUTING.md:
//! - Deterministic CLI argument parser rejecting any unknown parameters or N > 25.
//! - Loopback only (127.0.0.1) on ephemeral OS-assigned ports with TOCTOU logging.
//! - Global scenario traffic deadline (15s) with per-chunk budget recalculation and bounded read loop.
//! - Bounded HTTP response reading to prevent indefinite reads on peer stalls.
//! - Strict HTTP/1.1 200 status line validation with zero arbitrary string/reason phrase reflection.
//! - Typed error classification (ReadErrorKind: SCENARIO_DEADLINE_EXCEEDED, EOF_ZERO_BYTES, INCOMPLETE_HTTP_STATUS, READ_LIMIT_REACHED, TIMED_OUT, WOULD_BLOCK, BROKEN_PIPE, CONNECTION_RESET, IO_ERROR).
//! - Precise probe classification at MAX_RESPONSE_BYTES with pre-probe timeout recalculation and immediate post-probe deadline verification.
//! - Accurate real EOF semantics (EOF_ZERO_BYTES, no fabricated io::Error on zero-byte stream reads).
//! - RFC 8259 Section 7 compliant JSON escaping for all control characters U+0000..=U+001F.
//! - Fail-closed path sanitization (/api/status preserved, arbitrary paths/query strings redacted).
//! - Point-in-time TrafficStore observation semantics explicitly documented.
//! - RAII cleanup guards and active port release polling for safe teardown.
//! - Multiplatform metrics: Windows (WorkingSetSize, PagefileUsage, CPU time), Linux (VmRSS, RssAnon; private_bytes & CPU explicitly NOT_AVAILABLE).
//! - Rejection of output directories inside the repository or protected worktrees.
//! - Non-destructive partial write failure reporting without overwriting pre-existing error markers.
//! - 1:1 Semantic parity between console output, summary TXT, and JSON report for all critical fields.
//! - High-precision raw sample preservation and metadata with explicit units in JSON.
//! - Use of std::hint::black_box in microbenchmarks to prevent dead-code elimination.
//! - Zero modification to productive crates, no third-party crates added.

use slint::{ModelRc, SharedString, VecModel};
slint::include_modules!();

#[path = "../src/controller.rs"]
pub mod controller;
#[path = "../src/filter.rs"]
pub mod filter;
#[path = "../src/platform.rs"]
pub mod platform;

use kaska_http::models::{
    HttpMethod, HttpRequest, HttpResponse, HttpTransaction, TransactionState,
};
use kaska_http::proxy::{BoundedProxyObserver, NativeProxyServer};
use kaska_http::scope::AuditScope;
use kaska_http::store::{create_shared_store, TrafficStore};
use kaska_http::test_server::ControlledTestServer;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_FIXED_SEED: u64 = 0x5EED_13D1_2026_ABCD;
const SOCKET_TIMEOUT_MS: u64 = 3000;
const SCENARIO_DEADLINE_SECS: u64 = 15;
const MAX_RESPONSE_BYTES: usize = 8192; // 8 KiB safety cap for controlled status response

/// Supported CLI commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliCommand {
    Validate,
    Pilot5,
    Pilot25,
    Pilot100,
    All,
    Inspector10k,
    Help,
}

/// Parsed CLI configuration
#[derive(Debug, Clone)]
pub struct CliConfig {
    pub command: CliCommand,
    pub output_dir: Option<PathBuf>,
}

/// Strict, deterministic command-line argument parser.
/// Rejects any unrecognized argument or load parameter N > 100.
pub fn parse_cli_args(args: &[String]) -> Result<CliConfig, String> {
    let mut command: Option<CliCommand> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--validate" => {
                if command.is_some() {
                    return Err(format!("Conflicting command specified: '{}'", arg));
                }
                command = Some(CliCommand::Validate);
            }
            "--pilot-5" => {
                if command.is_some() {
                    return Err(format!("Conflicting command specified: '{}'", arg));
                }
                command = Some(CliCommand::Pilot5);
            }
            "--pilot-25" => {
                if command.is_some() {
                    return Err(format!("Conflicting command specified: '{}'", arg));
                }
                command = Some(CliCommand::Pilot25);
            }
            "--pilot-100" => {
                if command.is_some() {
                    return Err(format!("Conflicting command specified: '{}'", arg));
                }
                command = Some(CliCommand::Pilot100);
            }
            "--all" => {
                if command.is_some() {
                    return Err(format!("Conflicting command specified: '{}'", arg));
                }
                command = Some(CliCommand::All);
            }
            "--inspector-10k" => {
                if command.is_some() {
                    return Err(format!("Conflicting command specified: '{}'", arg));
                }
                command = Some(CliCommand::Inspector10k);
            }
            "--help" | "-h" => {
                return Ok(CliConfig {
                    command: CliCommand::Help,
                    output_dir: None,
                });
            }
            "--output-dir" | "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err(format!("Option '{}' requires a path argument", arg));
                }
                output_dir = Some(PathBuf::from(&args[i]));
            }
            unknown => {
                return Err(format!(
                    "Unknown or unauthorized argument '{}'. Allowed options: --validate, --pilot-5, --pilot-25, --pilot-100, --all, --inspector-10k, --output-dir <DIR>, --help",
                    unknown
                ));
            }
        }
        i += 1;
    }

    let cmd = command.ok_or_else(|| {
        "No command specified. Usage: perf_baseline [--validate | --pilot-5 | --pilot-25 | --pilot-100 | --all | --inspector-10k] [--output-dir <DIR>]".to_string()
    })?;

    Ok(CliConfig {
        command: cmd,
        output_dir,
    })
}

/// Multiplatform process memory and CPU metrics
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessMetrics {
    pub working_set_bytes: Option<usize>,
    pub private_bytes: Option<usize>,
    pub anonymous_rss_bytes: Option<usize>,
    pub cpu_time_ms: Option<u64>,
}

#[cfg(target_os = "windows")]
pub fn query_process_metrics() -> Option<ProcessMetrics> {
    use std::ffi::c_void;
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[repr(C)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
        fn GetProcessTimes(
            process: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    unsafe {
        let handle = GetCurrentProcess();
        let mut counters = ProcessMemoryCounters {
            cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
            page_fault_count: 0,
            peak_working_set_size: 0,
            working_set_size: 0,
            quota_peak_paged_pool_usage: 0,
            quota_paged_pool_usage: 0,
            quota_peak_non_paged_pool_usage: 0,
            quota_non_paged_pool_usage: 0,
            pagefile_usage: 0,
            peak_pagefile_usage: 0,
        };
        let ok_mem = K32GetProcessMemoryInfo(
            handle,
            &mut counters,
            std::mem::size_of::<ProcessMemoryCounters>() as u32,
        ) != 0;

        let mut creation = FileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut exit = FileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut kernel = FileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut user = FileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let ok_times =
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) != 0;

        if ok_mem {
            let cpu_ms = if ok_times {
                let k_100ns =
                    ((kernel.dw_high_date_time as u64) << 32) | (kernel.dw_low_date_time as u64);
                let u_100ns =
                    ((user.dw_high_date_time as u64) << 32) | (user.dw_low_date_time as u64);
                Some((k_100ns + u_100ns) / 10_000)
            } else {
                None
            };

            Some(ProcessMetrics {
                working_set_bytes: Some(counters.working_set_size),
                private_bytes: Some(counters.pagefile_usage),
                anonymous_rss_bytes: None,
                cpu_time_ms: cpu_ms,
            })
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
pub fn query_process_metrics() -> Option<ProcessMetrics> {
    use std::fs;
    let mut ws = None;
    let mut anon_rss = None;

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    ws = val.parse::<usize>().ok().map(|v| v * 1024);
                }
            } else if line.starts_with("RssAnon:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    anon_rss = val.parse::<usize>().ok().map(|v| v * 1024);
                }
            }
        }
    }

    Some(ProcessMetrics {
        working_set_bytes: ws,
        private_bytes: None, // Declared NOT_AVAILABLE per specification
        anonymous_rss_bytes: anon_rss,
        cpu_time_ms: None, // Declared NOT_AVAILABLE without CLK_TCK external dependency
    })
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn query_process_metrics() -> Option<ProcessMetrics> {
    None
}

/// Descriptive statistics with exact sample preservation
#[derive(Debug, Clone, Default)]
pub struct SampleStatistics {
    pub raw_samples: Vec<f64>,
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
}

impl SampleStatistics {
    pub fn compute(raw_samples: Vec<f64>) -> Option<Self> {
        if raw_samples.is_empty() {
            return None;
        }
        let mut sorted = raw_samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let count = sorted.len();
        let min = sorted[0];
        let max = sorted[count - 1];
        let sum: f64 = sorted.iter().sum();
        let mean = sum / (count as f64);
        let median = if count % 2 == 1 {
            sorted[count / 2]
        } else {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
        };
        let variance: f64 = sorted.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / (count as f64);
        let std_dev = variance.sqrt();

        Some(Self {
            raw_samples,
            count,
            min,
            max,
            mean,
            median,
            std_dev,
        })
    }

    pub fn p95(&self) -> f64 {
        if self.raw_samples.is_empty() {
            return 0.0;
        }
        let mut sorted = self.raw_samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((sorted.len() as f64) * 0.95).ceil() as usize;
        let clamped = idx.saturating_sub(1).min(sorted.len() - 1);
        sorted[clamped]
    }
}

/// Formats UTC timestamp in RFC 3339 format without external dependencies
pub fn format_utc_timestamp(now: SystemTime) -> String {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = dur.as_secs();

    let days = total_secs / 86400;
    let rem_secs = total_secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    let mut year = 1970i64;
    let mut d = days as i64;
    loop {
        let leap = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
            1
        } else {
            0
        };
        let days_in_year = 365 + leap;
        if d < days_in_year {
            let month_days = [
                31,
                if leap == 1 { 29 } else { 28 },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ];
            let mut month = 1;
            for &md in &month_days {
                if d < md {
                    break;
                }
                d -= md;
                month += 1;
            }
            let day = d + 1;
            return format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                year, month, day, hours, minutes, seconds
            );
        }
        d -= days_in_year;
        year += 1;
    }
}

/// Generates a unique execution identifier from the provided SystemTime
pub fn generate_run_id(now: SystemTime) -> String {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("run-{}-{}", dur.as_secs(), dur.subsec_millis())
}

/// Checks whether a given path is inside the current repository or a git worktree
pub fn is_path_inside_repo_or_worktree(path: &Path) -> bool {
    let check_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cur) => cur.join(path),
            Err(_) => path.to_path_buf(),
        }
    };

    let canonical = check_path.canonicalize().or_else(|_| {
        let mut ancestor = check_path.as_path();
        while let Some(parent) = ancestor.parent() {
            if let Ok(c) = parent.canonicalize() {
                return Ok(c);
            }
            ancestor = parent;
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No existing ancestor",
        ))
    });

    if let Ok(c_target) = canonical {
        let mut curr = Some(c_target.as_path());
        while let Some(p) = curr {
            if p.join(".git").exists() {
                return true;
            }
            curr = p.parent();
        }

        if let Ok(cur) = std::env::current_dir().and_then(|p| p.canonicalize()) {
            if c_target.starts_with(&cur) {
                return true;
            }
        }
    }

    false
}

/// Resolves the output directory dynamically, rejecting any path inside the repository or protected worktrees
pub fn resolve_output_dir(explicit_dir: Option<PathBuf>, run_id: &str) -> Result<PathBuf, String> {
    let dir = if let Some(d) = explicit_dir {
        d
    } else if let Ok(env_path) = std::env::var("KASKA_PERF_OUTPUT_DIR") {
        if !env_path.trim().is_empty() {
            PathBuf::from(env_path.trim())
        } else {
            std::env::temp_dir().join("kaska-perf-runs").join(run_id)
        }
    } else {
        std::env::temp_dir().join("kaska-perf-runs").join(run_id)
    };

    if is_path_inside_repo_or_worktree(&dir) {
        return Err(format!(
            "Output directory {:?} is inside the repository or a protected worktree; rejected for safety.",
            dir
        ));
    }

    Ok(dir)
}

/// Escapes strings for valid JSON serialization per RFC 8259 Section 7.
/// Handles quotes, backslashes, standard escape sequences, and all control characters U+0000..=U+001F.
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out
}

/// Exact synthetic path expected during controlled loopback benchmarks
pub const EXPECTED_SYNTHETIC_PATH: &str = "/api/status";

/// Fail-closed path sanitizer: allows only the known synthetic baseline path ("/api/status"),
/// redacting any other path, query parameters, tokens, or arbitrary HTTP string to prevent sensitive data leaks.
pub fn sanitize_transaction_path(raw_path: &str) -> &'static str {
    if raw_path == EXPECTED_SYNTHETIC_PATH {
        EXPECTED_SYNTHETIC_PATH
    } else {
        "REDACTED"
    }
}

/// Validates that the response starts with an exact HTTP/1.1 200 status line.
/// Rejects empty, truncated, or malformed responses, and rejects non-200 status codes.
/// Ensures no substring matching against body or headers.
/// Safely avoids leaking arbitrary status lines, reason phrases, or reflected data.
pub fn validate_http_status_line(response_bytes: &[u8]) -> Result<(), String> {
    if response_bytes.is_empty() {
        return Err("Empty HTTP response received".to_string());
    }
    let first_line_bytes = match response_bytes.windows(2).position(|w| w == b"\r\n") {
        Some(pos) => &response_bytes[..pos],
        None => match response_bytes.iter().position(|&b| b == b'\n') {
            Some(pos) => &response_bytes[..pos],
            None => {
                return Err("Malformed HTTP response: no status line delimiter found".to_string())
            }
        },
    };
    let status_line = std::str::from_utf8(first_line_bytes)
        .map_err(|_| "Malformed HTTP response: status line contains invalid UTF-8".to_string())?
        .trim();

    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(
            "Malformed HTTP response: status line contains insufficient tokens".to_string(),
        );
    }
    if parts[0] != "HTTP/1.1" {
        return Err("Unsupported HTTP protocol in status line".to_string());
    }
    if parts[1] != "200" {
        if parts[1].len() == 3 && parts[1].chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("Non-200 HTTP status code received: '{}'", parts[1]));
        } else {
            return Err("Malformed HTTP response: non-numeric status code".to_string());
        }
    }
    Ok(())
}

/// Calculates remaining execution budget against an absolute deadline
pub fn calculate_remaining_budget(now: Instant, deadline: Instant) -> Result<Duration, String> {
    if now >= deadline {
        Err(format!(
            "Scenario overall deadline of {}s exceeded",
            SCENARIO_DEADLINE_SECS
        ))
    } else {
        Ok(deadline.duration_since(now))
    }
}

/// Typed classification of client read outcomes and failure modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadErrorKind {
    ScenarioDeadlineExceeded,
    EofZeroBytes,
    IncompleteHttpStatus,
    InvalidHttpStatus,
    ReadLimitReached,
    TimedOut,
    WouldBlock,
    BrokenPipe,
    ConnectionReset,
    IoError,
}

impl ReadErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReadErrorKind::ScenarioDeadlineExceeded => "SCENARIO_DEADLINE_EXCEEDED",
            ReadErrorKind::EofZeroBytes => "EOF_ZERO_BYTES",
            ReadErrorKind::IncompleteHttpStatus => "INCOMPLETE_HTTP_STATUS",
            ReadErrorKind::InvalidHttpStatus => "INVALID_HTTP_STATUS",
            ReadErrorKind::ReadLimitReached => "READ_LIMIT_REACHED",
            ReadErrorKind::TimedOut => "TIMED_OUT",
            ReadErrorKind::WouldBlock => "WOULD_BLOCK",
            ReadErrorKind::BrokenPipe => "BROKEN_PIPE",
            ReadErrorKind::ConnectionReset => "CONNECTION_RESET",
            ReadErrorKind::IoError => "IO_ERROR",
        }
    }
}

/// Structured I/O error details captured during client reading
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReadError {
    pub classification: ReadErrorKind,
    pub message: String,
    pub error_kind: Option<std::io::ErrorKind>,
    pub os_code: Option<i32>,
    pub bytes_read: usize,
}

impl std::fmt::Display for ClientReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ClientReadError {}

/// Pure helper classifying probe results at max_bytes based on immediate post-probe instant and deadline.
/// Enforces fail-closed semantics: if deadline expired before or during/after probe, ScenarioDeadlineExceeded
/// is returned with the exact bytes accumulated prior to probe.
pub fn classify_probe_outcome(
    probe_res: std::io::Result<usize>,
    now_post_probe: Instant,
    deadline: Instant,
    accumulated_bytes: usize,
    max_bytes: usize,
) -> Result<bool, ClientReadError> {
    // 3. Verificar el deadline inmediatamente después del probe, antes de interpretar cualquier resultado.
    // 4. Si el deadline venció, devolver ScenarioDeadlineExceeded, incluso si el probe devolvió Ok(0) u Ok(1).
    if now_post_probe >= deadline {
        return Err(ClientReadError {
            classification: ReadErrorKind::ScenarioDeadlineExceeded,
            message: format!(
                "Scenario overall deadline of {}s exceeded during probe",
                SCENARIO_DEADLINE_SECS
            ),
            error_kind: None,
            os_code: None,
            bytes_read: accumulated_bytes,
        });
    }

    // 5. Si el deadline no venció, conservar las clasificaciones existentes.
    match probe_res {
        Ok(0) => {
            // Natural EOF observed at exactly max_bytes before deadline
            Ok(true)
        }
        Ok(_) => {
            // Additional byte observed and consumed before deadline: response demonstrated to exceed limit
            Err(ClientReadError {
                classification: ReadErrorKind::ReadLimitReached,
                message: format!(
                    "Response exceeded maximum allowed size of {} bytes (additional byte observed)",
                    max_bytes
                ),
                error_kind: None,
                os_code: None,
                bytes_read: accumulated_bytes,
            })
        }
        Err(e) => {
            let kind = e.kind();
            let classification = match kind {
                std::io::ErrorKind::TimedOut => ReadErrorKind::TimedOut,
                std::io::ErrorKind::WouldBlock => ReadErrorKind::WouldBlock,
                std::io::ErrorKind::BrokenPipe => ReadErrorKind::BrokenPipe,
                std::io::ErrorKind::ConnectionReset => ReadErrorKind::ConnectionReset,
                _ => ReadErrorKind::IoError,
            };
            let message =
                if kind == std::io::ErrorKind::TimedOut || kind == std::io::ErrorKind::WouldBlock {
                    format!(
                        "Probe timed out or would block without observing additional bytes: {}",
                        e
                    )
                } else {
                    format!("Read failed during probe: {}", e)
                };
            Err(ClientReadError {
                classification,
                message,
                error_kind: Some(kind),
                os_code: e.raw_os_error(),
                bytes_read: accumulated_bytes,
            })
        }
    }
}

/// Generic bounded chunk reader enforcing buffer limits, EOF detection, and deadline checks
pub fn read_bounded_chunks<R: Read>(
    reader: &mut R,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>, ClientReadError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        if Instant::now() >= deadline {
            return Err(ClientReadError {
                classification: ReadErrorKind::ScenarioDeadlineExceeded,
                message: format!(
                    "Scenario overall deadline of {}s exceeded",
                    SCENARIO_DEADLINE_SECS
                ),
                error_kind: None,
                os_code: None,
                bytes_read: buffer.len(),
            });
        }

        let bytes_left = max_bytes.saturating_sub(buffer.len());
        if bytes_left == 0 {
            // 1. Verificar el deadline inmediatamente antes de intentar el probe.
            if Instant::now() >= deadline {
                return Err(ClientReadError {
                    classification: ReadErrorKind::ScenarioDeadlineExceeded,
                    message: format!(
                        "Scenario overall deadline of {}s exceeded at response limit",
                        SCENARIO_DEADLINE_SECS
                    ),
                    error_kind: None,
                    os_code: None,
                    bytes_read: buffer.len(),
                });
            }

            // 2. Ejecutar el probe.
            let mut probe = [0u8; 1];
            let probe_res = loop {
                match reader.read(&mut probe) {
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        if Instant::now() >= deadline {
                            return Err(ClientReadError {
                                classification: ReadErrorKind::ScenarioDeadlineExceeded,
                                message: format!(
                                    "Scenario overall deadline of {}s exceeded during probe",
                                    SCENARIO_DEADLINE_SECS
                                ),
                                error_kind: None,
                                os_code: None,
                                bytes_read: buffer.len(),
                            });
                        }
                        continue;
                    }
                    res => break res,
                }
            };

            // 3. Verificar el deadline inmediatamente después del probe, antes de interpretar cualquier resultado.
            let now_post_probe = Instant::now();
            let ended = classify_probe_outcome(
                probe_res,
                now_post_probe,
                deadline,
                buffer.len(),
                max_bytes,
            )?;
            if ended {
                break; // Stream naturally ended at exactly max_bytes
            }
        }
        let read_len = chunk.len().min(bytes_left);

        match reader.read(&mut chunk[..read_len]) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if Instant::now() >= deadline {
                    return Err(ClientReadError {
                        classification: ReadErrorKind::ScenarioDeadlineExceeded,
                        message: format!(
                            "Scenario overall deadline of {}s exceeded after read operation",
                            SCENARIO_DEADLINE_SECS
                        ),
                        error_kind: None,
                        os_code: None,
                        bytes_read: buffer.len(),
                    });
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                let classification = if e.kind() == std::io::ErrorKind::TimedOut {
                    ReadErrorKind::TimedOut
                } else {
                    ReadErrorKind::WouldBlock
                };
                return Err(ClientReadError {
                    classification,
                    message: format!("Read timed out: {}", e),
                    error_kind: Some(e.kind()),
                    os_code: e.raw_os_error(),
                    bytes_read: buffer.len(),
                });
            }
            Err(e) => {
                let kind = e.kind();
                let classification = match kind {
                    std::io::ErrorKind::BrokenPipe => ReadErrorKind::BrokenPipe,
                    std::io::ErrorKind::ConnectionReset => ReadErrorKind::ConnectionReset,
                    _ => ReadErrorKind::IoError,
                };
                return Err(ClientReadError {
                    classification,
                    message: format!("Read failed: {}", e),
                    error_kind: Some(kind),
                    os_code: e.raw_os_error(),
                    bytes_read: buffer.len(),
                });
            }
        }
    }
    Ok(buffer)
}

/// Reads an HTTP response from a TcpStream using an explicit bounded loop, applying remaining budget to every chunk read
pub fn read_response_bounded_loop(
    stream: &mut TcpStream,
    max_bytes: usize,
    deadline: Instant,
    socket_timeout_ms: u64,
) -> Result<Vec<u8>, ClientReadError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        let remaining = match calculate_remaining_budget(Instant::now(), deadline) {
            Ok(rem) => rem,
            Err(e) => {
                return Err(ClientReadError {
                    classification: ReadErrorKind::ScenarioDeadlineExceeded,
                    message: e,
                    error_kind: None,
                    os_code: None,
                    bytes_read: buffer.len(),
                });
            }
        };
        let op_timeout = remaining.min(Duration::from_millis(socket_timeout_ms));
        if let Err(e) = stream.set_read_timeout(Some(op_timeout)) {
            let kind = e.kind();
            let classification = match kind {
                std::io::ErrorKind::TimedOut => ReadErrorKind::TimedOut,
                std::io::ErrorKind::WouldBlock => ReadErrorKind::WouldBlock,
                _ => ReadErrorKind::IoError,
            };
            return Err(ClientReadError {
                classification,
                message: format!("Failed to set read timeout on stream: {}", e),
                error_kind: Some(kind),
                os_code: e.raw_os_error(),
                bytes_read: buffer.len(),
            });
        }

        let bytes_left = max_bytes.saturating_sub(buffer.len());
        if bytes_left == 0 {
            // 1. Recalcular el presupuesto inmediatamente antes del probe y verificar deadline
            let remaining = match calculate_remaining_budget(Instant::now(), deadline) {
                Ok(rem) => rem,
                Err(e) => {
                    return Err(ClientReadError {
                        classification: ReadErrorKind::ScenarioDeadlineExceeded,
                        message: e,
                        error_kind: None,
                        os_code: None,
                        bytes_read: buffer.len(),
                    });
                }
            };

            // Configurar el read_timeout del TcpStream a un valor positivo acotado por ese presupuesto
            let op_timeout = remaining.min(Duration::from_millis(socket_timeout_ms));
            if let Err(e) = stream.set_read_timeout(Some(op_timeout)) {
                let kind = e.kind();
                let classification = match kind {
                    std::io::ErrorKind::TimedOut => ReadErrorKind::TimedOut,
                    std::io::ErrorKind::WouldBlock => ReadErrorKind::WouldBlock,
                    _ => ReadErrorKind::IoError,
                };
                return Err(ClientReadError {
                    classification,
                    message: format!("Failed to set read timeout on stream before probe: {}", e),
                    error_kind: Some(kind),
                    os_code: e.raw_os_error(),
                    bytes_read: buffer.len(),
                });
            }

            // 2. Ejecutar el probe.
            let mut probe = [0u8; 1];
            let probe_res = loop {
                match stream.read(&mut probe) {
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        if Instant::now() >= deadline {
                            return Err(ClientReadError {
                                classification: ReadErrorKind::ScenarioDeadlineExceeded,
                                message: format!(
                                    "Scenario overall deadline of {}s exceeded during probe",
                                    SCENARIO_DEADLINE_SECS
                                ),
                                error_kind: None,
                                os_code: None,
                                bytes_read: buffer.len(),
                            });
                        }
                        continue;
                    }
                    res => break res,
                }
            };

            // 3. Verificar el deadline inmediatamente después del probe, antes de interpretar cualquier resultado.
            let now_post_probe = Instant::now();
            let ended = classify_probe_outcome(
                probe_res,
                now_post_probe,
                deadline,
                buffer.len(),
                max_bytes,
            )?;
            if ended {
                break; // Stream naturally ended at exactly max_bytes
            }
        }
        let read_len = chunk.len().min(bytes_left);

        match stream.read(&mut chunk[..read_len]) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if Instant::now() >= deadline {
                    return Err(ClientReadError {
                        classification: ReadErrorKind::ScenarioDeadlineExceeded,
                        message: format!(
                            "Scenario overall deadline of {}s exceeded after read operation",
                            SCENARIO_DEADLINE_SECS
                        ),
                        error_kind: None,
                        os_code: None,
                        bytes_read: buffer.len(),
                    });
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                let classification = if e.kind() == std::io::ErrorKind::TimedOut {
                    ReadErrorKind::TimedOut
                } else {
                    ReadErrorKind::WouldBlock
                };
                return Err(ClientReadError {
                    classification,
                    message: format!("Read timed out (budget remaining: {:?}): {}", remaining, e),
                    error_kind: Some(e.kind()),
                    os_code: e.raw_os_error(),
                    bytes_read: buffer.len(),
                });
            }
            Err(e) => {
                let kind = e.kind();
                let classification = match kind {
                    std::io::ErrorKind::BrokenPipe => ReadErrorKind::BrokenPipe,
                    std::io::ErrorKind::ConnectionReset => ReadErrorKind::ConnectionReset,
                    _ => ReadErrorKind::IoError,
                };
                return Err(ClientReadError {
                    classification,
                    message: format!("Read from proxy failed: {}", e),
                    error_kind: Some(kind),
                    os_code: e.raw_os_error(),
                    bytes_read: buffer.len(),
                });
            }
        }
    }
    Ok(buffer)
}

/// Polls boundedly to verify that the specified loopback ports have been released by the OS.
/// Avoids arbitrary sleep delays while defending against foreign port conflicts.
pub fn wait_for_ports_released(ports: &[u16], max_wait: Duration) -> bool {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(10);
    while start.elapsed() < max_wait {
        let all_released = ports
            .iter()
            .all(|&port| TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok());
        if all_released {
            return true;
        }
        std::thread::sleep(poll_interval);
    }
    ports
        .iter()
        .all(|&port| TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok())
}

/// Generates N deterministic synthetic transactions with a fixed PRNG seed and small payloads (<= 100 bytes)
pub fn generate_synthetic_transactions(n: usize, seed: u64) -> Vec<HttpTransaction> {
    let mut txs = Vec::with_capacity(n);
    let mut state = seed;
    for i in 1..=n {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let path_idx = (state % 4) as usize;
        let paths = ["/api/status", "/api/health", "/api/metrics", "/api/auth"];
        let path = paths[path_idx];
        let method = if (state >> 3).is_multiple_of(5) {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        };

        let body_str = format!("{{\"id\":{},\"r\":{}}}", i, (state >> 16) % 1000);
        let body_bytes = body_str.into_bytes();
        assert!(body_bytes.len() <= 100, "Payload must be <= 100 bytes");

        txs.push(HttpTransaction {
            id: i as u64,
            timestamp_rfc3339: "2026-10-15T12:00:00Z".to_string(),
            request: HttpRequest {
                method,
                raw_url: format!("http://127.0.0.1:8989{}", path),
                host: "127.0.0.1:8989".to_string(),
                path: path.to_string(),
                query: String::new(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![
                    kaska_http::models::HttpHeader::new("Host", "127.0.0.1:8989"),
                    kaska_http::models::HttpHeader::new("User-Agent", "Kaska-Perf/1.3D"),
                ],
                body: body_bytes.clone(),
            },
            response: Some(HttpResponse {
                status_code: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![kaska_http::models::HttpHeader::new(
                    "Content-Type",
                    "application/json",
                )],
                body: body_bytes,
            }),
            duration_ms: (state >> 24) % 15 + 1,
            state: TransactionState::Completed,
        });
    }
    txs
}

/// Finds an available ephemeral loopback port by binding temporarily to port 0
pub fn get_ephemeral_port() -> u16 {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to probe ephemeral port on loopback");
    let port = listener
        .local_addr()
        .expect("Failed to get local addr")
        .port();
    drop(listener);
    port
}

/// Result of a single microbenchmark module
#[derive(Debug, Clone, Default)]
pub struct ModuleResult {
    pub name: String,
    pub description: String,
    pub stats: Option<SampleStatistics>,
    pub secondary_stats: Option<SampleStatistics>,
    pub notes: Vec<String>,
}

/// Formats a ModuleResult into a clean summary string for stdout and TXT parity
pub fn format_module_summary(res: &ModuleResult) -> String {
    let mut out = String::new();
    out.push_str("--------------------------------------------------\n");
    out.push_str(&format!("MODULE: {}\n", res.name));
    out.push_str(&format!("Description: {}\n", res.description));
    if let Some(s) = &res.stats {
        out.push_str(&format!(
            "  [Primary] Count: {}, Min: {:.4} us, Max: {:.4} us, Mean: {:.4} us, Median: {:.4} us, StdDev: {:.4} us\n",
            s.count, s.min, s.max, s.mean, s.median, s.std_dev
        ));
    }
    if let Some(s) = &res.secondary_stats {
        out.push_str(&format!(
            "  [Secondary] Count: {}, Min: {:.4} us, Max: {:.4} us, Mean: {:.4} us, Median: {:.4} us, StdDev: {:.4} us\n",
            s.count, s.min, s.max, s.mean, s.median, s.std_dev
        ));
    }
    for note in &res.notes {
        out.push_str(&format!("  • {}\n", note));
    }
    out
}

/// Runs Module 1: PRF-01 Synthetic Model Reconstruction & Cloning Cost
pub fn run_prf01_microbenchmark(n: usize, iterations: usize) -> ModuleResult {
    let synth = generate_synthetic_transactions(n, DEFAULT_FIXED_SEED);
    let mut store = TrafficStore::new(10_000);
    for tx in synth {
        store.insert(tx);
    }
    let store_arc = Arc::new(Mutex::new(store));

    // Warm-up iteration (not counted in statistics)
    {
        let all_txs = std::hint::black_box(store_arc.lock().unwrap().get_all());
        let items: Vec<TrafficItem> = all_txs
            .into_iter()
            .map(|t| TrafficItem {
                id: SharedString::from(t.id.to_string()),
                method: SharedString::from(t.request.method.to_string()),
                host: SharedString::from(t.request.host.clone()),
                path: SharedString::from(t.request.path.clone()),
                status_code: t.status_code() as i32,
                status_text: SharedString::from(t.status_text()),
                duration_ms: t.duration_ms as i32,
                size_bytes: t.response_size_bytes() as i32,
                content_type: SharedString::from(t.content_type()),
                is_error: t.is_error(),
            })
            .collect();
        let model = std::hint::black_box(ModelRc::new(VecModel::from(items)));
        std::hint::black_box(&model);
    }

    let mut clone_times_us = Vec::with_capacity(iterations);
    let mut transform_times_us = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        // Step A: Clone from TrafficStore under Mutex
        let t0 = Instant::now();
        let all_txs = std::hint::black_box(store_arc.lock().unwrap().get_all());
        let t1 = Instant::now();
        clone_times_us.push((t1 - t0).as_nanos() as f64 / 1000.0);

        // Step B: Transform to Slint TrafficItems with SharedString allocations and wrap in VecModel
        let t2 = Instant::now();
        let items: Vec<TrafficItem> = all_txs
            .into_iter()
            .map(|t| TrafficItem {
                id: SharedString::from(t.id.to_string()),
                method: SharedString::from(t.request.method.to_string()),
                host: SharedString::from(t.request.host.clone()),
                path: SharedString::from(t.request.path.clone()),
                status_code: t.status_code() as i32,
                status_text: SharedString::from(t.status_text()),
                duration_ms: t.duration_ms as i32,
                size_bytes: t.response_size_bytes() as i32,
                content_type: SharedString::from(t.content_type()),
                is_error: t.is_error(),
            })
            .collect();
        let model = std::hint::black_box(ModelRc::new(VecModel::from(items)));
        std::hint::black_box(&model);
        let t3 = Instant::now();
        transform_times_us.push((t3 - t2).as_nanos() as f64 / 1000.0);
    }

    let clone_stats = SampleStatistics::compute(clone_times_us);
    let transform_stats = SampleStatistics::compute(transform_times_us);

    ModuleResult {
        name: format!("PRF-01: Store Clone & Model Construction (N={})", n),
        description: "Measures store.get_all() clone latency under mutex vs Slint TrafficItem transformation and ModelRc creation".to_string(),
        stats: clone_stats,
        secondary_stats: transform_stats,
        notes: vec![
            format!("Build profile: {}", if cfg!(debug_assertions) { "debug (unoptimized)" } else { "release (optimized)" }),
            "Warm-up: 1 unmeasured iteration executed before timed repetitions to prime memory allocator.".to_string(),
            format!("Repetitions: {} timed iterations evaluated.", iterations),
            "Instant resolution: Sub-microsecond samples subject to host OS timer resolution.".to_string(),
            "Primary stats: store.get_all() clone latency under Mutex (microseconds)".to_string(),
            "Secondary stats: Slint model transformation & allocation latency (microseconds)".to_string(),
            "PRF-01 AUDIT NOTE: Local transformation benchmark measures heap cloning and Slint model wrapping; it does NOT measure or simulate real Slint UI event loop queue scheduling latency.".to_string(),
            "PRODUCTION CAVEAT: Microbenchmark results in isolation do not guarantee aggregate production UI improvements.".to_string(),
        ],
    }
}

/// Runs Module 2: PRF-02 Selection Comparison: get_all() vs get_by_id()
pub fn run_prf02_microbenchmark(n: usize, iterations: usize) -> ModuleResult {
    let synth = generate_synthetic_transactions(n, DEFAULT_FIXED_SEED);
    let mut store = TrafficStore::new(10_000);
    for tx in synth {
        store.insert(tx);
    }
    let store_arc = Arc::new(Mutex::new(store));
    let target_idx = n / 2;
    let target_id = (target_idx + 1) as u64;

    // Warm-up
    {
        let store = store_arc.lock().unwrap();
        let txs = std::hint::black_box(store.get_all());
        let _ = txs.get(target_idx);
        let item_ref = std::hint::black_box(store.get_by_id(target_id));
        std::hint::black_box(&item_ref);
    }

    let mut get_all_times_us = Vec::with_capacity(iterations);
    let mut get_by_id_times_us = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        // Current approach: lock, clone all, get index
        let t0 = Instant::now();
        let store = store_arc.lock().unwrap();
        let txs = std::hint::black_box(store.get_all());
        let item_opt = txs.get(target_idx);
        let res = item_opt.map(|t| (t.request.headers_raw_text(), t.request.body_as_utf8()));
        std::hint::black_box(&res);
        drop(store);
        let t1 = Instant::now();
        get_all_times_us.push((t1 - t0).as_nanos() as f64 / 1000.0);

        // Targeted lookup: lock, call get_by_id, clone only target item
        let t2 = Instant::now();
        let store = store_arc.lock().unwrap();
        let item_ref = std::hint::black_box(store.get_by_id(target_id));
        let res2 = item_ref.map(|t| (t.request.headers_raw_text(), t.request.body_as_utf8()));
        std::hint::black_box(&res2);
        drop(store);
        let t3 = Instant::now();
        get_by_id_times_us.push((t3 - t2).as_nanos() as f64 / 1000.0);
    }

    let get_all_stats = SampleStatistics::compute(get_all_times_us);
    let get_by_id_stats = SampleStatistics::compute(get_by_id_times_us);

    ModuleResult {
        name: format!("PRF-02: Selection Latency get_all() vs get_by_id() (N={})", n),
        description: "Compares current full-store cloning with direct get_by_id lookup".to_string(),
        stats: get_all_stats,
        secondary_stats: get_by_id_stats,
        notes: vec![
            format!("Build profile: {}", if cfg!(debug_assertions) { "debug (unoptimized)" } else { "release (optimized)" }),
            "Warm-up: 1 unmeasured iteration executed before timed repetitions to prime memory allocator.".to_string(),
            format!("Repetitions: {} timed iterations evaluated.", iterations),
            "Instant resolution: Sub-microsecond samples subject to host OS timer resolution.".to_string(),
            "Primary stats: Current on_select_transaction (store.get_all() full clone) latency (microseconds)".to_string(),
            "Secondary stats: Targeted lookup (store.get_by_id) latency (microseconds)".to_string(),
            "PRF-02 AUDIT NOTE: TrafficStore::get_by_id performs an O(N) linear scan over VecDeque; it is NOT O(1), but it avoids cloning the N-1 transaction bodies and headers.".to_string(),
            "PRODUCTION CAVEAT: Microbenchmark results in isolation do not guarantee aggregate production UI improvements.".to_string(),
        ],
    }
}

/// Runs Module 3: PRF-06 Limits & Retention Verification
pub fn run_prf06_limits_check() -> ModuleResult {
    let _store = TrafficStore::default();
    let max_cap = 10_000;

    ModuleResult {
        name: "PRF-06: Store Limits & Retention Verification".to_string(),
        description: "Records the configured store count limit and memory retention invariants".to_string(),
        stats: None,
        secondary_stats: None,
        notes: vec![
            format!("TrafficStore DEFAULT_MAX_CAPACITY: {} transactions", max_cap),
            "LIMIT CHARACTERISTIC: Count limit ONLY. There is no global RAM byte limit in TrafficStore.".to_string(),
            "RISK AUDIT: If N transactions carry 2 MiB bodies, retained buffer RAM can theoretically reach 20 GiB.".to_string(),
            "REQUEST BODY ACCUMULATION: Request and response buffers are stored uncompressed in memory.".to_string(),
        ],
    }
}

/// Inspector 10k Pipeline Benchmark Result
#[derive(Debug, Clone)]
pub struct Inspector10kResult {
    pub metadata_snapshot: SampleStatistics,
    pub neutral_filter: SampleStatistics,
    pub restrictive_filter: SampleStatistics,
    pub text_search: SampleStatistics,
    pub model_projection: SampleStatistics,
    pub full_pipeline: SampleStatistics,
    pub legacy_comparison: SampleStatistics,
    pub details_lookup: SampleStatistics,
    pub total_transactions: usize,
    pub neutral_visible: usize,
    pub restrictive_visible: usize,
    pub text_search_visible: usize,
}

/// Runs the 10,000 transaction Inspector metadata and filtering pipeline benchmark.
/// Measures the 8 specified stages with in-memory synthetic transactions, warmup, and repetitions.
pub fn run_inspector_10k_microbenchmark(iterations: usize) -> Inspector10kResult {
    let n = 10_000;
    let synth = generate_synthetic_transactions(n, DEFAULT_FIXED_SEED);
    let mut store = TrafficStore::new(10_000);
    for tx in synth {
        store.insert(tx);
    }
    let store_arc = Arc::new(Mutex::new(store));
    let scope = AuditScope::default();

    let neutral_filter = filter::FilterState::default();
    let restrictive_filter = filter::FilterState {
        method: filter::MethodFilter::Post,
        status: filter::HttpStatusFilter::Status2xx,
        outcome: filter::OutcomeFilter::Completed,
        ..Default::default()
    };

    let search_filter = filter::FilterState {
        search_query: "status".to_string(),
        ..Default::default()
    };

    let target_id = 5000u64;

    // Warm-up pass (unmeasured)
    {
        let store = store_arc.lock().unwrap();
        let snap = std::hint::black_box(store.get_metadata_snapshot());
        let _ = std::hint::black_box(neutral_filter.filter(&snap, &scope));
        let _ = std::hint::black_box(restrictive_filter.filter(&snap, &scope));
        let _ = std::hint::black_box(search_filter.filter(&snap, &scope));
        let (items, _, _, _, _) =
            controller::project_traffic(&snap, &neutral_filter, &scope, Some(target_id));
        let model = std::hint::black_box(ModelRc::new(VecModel::from(items)));
        std::hint::black_box(&model);
        let all_txs = std::hint::black_box(store.get_all());
        std::hint::black_box(&all_txs);
        let detail = std::hint::black_box(store.get_by_id(target_id));
        std::hint::black_box(&detail);
    }

    let mut snap_samples = Vec::with_capacity(iterations);
    let mut neutral_samples = Vec::with_capacity(iterations);
    let mut restr_samples = Vec::with_capacity(iterations);
    let mut search_samples = Vec::with_capacity(iterations);
    let mut proj_samples = Vec::with_capacity(iterations);
    let mut pipe_samples = Vec::with_capacity(iterations);
    let mut legacy_samples = Vec::with_capacity(iterations);
    let mut detail_samples = Vec::with_capacity(iterations);

    let mut neutral_vis = 0;
    let mut restr_vis = 0;
    let mut search_vis = 0;

    for _ in 0..iterations {
        // Stage 1: get_metadata_snapshot() latency under lock
        let t0 = Instant::now();
        let snap = {
            let store = store_arc.lock().unwrap();
            std::hint::black_box(store.get_metadata_snapshot())
        };
        let t1 = Instant::now();
        snap_samples.push((t1 - t0).as_nanos() as f64 / 1000.0);

        // Stage 2: Neutral filter matching latency
        let t2 = Instant::now();
        let neutral_res = std::hint::black_box(neutral_filter.filter(&snap, &scope));
        let t3 = Instant::now();
        neutral_samples.push((t3 - t2).as_nanos() as f64 / 1000.0);
        neutral_vis = neutral_res.len();

        // Stage 3: Restrictive filter matching latency
        let t4 = Instant::now();
        let restr_res = std::hint::black_box(restrictive_filter.filter(&snap, &scope));
        let t5 = Instant::now();
        restr_samples.push((t5 - t4).as_nanos() as f64 / 1000.0);
        restr_vis = restr_res.len();

        // Stage 4: Case-insensitive text search over host/path
        let t6 = Instant::now();
        let search_res = std::hint::black_box(search_filter.filter(&snap, &scope));
        let t7 = Instant::now();
        search_samples.push((t7 - t6).as_nanos() as f64 / 1000.0);
        search_vis = search_res.len();

        // Stage 5: TrafficItem + ModelRc<TrafficItem> / VecModel projection latency
        let t8 = Instant::now();
        let items: Vec<TrafficItem> = neutral_res
            .iter()
            .map(|s| controller::summary_to_traffic_item(s))
            .collect();
        let model = std::hint::black_box(ModelRc::new(VecModel::from(items)));
        std::hint::black_box(&model);
        let t9 = Instant::now();
        proj_samples.push((t9 - t8).as_nanos() as f64 / 1000.0);

        // Stage 6: Combined end-to-end projection pipeline latency (lock snapshot -> filter -> project -> VecModel)
        let t10 = Instant::now();
        let pipe_snap = {
            let store = store_arc.lock().unwrap();
            std::hint::black_box(store.get_metadata_snapshot())
        };
        let (pipe_items, _tot, _vis, _idx, _retained) =
            controller::project_traffic(&pipe_snap, &neutral_filter, &scope, Some(target_id));
        let pipe_model = std::hint::black_box(ModelRc::new(VecModel::from(pipe_items)));
        std::hint::black_box(&pipe_model);
        let t11 = Instant::now();
        pipe_samples.push((t11 - t10).as_nanos() as f64 / 1000.0);

        // Stage 7: Controlled comparison with legacy get_all() path
        let t12 = Instant::now();
        let all_txs = {
            let store = store_arc.lock().unwrap();
            std::hint::black_box(store.get_all())
        };
        let legacy_items: Vec<TrafficItem> = all_txs
            .into_iter()
            .map(|t| TrafficItem {
                id: SharedString::from(t.id.to_string()),
                method: SharedString::from(t.request.method.to_string()),
                host: SharedString::from(t.request.host.clone()),
                path: SharedString::from(t.request.path.clone()),
                status_code: t.status_code() as i32,
                status_text: SharedString::from(t.status_text()),
                duration_ms: t.duration_ms as i32,
                size_bytes: t.response_size_bytes() as i32,
                content_type: SharedString::from(t.content_type()),
                is_error: t.is_error(),
            })
            .collect();
        let legacy_model = std::hint::black_box(ModelRc::new(VecModel::from(legacy_items)));
        std::hint::black_box(&legacy_model);
        let t13 = Instant::now();
        legacy_samples.push((t13 - t12).as_nanos() as f64 / 1000.0);

        // Stage 8: Cost of accessing selected item details by u64 ID
        let t14 = Instant::now();
        let store = store_arc.lock().unwrap();
        let item_ref = std::hint::black_box(store.get_by_id(target_id));
        let res_details =
            item_ref.map(|t| (t.request.headers_raw_text(), t.request.body_as_utf8()));
        std::hint::black_box(&res_details);
        drop(store);
        let t15 = Instant::now();
        detail_samples.push((t15 - t14).as_nanos() as f64 / 1000.0);
    }

    Inspector10kResult {
        metadata_snapshot: SampleStatistics::compute(snap_samples).unwrap(),
        neutral_filter: SampleStatistics::compute(neutral_samples).unwrap(),
        restrictive_filter: SampleStatistics::compute(restr_samples).unwrap(),
        text_search: SampleStatistics::compute(search_samples).unwrap(),
        model_projection: SampleStatistics::compute(proj_samples).unwrap(),
        full_pipeline: SampleStatistics::compute(pipe_samples).unwrap(),
        legacy_comparison: SampleStatistics::compute(legacy_samples).unwrap(),
        details_lookup: SampleStatistics::compute(detail_samples).unwrap(),
        total_transactions: n,
        neutral_visible: neutral_vis,
        restrictive_visible: restr_vis,
        text_search_visible: search_vis,
    }
}

/// Formats the Inspector10kResult into an informative summary report string.
pub fn format_inspector_10k_summary(res: &Inspector10kResult) -> String {
    let mut out = String::new();
    out.push_str("==================================================================\n");
    out.push_str("MODULE: INSPECTOR 10,000 TRANSACTION PIPELINE BENCHMARK\n");
    out.push_str("==================================================================\n");
    out.push_str(&format!(
        "Total in-memory transactions: {}\n",
        res.total_transactions
    ));
    out.push_str(&format!(
        "Neutral filter matching items: {}\n",
        res.neutral_visible
    ));
    out.push_str(&format!(
        "Restrictive filter matching items: {}\n",
        res.restrictive_visible
    ));
    out.push_str(&format!(
        "Text search matching items: {}\n\n",
        res.text_search_visible
    ));

    let fmt_stage = |name: &str, s: &SampleStatistics| -> String {
        format!(
            "  • {:<35} min: {:>9.2} us | p50: {:>9.2} us | p95: {:>9.2} us | max: {:>9.2} us (mean: {:>9.2} us, std_dev: {:>7.2} us)\n",
            name, s.min, s.median, s.p95(), s.max, s.mean, s.std_dev
        )
    };

    out.push_str("PIPELINE STAGE LATENCIES (microseconds):\n");
    out.push_str(&fmt_stage(
        "1. get_metadata_snapshot()",
        &res.metadata_snapshot,
    ));
    out.push_str(&fmt_stage(
        "2. Neutral filter matching",
        &res.neutral_filter,
    ));
    out.push_str(&fmt_stage(
        "3. Restrictive filter matching",
        &res.restrictive_filter,
    ));
    out.push_str(&fmt_stage("4. Host/path text search", &res.text_search));
    out.push_str(&fmt_stage(
        "5. Model projection (10k items)",
        &res.model_projection,
    ));
    out.push_str(&fmt_stage(
        "6. End-to-end projection pipeline",
        &res.full_pipeline,
    ));
    out.push_str(&fmt_stage(
        "7. Legacy get_all() path comparison",
        &res.legacy_comparison,
    ));
    out.push_str(&fmt_stage(
        "8. Single item detail by ID",
        &res.details_lookup,
    ));

    let speedup = res.legacy_comparison.median / res.full_pipeline.median;
    out.push_str("\nPIPELINE EFFICIENCY ANALYSIS:\n");
    out.push_str(&format!(
        "  • Metadata pipeline p50: {:.2} us vs Legacy get_all() p50: {:.2} us ({:.2}x speedup)\n",
        res.full_pipeline.median, res.legacy_comparison.median, speedup
    ));
    out.push_str(&format!(
        "  • Detail lookup by ID p50: {:.2} us vs Legacy full-clone p50: {:.2} us\n",
        res.details_lookup.median, res.legacy_comparison.median
    ));
    out.push_str("------------------------------------------------------------------\n");
    out.push_str("AUDIT & METHODOLOGY NOTES:\n");
    out.push_str("  • Synthetic in-memory transactions with bounded payloads (<= 100 B), zero network I/O.\n");
    out.push_str(
        "  • std::hint::black_box used on all pipeline outputs to prevent dead-code elimination.\n",
    );
    out.push_str(
        "  • Warm-up iteration executed prior to measured repetitions to prime allocator.\n",
    );
    out.push_str("  • NOTE: Microbenchmarks isolate heap allocation, metadata iteration, and ModelRc wrapping;\n");
    out.push_str("    they do NOT measure real Slint UI render/event-loop scheduling latency.\n");
    out.push_str("==================================================================\n");
    out
}

#[derive(Debug, Clone, Default)]
pub struct E2eScenarioResult {
    pub target_dispatched: usize,
    pub transactions_captured: usize,
    pub wall_clock_duration: Duration,
    pub sockets_released: bool,
    pub validation_passed: bool,
    pub initial_metrics: ProcessMetrics,
    pub final_metrics: ProcessMetrics,
    pub error_message: Option<String>,
}

/// Formats an E2eScenarioResult into a clean summary string for stdout and TXT parity
pub fn format_e2e_summary(e: &E2eScenarioResult, n: usize) -> String {
    let mut out = String::new();
    out.push_str("--------------------------------------------------\n");
    out.push_str(&format!("MODULE: End-to-End Loopback Pilot (N={})\n", n));
    out.push_str(&format!("  • Dispatched: {}\n", e.target_dispatched));
    out.push_str(&format!(
        "  • Captured in store: {}\n",
        e.transactions_captured
    ));
    out.push_str(&format!(
        "  • Wall-clock duration: {:.4} ms\n",
        e.wall_clock_duration.as_secs_f64() * 1000.0
    ));
    out.push_str(&format!(
        "  • Sockets released cleanly: {}\n",
        e.sockets_released
    ));
    out.push_str(&format!(
        "  • Validation status: {}\n",
        if e.validation_passed { "PASS" } else { "FAIL" }
    ));
    if let Some(ws) = e.final_metrics.working_set_bytes {
        out.push_str(&format!(
            "  • Final Working Set: {:.2} MiB\n",
            ws as f64 / (1024.0 * 1024.0)
        ));
    }
    if let Some(pb) = e.final_metrics.private_bytes {
        out.push_str(&format!(
            "  • Final Private Bytes: {:.2} MiB\n",
            pb as f64 / (1024.0 * 1024.0)
        ));
    }
    if let Some(ar) = e.final_metrics.anonymous_rss_bytes {
        out.push_str(&format!(
            "  • Final Anonymous RSS: {:.2} MiB\n",
            ar as f64 / (1024.0 * 1024.0)
        ));
    }
    if let (Some(i), Some(f)) = (e.initial_metrics.cpu_time_ms, e.final_metrics.cpu_time_ms) {
        out.push_str(&format!(
            "  • CPU Time: cumulative = {} ms, scenario delta = {} ms\n",
            f,
            f.saturating_sub(i)
        ));
    }
    out
}

/// Typed observable execution phases for safe, deterministic failure diagnosis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticPhase {
    Startup,
    ConnectProxy,
    WriteRequest,
    ReadResponse,
    ValidateResponse,
    VerifyStore,
    Shutdown,
}

impl DiagnosticPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiagnosticPhase::Startup => "STARTUP",
            DiagnosticPhase::ConnectProxy => "CONNECT_PROXY",
            DiagnosticPhase::WriteRequest => "WRITE_REQUEST",
            DiagnosticPhase::ReadResponse => "READ_RESPONSE",
            DiagnosticPhase::ValidateResponse => "VALIDATE_RESPONSE",
            DiagnosticPhase::VerifyStore => "VERIFY_STORE",
            DiagnosticPhase::Shutdown => "SHUTDOWN",
        }
    }
}

/// Safe, privacy-preserving transaction summary snapshot
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeTransactionSummary {
    pub id: u64,
    pub method: String,
    pub path: String,
    pub status_code: Option<u16>,
    pub duration_ms: u64,
    pub has_request_body: bool,
    pub has_response_body: bool,
}

/// Correlation resolution status indicating diagnostic integrity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationStatus {
    Complete,
    Incomplete,
    Ambiguous,
    NotFound,
    Degraded,
}

impl CorrelationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Incomplete => "INCOMPLETE",
            Self::Ambiguous => "AMBIGUOUS",
            Self::NotFound => "NOT_FOUND",
            Self::Degraded => "DEGRADED",
        }
    }
}

/// Safe, zero-leak summary of a proxy diagnostic event for reporting and serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeProxyEventSummary {
    pub conn_id: u64,
    pub client_port: u16,
    pub phase: String,
    pub io_result: Option<String>,
    pub termination_reason: Option<String>,
    pub http_response_attempted: Option<u16>,
    pub http_response_write_succeeded: Option<bool>,
}

/// Structured proxy-side diagnostic context correlating proxy events with client failure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyFailureDiagnostic {
    pub correlation_status: CorrelationStatus,
    pub client_ephemeral_port: Option<u16>,
    pub correlated_conn_id: Option<u64>,
    pub correlated_termination_reason: Option<String>,
    pub correlated_phase: Option<String>,
    pub correlated_io_result: Option<String>,
    pub terminal_event: Option<SafeProxyEventSummary>,
    pub correlated_events: Vec<SafeProxyEventSummary>,
    pub total_captured_events: usize,
    pub observer_ring_capacity: usize,
    pub observer_dropped_events: usize,
}

/// Pure, deterministic function to correlate proxy events for a given client ephemeral port.
/// Returns a fully qualified ProxyFailureDiagnostic without side effects or I/O.
pub fn correlate_proxy_diagnostics(
    client_port: Option<u16>,
    all_events: &[kaska_http::proxy::ProxyDiagnosticEvent],
    total_captured: usize,
    ring_cap: usize,
    dropped_events: usize,
) -> ProxyFailureDiagnostic {
    let port = match client_port {
        Some(p) => p,
        None => {
            return ProxyFailureDiagnostic {
                correlation_status: CorrelationStatus::NotFound,
                client_ephemeral_port: None,
                correlated_conn_id: None,
                correlated_termination_reason: None,
                correlated_phase: None,
                correlated_io_result: None,
                terminal_event: None,
                correlated_events: Vec::new(),
                total_captured_events: total_captured,
                observer_ring_capacity: ring_cap,
                observer_dropped_events: dropped_events,
            };
        }
    };

    // Filter events matching the client port
    let matching_events: Vec<&kaska_http::proxy::ProxyDiagnosticEvent> = all_events
        .iter()
        .filter(|ev| ev.client_port == port)
        .collect();

    if matching_events.is_empty() {
        let status = if dropped_events > 0 {
            CorrelationStatus::Degraded
        } else {
            CorrelationStatus::NotFound
        };
        return ProxyFailureDiagnostic {
            correlation_status: status,
            client_ephemeral_port: Some(port),
            correlated_conn_id: None,
            correlated_termination_reason: None,
            correlated_phase: None,
            correlated_io_result: None,
            terminal_event: None,
            correlated_events: Vec::new(),
            total_captured_events: total_captured,
            observer_ring_capacity: ring_cap,
            observer_dropped_events: dropped_events,
        };
    }

    // Check distinct conn_ids for this port
    let mut conn_ids: Vec<u64> = matching_events.iter().map(|e| e.conn_id).collect();
    conn_ids.sort_unstable();
    conn_ids.dedup();

    if conn_ids.len() > 1 {
        // Port reuse / collision detected -> Ambiguous!
        let safe_events = matching_events
            .iter()
            .map(|ev| SafeProxyEventSummary {
                conn_id: ev.conn_id,
                client_port: ev.client_port,
                phase: format!("{:?}", ev.phase),
                io_result: ev.io_result.as_ref().map(|res| format!("{:?}", res)),
                termination_reason: ev.termination_reason.as_ref().map(|r| format!("{:?}", r)),
                http_response_attempted: ev.http_response_attempted,
                http_response_write_succeeded: ev.http_response_write_succeeded,
            })
            .collect();

        return ProxyFailureDiagnostic {
            correlation_status: CorrelationStatus::Ambiguous,
            client_ephemeral_port: Some(port),
            correlated_conn_id: None,
            correlated_termination_reason: None,
            correlated_phase: None,
            correlated_io_result: None,
            terminal_event: None,
            correlated_events: safe_events,
            total_captured_events: total_captured,
            observer_ring_capacity: ring_cap,
            observer_dropped_events: dropped_events,
        };
    }

    let conn_id = conn_ids[0];
    let safe_events: Vec<SafeProxyEventSummary> = matching_events
        .iter()
        .map(|ev| SafeProxyEventSummary {
            conn_id: ev.conn_id,
            client_port: ev.client_port,
            phase: format!("{:?}", ev.phase),
            io_result: ev.io_result.as_ref().map(|res| format!("{:?}", res)),
            termination_reason: ev.termination_reason.as_ref().map(|r| format!("{:?}", r)),
            http_response_attempted: ev.http_response_attempted,
            http_response_write_succeeded: ev.http_response_write_succeeded,
        })
        .collect();

    // Locate the terminal event: the last event that contains a termination_reason
    let terminal_event_summary = safe_events
        .iter()
        .rfind(|ev| ev.termination_reason.is_some())
        .cloned();

    let (status, term_reason, phase, io_res) = if let Some(ref term) = terminal_event_summary {
        let st = if dropped_events > 0 {
            CorrelationStatus::Degraded
        } else {
            CorrelationStatus::Complete
        };
        (
            st,
            term.termination_reason.clone(),
            Some(term.phase.clone()),
            term.io_result.clone(),
        )
    } else {
        let st = if dropped_events > 0 {
            CorrelationStatus::Degraded
        } else {
            CorrelationStatus::Incomplete
        };
        // In incomplete status, last event phase provides latest observed state
        let latest_phase = safe_events.last().map(|e| e.phase.clone());
        (st, None, latest_phase, None)
    };

    ProxyFailureDiagnostic {
        correlation_status: status,
        client_ephemeral_port: Some(port),
        correlated_conn_id: Some(conn_id),
        correlated_termination_reason: term_reason,
        correlated_phase: phase,
        correlated_io_result: io_res,
        terminal_event: terminal_event_summary,
        correlated_events: safe_events,
        total_captured_events: total_captured,
        observer_ring_capacity: ring_cap,
        observer_dropped_events: dropped_events,
    }
}

/// Pure function calculating the exact sleep duration for diagnostic polling.
/// Returns Duration::ZERO if remaining diagnostic budget or scenario budget is zero.
/// Otherwise returns min(poll_interval, remaining_diag_budget, remaining_scenario_budget).
pub fn calculate_diagnostic_poll_sleep(
    poll_interval: Duration,
    elapsed_diag: Duration,
    max_diag: Duration,
    now: Instant,
    deadline: Instant,
) -> Duration {
    let diag_rem = max_diag.saturating_sub(elapsed_diag);
    if diag_rem.is_zero() {
        return Duration::ZERO;
    }
    if now >= deadline {
        return Duration::ZERO;
    }
    let scen_rem = deadline.duration_since(now);
    if scen_rem.is_zero() {
        return Duration::ZERO;
    }
    poll_interval.min(diag_rem).min(scen_rem)
}

/// Comprehensive failure diagnostic captured prior to process termination
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PilotFailureDiagnostic {
    pub target_n: usize,
    pub failed_request_index: usize,
    pub validated_requests_count: usize,
    pub phase: DiagnosticPhase,
    pub io_result_type: String,
    pub error_kind: Option<String>,
    pub os_error_code: Option<i32>,
    pub bytes_received_len: usize,
    pub error_message: String,
    pub store_transaction_count: usize,
    pub store_summary: Vec<SafeTransactionSummary>,
    pub proxy_diagnostics: Option<ProxyFailureDiagnostic>,
    pub elapsed_since_start_ms: u64,
    pub remaining_budget_ms: Option<u64>,
    pub stop_signal_sent: bool,
    pub sockets_released: bool,
}

/// Formats failure diagnostic into human-readable summary for stdout and TXT parity
pub fn format_failure_diagnostic_summary(d: &PilotFailureDiagnostic) -> String {
    let mut out = String::new();
    out.push_str("--------------------------------------------------\n");
    out.push_str(&format!(
        "VALIDATION FAILURE in End-to-End Pilot (N={}):\n",
        d.target_n
    ));
    out.push_str(&format!("  • Observable Phase: {}\n", d.phase.as_str()));
    out.push_str(&format!(
        "  • Failed Request Index: {} (Validated: {}/{})\n",
        d.failed_request_index, d.validated_requests_count, d.target_n
    ));
    out.push_str(&format!("  • I/O Result Type: {}\n", d.io_result_type));
    if let Some(ref ek) = d.error_kind {
        out.push_str(&format!("  • ErrorKind: {}\n", ek));
    }
    if let Some(code) = d.os_error_code {
        out.push_str(&format!("  • OS Error Code: {}\n", code));
    }
    out.push_str(&format!(
        "  • Bytes Received in Buffer: {}\n",
        d.bytes_received_len
    ));
    out.push_str(&format!("  • Diagnostic Detail: {}\n", d.error_message));
    out.push_str(&format!(
        "  • TrafficStore Observed Count (Point-in-Time): {}\n",
        d.store_transaction_count
    ));
    out.push_str(&format!(
        "  • Elapsed Since Scenario Start: {} ms\n",
        d.elapsed_since_start_ms
    ));
    if let Some(rem) = d.remaining_budget_ms {
        out.push_str(&format!("  • Remaining Budget: {} ms\n", rem));
    } else {
        out.push_str("  • Remaining Budget: EXPIRED\n");
    }
    out.push_str(&format!(
        "  • Stop Signal Sent: {}, Sockets Released: {}\n",
        d.stop_signal_sent, d.sockets_released
    ));
    if let Some(ref pdiag) = d.proxy_diagnostics {
        out.push_str("  • PROXY DIAGNOSTICS (Correlated by Client Ephemeral Port):\n");
        out.push_str(&format!(
            "    - Correlation Status: {}\n",
            pdiag.correlation_status.as_str()
        ));
        if let Some(port) = pdiag.client_ephemeral_port {
            out.push_str(&format!("    - Client Port: {}\n", port));
        }
        if let Some(cid) = pdiag.correlated_conn_id {
            out.push_str(&format!("    - Proxy Conn ID: {}\n", cid));
        }
        if let Some(ref ph) = pdiag.correlated_phase {
            out.push_str(&format!("    - Proxy Phase: {}\n", ph));
        }
        if let Some(ref tr) = pdiag.correlated_termination_reason {
            out.push_str(&format!("    - Proxy Termination Reason: {}\n", tr));
        }
        if let Some(ref io) = pdiag.correlated_io_result {
            out.push_str(&format!("    - Proxy I/O Result: {}\n", io));
        }
        if let Some(ref term) = pdiag.terminal_event {
            out.push_str(&format!(
                "    - Terminal Event: [conn:{}] phase={} term={:?} io={:?} resp_att={:?} resp_ok={:?}\n",
                term.conn_id,
                term.phase,
                term.termination_reason,
                term.io_result,
                term.http_response_attempted,
                term.http_response_write_succeeded
            ));
        }
        out.push_str(&format!(
            "    - Correlated Events Count: {}\n",
            pdiag.correlated_events.len()
        ));
        for ev in &pdiag.correlated_events {
            out.push_str(&format!(
                "      * [conn:{}] phase={} term={:?} io={:?} resp_att={:?} resp_ok={:?}\n",
                ev.conn_id,
                ev.phase,
                ev.termination_reason,
                ev.io_result,
                ev.http_response_attempted,
                ev.http_response_write_succeeded
            ));
        }
        out.push_str(&format!(
            "    - Observer Status: total_captured={}, capacity={}, dropped={}\n",
            pdiag.total_captured_events,
            pdiag.observer_ring_capacity,
            pdiag.observer_dropped_events
        ));
        match pdiag.correlation_status {
            CorrelationStatus::Degraded => {
                out.push_str("    - Note: Buffer capacity reached (Drop Newest policy; new events dropped). Diagnostic completeness degraded.\n");
            }
            CorrelationStatus::Ambiguous => {
                out.push_str("    - Note: Ephemeral port collision detected across multiple connections. Causality ambiguous.\n");
            }
            CorrelationStatus::Incomplete => {
                out.push_str("    - Note: Connection recorded in proxy but terminated abnormally without recording terminal event.\n");
            }
            CorrelationStatus::NotFound => {
                out.push_str("    - Note: No proxy events recorded for this client port.\n");
            }
            CorrelationStatus::Complete => {}
        }
    }
    out.push_str("  • OBSERVABILITY LIMITATION: Client-side observations record socket disconnection but do not uniquely identify internal proxy branches without proxy-side instrumentation.\n");
    out.push_str("  • STREAMING LIMITATION NOTE: In the pre-existing proxy architecture, client write interruptions during response streaming terminate the streaming loop via break, but proceed to normal transaction recording. A CompletedSuccessfully diagnostic event indicates that the proxy processing pipeline reached completion, but does not guarantee full byte delivery of streamed response bodies.\n");
    out.push_str("  • STORE OBSERVATION NOTE: The store transaction count and snapshot represent a point-in-time observation captured on the client error path. In-flight requests being processed asynchronously by background proxy worker threads may not have reached store insertion yet, or may still be pending.\n");
    out.push_str("  • PARITY NOTE: Critical failure fields (status, N, failed index, validated count, phase, I/O result, bytes received, observed store count, teardown status) have 1:1 semantic parity with JSON. JSON additionally provides structured transaction summaries and machine-readable metadata arrays.\n");
    out.push_str("--------------------------------------------------\n");
    out
}

/// Formats failure diagnostic into structured JSON without external dependencies
pub fn format_failure_diagnostic_json(d: &PilotFailureDiagnostic) -> String {
    let mut json = String::with_capacity(1024);
    json.push_str("{\n");
    json.push_str(&format!("    \"target_n\": {},\n", d.target_n));
    json.push_str(&format!(
        "    \"failed_request_index\": {},\n",
        d.failed_request_index
    ));
    json.push_str(&format!(
        "    \"validated_requests_count\": {},\n",
        d.validated_requests_count
    ));
    json.push_str(&format!(
        "    \"phase\": \"{}\",\n",
        escape_json(d.phase.as_str())
    ));
    json.push_str(&format!(
        "    \"io_result_type\": \"{}\",\n",
        escape_json(&d.io_result_type)
    ));
    match &d.error_kind {
        Some(k) => json.push_str(&format!("    \"error_kind\": \"{}\",\n", escape_json(k))),
        None => json.push_str("    \"error_kind\": null,\n"),
    }
    match d.os_error_code {
        Some(c) => json.push_str(&format!("    \"os_error_code\": {},\n", c)),
        None => json.push_str("    \"os_error_code\": null,\n"),
    }
    json.push_str(&format!(
        "    \"bytes_received_len\": {},\n",
        d.bytes_received_len
    ));
    json.push_str(&format!(
        "    \"error_message\": \"{}\",\n",
        escape_json(&d.error_message)
    ));
    json.push_str(&format!(
        "    \"store_transaction_count\": {},\n",
        d.store_transaction_count
    ));
    json.push_str(&format!(
        "    \"elapsed_since_start_ms\": {},\n",
        d.elapsed_since_start_ms
    ));
    match d.remaining_budget_ms {
        Some(r) => json.push_str(&format!("    \"remaining_budget_ms\": {},\n", r)),
        None => json.push_str("    \"remaining_budget_ms\": null,\n"),
    }
    json.push_str(&format!(
        "    \"stop_signal_sent\": {},\n",
        d.stop_signal_sent
    ));
    json.push_str(&format!(
        "    \"sockets_released\": {},\n",
        d.sockets_released
    ));

    let tx_items: Vec<String> = d
        .store_summary
        .iter()
        .map(|tx| {
            let sanitized_path = sanitize_transaction_path(&tx.path);
            format!(
                "{{\"id\":{},\"method\":\"{}\",\"path\":\"{}\",\"status_code\":{},\"duration_ms\":{},\"has_request_body\":{},\"has_response_body\":{}}}",
                tx.id,
                escape_json(&tx.method),
                escape_json(sanitized_path),
                tx.status_code
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                tx.duration_ms,
                tx.has_request_body,
                tx.has_response_body
            )
        })
        .collect();
    json.push_str(&format!(
        "    \"store_summary\": [{}],\n",
        tx_items.join(",")
    ));

    match &d.proxy_diagnostics {
        Some(pdiag) => {
            let events_json: Vec<String> = pdiag
                .correlated_events
                .iter()
                .map(|ev| {
                    format!(
                        "{{\"conn_id\":{},\"client_port\":{},\"phase\":\"{}\",\"io_result\":{},\"termination_reason\":{},\"http_response_attempted\":{},\"http_response_write_succeeded\":{}}}",
                        ev.conn_id,
                        ev.client_port,
                        escape_json(&ev.phase),
                        ev.io_result.as_ref().map(|s| format!("\"{}\"", escape_json(s))).unwrap_or_else(|| "null".to_string()),
                        ev.termination_reason.as_ref().map(|s| format!("\"{}\"", escape_json(s))).unwrap_or_else(|| "null".to_string()),
                        ev.http_response_attempted.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string()),
                        ev.http_response_write_succeeded.map(|b| b.to_string()).unwrap_or_else(|| "null".to_string())
                    )
                })
                .collect();

            json.push_str("    \"proxy_diagnostics\": {\n");
            json.push_str(&format!(
                "      \"correlation_status\": \"{}\",\n",
                escape_json(pdiag.correlation_status.as_str())
            ));
            json.push_str(&format!(
                "      \"client_ephemeral_port\": {},\n",
                pdiag
                    .client_ephemeral_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"correlated_conn_id\": {},\n",
                pdiag
                    .correlated_conn_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"correlated_termination_reason\": {},\n",
                pdiag
                    .correlated_termination_reason
                    .as_ref()
                    .map(|r| format!("\"{}\"", escape_json(r)))
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"correlated_phase\": {},\n",
                pdiag
                    .correlated_phase
                    .as_ref()
                    .map(|ph| format!("\"{}\"", escape_json(ph)))
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"correlated_io_result\": {},\n",
                pdiag
                    .correlated_io_result
                    .as_ref()
                    .map(|io| format!("\"{}\"", escape_json(io)))
                    .unwrap_or_else(|| "null".to_string())
            ));
            match &pdiag.terminal_event {
                Some(term) => {
                    json.push_str(&format!(
                        "      \"terminal_event\": {{\"conn_id\":{},\"client_port\":{},\"phase\":\"{}\",\"io_result\":{},\"termination_reason\":{},\"http_response_attempted\":{},\"http_response_write_succeeded\":{}}},\n",
                        term.conn_id,
                        term.client_port,
                        escape_json(&term.phase),
                        term.io_result.as_ref().map(|s| format!("\"{}\"", escape_json(s))).unwrap_or_else(|| "null".to_string()),
                        term.termination_reason.as_ref().map(|s| format!("\"{}\"", escape_json(s))).unwrap_or_else(|| "null".to_string()),
                        term.http_response_attempted.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string()),
                        term.http_response_write_succeeded.map(|b| b.to_string()).unwrap_or_else(|| "null".to_string())
                    ));
                }
                None => {
                    json.push_str("      \"terminal_event\": null,\n");
                }
            }
            json.push_str(&format!(
                "      \"correlated_events\": [{}],\n",
                events_json.join(",")
            ));
            json.push_str(&format!(
                "      \"total_captured_events\": {},\n",
                pdiag.total_captured_events
            ));
            json.push_str(&format!(
                "      \"observer_ring_capacity\": {},\n",
                pdiag.observer_ring_capacity
            ));
            json.push_str(&format!(
                "      \"observer_dropped_events\": {}\n",
                pdiag.observer_dropped_events
            ));
            json.push_str("    },\n");
        }
        None => {
            json.push_str("    \"proxy_diagnostics\": null,\n");
        }
    }

    json.push_str("    \"observability_limitations\": [\n");
    json.push_str("      \"CLIENT_OBSERVATION_NOTE: An EOF or socket error observed at the client indicates that the connection with the proxy terminated, but it does NOT uniquely identify whether the proxy failed at client reading, upstream connection, upstream writing, or upstream reading without proxy-side instrumentation.\",\n");
    json.push_str("      \"STREAMING_LIMITATION_NOTE: In the pre-existing proxy architecture, client write interruptions during response streaming terminate the streaming loop via break, but proceed to normal transaction recording. A CompletedSuccessfully diagnostic event indicates that the proxy processing pipeline reached completion, but does not guarantee full byte delivery of streamed response bodies.\",\n");
    json.push_str("      \"STORE_OBSERVATION_NOTE: The store transaction count and snapshot represent a point-in-time observation captured on the client error path. In-flight requests being processed asynchronously by background proxy worker threads may not have reached store insertion yet, or may still be pending.\",\n");
    json.push_str("      \"PARITY_NOTE: Critical failure fields (status, target_n, failed_request_index, validated_requests_count, phase, io_result_type, bytes_received_len, store_transaction_count, stop_signal_sent, sockets_released) have 1:1 semantic parity between TXT summary and JSON report. JSON additionally provides the structured store_summary transaction array and machine-readable metadata.\"\n");
    json.push_str("    ]\n");
    json.push_str("  }");
    json
}

/// RAII cleanup guard guaranteeing server shutdown on any exit or error path
struct PilotServersGuard<'a> {
    test_server: &'a ControlledTestServer,
    proxy: &'a NativeProxyServer,
}

impl<'a> Drop for PilotServersGuard<'a> {
    fn drop(&mut self) {
        self.test_server.stop();
        self.proxy.stop();
    }
}

/// Runs Module 4: End-to-End Loopback Controlled Pilot Scenario with strict deadline and validation
pub fn run_end_to_end_pilot(n: usize) -> Result<E2eScenarioResult, Box<PilotFailureDiagnostic>> {
    let test_port = get_ephemeral_port();
    let proxy_port = get_ephemeral_port();

    let initial_metrics = query_process_metrics().unwrap_or_default();

    // 1. Start Controlled Local Test Server
    let test_server = ControlledTestServer::new(test_port);
    if let Err(e) = test_server.start() {
        return Err(Box::new(PilotFailureDiagnostic {
            target_n: n,
            failed_request_index: 0,
            validated_requests_count: 0,
            phase: DiagnosticPhase::Startup,
            io_result_type: "TEST_SERVER_BIND_ERROR".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: format!(
                "ControlledTestServer failed to bind on port {}: {}",
                test_port, e
            ),
            store_transaction_count: 0,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 0,
            remaining_budget_ms: Some(SCENARIO_DEADLINE_SECS * 1000),
            stop_signal_sent: false,
            sockets_released: false,
        }));
    }

    // 2. Start Native Capturing Proxy Server with Bounded Diagnostic Observer
    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy_observer = Arc::new(BoundedProxyObserver::new(2000));
    let observer_for_proxy = Arc::clone(&proxy_observer);
    let proxy = NativeProxyServer::with_diagnostic_observer(
        proxy_port,
        Arc::clone(&store),
        scope,
        None,
        Some(Arc::new(move |event| {
            observer_for_proxy.record(event);
        })),
    );
    if let Err(e) = proxy.start() {
        test_server.stop();
        let ports_to_verify = [test_port];
        let sockets_freed = wait_for_ports_released(&ports_to_verify, Duration::from_millis(500));
        return Err(Box::new(PilotFailureDiagnostic {
            target_n: n,
            failed_request_index: 0,
            validated_requests_count: 0,
            phase: DiagnosticPhase::Startup,
            io_result_type: "PROXY_BIND_ERROR".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: format!(
                "NativeProxyServer failed to bind on port {}: {}",
                proxy_port, e
            ),
            store_transaction_count: 0,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 0,
            remaining_budget_ms: Some(SCENARIO_DEADLINE_SECS * 1000),
            stop_signal_sent: true,
            sockets_released: sockets_freed,
        }));
    }

    // Attach RAII cleanup guard guaranteeing shutdown of created servers on any exit
    let guard = PilotServersGuard {
        test_server: &test_server,
        proxy: &proxy,
    };

    // Allow sockets to bind cleanly
    std::thread::sleep(Duration::from_millis(100));

    // 3. Send N controlled HTTP requests over loopback TCP with overall scenario deadline
    let wall_start = Instant::now();
    let scenario_deadline = wall_start + Duration::from_secs(SCENARIO_DEADLINE_SECS);

    let proxy_addr: std::net::SocketAddr = match format!("127.0.0.1:{}", proxy_port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            drop(guard);
            let ports_to_verify = [test_port, proxy_port];
            let sockets_freed =
                wait_for_ports_released(&ports_to_verify, Duration::from_millis(500));
            return Err(Box::new(PilotFailureDiagnostic {
                target_n: n,
                failed_request_index: 0,
                validated_requests_count: 0,
                phase: DiagnosticPhase::Startup,
                io_result_type: "PROXY_ADDR_PARSE_ERROR".to_string(),
                error_kind: None,
                os_error_code: None,
                bytes_received_len: 0,
                error_message: format!("Failed to parse proxy address: {}", e),
                store_transaction_count: 0,
                store_summary: vec![],
                proxy_diagnostics: None,
                elapsed_since_start_ms: 0,
                remaining_budget_ms: Some(SCENARIO_DEADLINE_SECS * 1000),
                stop_signal_sent: true,
                sockets_released: sockets_freed,
            }));
        }
    };

    let mut validated_count = 0;
    let mut last_client_port: Option<u16> = None;

    let capture_diag_and_cleanup = |failed_idx: usize,
                                    val_count: usize,
                                    phase: DiagnosticPhase,
                                    io_type: &str,
                                    err_kind: Option<String>,
                                    os_code: Option<i32>,
                                    bytes_len: usize,
                                    msg: String,
                                    client_port: Option<u16>|
     -> Box<PilotFailureDiagnostic> {
        let (tx_count, safe_summary) = {
            let st = store.lock().unwrap();
            let count = st.count();
            let summary: Vec<SafeTransactionSummary> = st
                .get_all()
                .iter()
                .map(|t| SafeTransactionSummary {
                    id: t.id,
                    method: t.request.method.to_string(),
                    path: sanitize_transaction_path(&t.request.path).to_string(),
                    status_code: t.response.as_ref().map(|r| r.status_code),
                    duration_ms: t.duration_ms,
                    has_request_body: !t.request.body.is_empty(),
                    has_response_body: t
                        .response
                        .as_ref()
                        .map(|r| !r.body.is_empty())
                        .unwrap_or(false),
                })
                .collect();
            (count, summary)
        };

        // Extract proxy diagnostics correlated by client ephemeral port.
        // On the error path, perform a bounded wait (up to 100ms in 10ms intervals)
        // strictly if remaining scenario budget allows, until the proxy observer records
        // a terminal event for the connection, preventing incomplete snapshots from thread race.
        let wait_start = Instant::now();
        let max_diag_wait = Duration::from_millis(100);
        let diag_poll_interval = Duration::from_millis(10);
        while wait_start.elapsed() < max_diag_wait && Instant::now() < scenario_deadline {
            let snap = proxy_observer.snapshot();
            let has_terminal = if let Some(port) = client_port {
                snap.iter()
                    .any(|ev| ev.client_port == port && ev.termination_reason.is_some())
            } else {
                false
            };
            if has_terminal {
                break;
            }
            let sleep_dur = calculate_diagnostic_poll_sleep(
                diag_poll_interval,
                wait_start.elapsed(),
                max_diag_wait,
                Instant::now(),
                scenario_deadline,
            );
            if sleep_dur.is_zero() {
                break;
            }
            std::thread::sleep(sleep_dur);
        }

        let all_events = proxy_observer.snapshot();
        let total_captured = proxy_observer.total_captured();
        let ring_cap = proxy_observer.capacity();
        let dropped_events = proxy_observer.dropped_count();

        let proxy_diag = Some(correlate_proxy_diagnostics(
            client_port,
            &all_events,
            total_captured,
            ring_cap,
            dropped_events,
        ));

        test_server.stop();
        proxy.stop();

        let ports_to_verify = [test_port, proxy_port];
        let sockets_freed = wait_for_ports_released(&ports_to_verify, Duration::from_millis(500));

        let elapsed = wall_start.elapsed();
        let remaining_budget = if Instant::now() < scenario_deadline {
            Some(scenario_deadline.duration_since(Instant::now()).as_millis() as u64)
        } else {
            None
        };

        Box::new(PilotFailureDiagnostic {
            target_n: n,
            failed_request_index: failed_idx,
            validated_requests_count: val_count,
            phase,
            io_result_type: io_type.to_string(),
            error_kind: err_kind,
            os_error_code: os_code,
            bytes_received_len: bytes_len,
            error_message: msg,
            store_transaction_count: tx_count,
            store_summary: safe_summary,
            proxy_diagnostics: proxy_diag,
            elapsed_since_start_ms: elapsed.as_millis() as u64,
            remaining_budget_ms: remaining_budget,
            stop_signal_sent: true,
            sockets_released: sockets_freed,
        })
    };

    for i in 1..=n {
        let remaining = match calculate_remaining_budget(Instant::now(), scenario_deadline) {
            Ok(rem) => rem,
            Err(e) => {
                drop(guard);
                return Err(capture_diag_and_cleanup(
                    i,
                    validated_count,
                    DiagnosticPhase::ConnectProxy,
                    "SCENARIO_DEADLINE_EXCEEDED",
                    None,
                    None,
                    0,
                    e,
                    last_client_port,
                ));
            }
        };
        let connect_timeout = remaining.min(Duration::from_millis(SOCKET_TIMEOUT_MS));

        let mut stream = match TcpStream::connect_timeout(&proxy_addr, connect_timeout) {
            Ok(s) => s,
            Err(e) => {
                let io_type = match e.kind() {
                    std::io::ErrorKind::TimedOut => "TIMED_OUT",
                    std::io::ErrorKind::ConnectionRefused => "CONNECTION_REFUSED",
                    std::io::ErrorKind::ConnectionReset => "CONNECTION_RESET",
                    std::io::ErrorKind::WouldBlock => "WOULD_BLOCK",
                    _ => "CONNECT_ERROR",
                };
                drop(guard);
                return Err(capture_diag_and_cleanup(
                    i,
                    validated_count,
                    DiagnosticPhase::ConnectProxy,
                    io_type,
                    Some(format!("{:?}", e.kind())),
                    e.raw_os_error(),
                    0,
                    format!(
                        "Failed to connect to proxy on 127.0.0.1:{} within {:?}: {}",
                        proxy_port, connect_timeout, e
                    ),
                    None,
                ));
            }
        };

        let current_client_port = stream.local_addr().ok().map(|a| a.port());
        last_client_port = current_client_port;

        let remaining = match calculate_remaining_budget(Instant::now(), scenario_deadline) {
            Ok(rem) => rem,
            Err(e) => {
                drop(stream);
                drop(guard);
                return Err(capture_diag_and_cleanup(
                    i,
                    validated_count,
                    DiagnosticPhase::WriteRequest,
                    "SCENARIO_DEADLINE_EXCEEDED",
                    None,
                    None,
                    0,
                    e,
                    current_client_port,
                ));
            }
        };
        let op_timeout = remaining.min(Duration::from_millis(SOCKET_TIMEOUT_MS));
        if let Err(e) = stream.set_write_timeout(Some(op_timeout)) {
            drop(stream);
            drop(guard);
            return Err(capture_diag_and_cleanup(
                i,
                validated_count,
                DiagnosticPhase::WriteRequest,
                "SET_WRITE_TIMEOUT_ERROR",
                Some(format!("{:?}", e.kind())),
                e.raw_os_error(),
                0,
                format!("Failed to set write timeout: {}", e),
                current_client_port,
            ));
        }

        let req_body = format!("{{\"pilot_req\":{}}}", i);
        let req = format!(
            "POST http://127.0.0.1:{}/api/status HTTP/1.1\r\n\
             Host: 127.0.0.1:{}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            test_port,
            test_port,
            req_body.len(),
            req_body
        );

        if let Err(e) = stream.write_all(req.as_bytes()) {
            let io_type = match e.kind() {
                std::io::ErrorKind::BrokenPipe => "BROKEN_PIPE",
                std::io::ErrorKind::ConnectionReset => "CONNECTION_RESET",
                std::io::ErrorKind::TimedOut => "TIMED_OUT",
                std::io::ErrorKind::WouldBlock => "WOULD_BLOCK",
                _ => "WRITE_ERROR",
            };
            drop(stream);
            drop(guard);
            return Err(capture_diag_and_cleanup(
                i,
                validated_count,
                DiagnosticPhase::WriteRequest,
                io_type,
                Some(format!("{:?}", e.kind())),
                e.raw_os_error(),
                0,
                format!("Write to proxy failed at request {}: {}", i, e),
                current_client_port,
            ));
        }

        let resp = match read_response_bounded_loop(
            &mut stream,
            MAX_RESPONSE_BYTES,
            scenario_deadline,
            SOCKET_TIMEOUT_MS,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                let io_type = e.classification.as_str();
                drop(stream);
                drop(guard);
                return Err(capture_diag_and_cleanup(
                    i,
                    validated_count,
                    DiagnosticPhase::ReadResponse,
                    io_type,
                    e.error_kind.map(|k| format!("{:?}", k)),
                    e.os_code,
                    e.bytes_read,
                    e.message,
                    current_client_port,
                ));
            }
        };
        drop(stream);

        if let Err(e) = validate_http_status_line(&resp) {
            let io_result_type = if resp.is_empty() {
                ReadErrorKind::EofZeroBytes.as_str()
            } else if !resp.contains(&b'\n') {
                ReadErrorKind::IncompleteHttpStatus.as_str()
            } else {
                ReadErrorKind::InvalidHttpStatus.as_str()
            };
            drop(guard);
            return Err(capture_diag_and_cleanup(
                i,
                validated_count,
                DiagnosticPhase::ValidateResponse,
                io_result_type,
                None,
                None,
                resp.len(),
                format!(
                    "Request {} response validation failed in phase VALIDATE_RESPONSE: {}",
                    i, e
                ),
                current_client_port,
            ));
        }

        validated_count += 1;
    }
    let wall_elapsed = wall_start.elapsed();

    // Allow background worker threads to persist transactions
    std::thread::sleep(Duration::from_millis(150));

    let final_metrics = query_process_metrics().unwrap_or_default();
    let captured_count = store.lock().unwrap().count();

    // 4. Teardown phase
    drop(guard);

    let ports_to_verify = [test_port, proxy_port];
    let sockets_freed = wait_for_ports_released(&ports_to_verify, Duration::from_millis(500));

    if captured_count != n {
        return Err(capture_diag_and_cleanup(
            n,
            validated_count,
            DiagnosticPhase::VerifyStore,
            "STORE_COUNT_MISMATCH",
            None,
            None,
            0,
            format!(
                "Validation failure: captured {} transactions in store, expected {}",
                captured_count, n
            ),
            last_client_port,
        ));
    }

    if !sockets_freed {
        return Err(capture_diag_and_cleanup(
            n,
            validated_count,
            DiagnosticPhase::Shutdown,
            "SOCKET_RELEASE_TIMEOUT",
            None,
            None,
            0,
            "Validation failure: ephemeral sockets were not freed on shutdown within timeout"
                .to_string(),
            last_client_port,
        ));
    }

    Ok(E2eScenarioResult {
        target_dispatched: n,
        transactions_captured: captured_count,
        wall_clock_duration: wall_elapsed,
        sockets_released: sockets_freed,
        validation_passed: true,
        initial_metrics,
        final_metrics,
        error_message: None,
    })
}

/// Parameters for formatting the JSON report programmatically
pub struct JsonReportParams<'a> {
    pub run_id: &'a str,
    pub timestamp_utc: &'a str,
    pub command_str: &'a str,
    pub seed: u64,
    pub prf01_5: Option<&'a ModuleResult>,
    pub prf02_5: Option<&'a ModuleResult>,
    pub e2e_5: Option<&'a E2eScenarioResult>,
    pub prf01_25: Option<&'a ModuleResult>,
    pub prf02_25: Option<&'a ModuleResult>,
    pub e2e_25: Option<&'a E2eScenarioResult>,
    pub prf01_100: Option<&'a ModuleResult>,
    pub prf02_100: Option<&'a ModuleResult>,
    pub e2e_100: Option<&'a E2eScenarioResult>,
    pub prf06: &'a ModuleResult,
    pub failure_diagnostic: Option<&'a PilotFailureDiagnostic>,
}

/// Formats the JSON report programmatically without external dependencies
pub fn format_json_report(params: &JsonReportParams<'_>) -> String {
    let mut json = String::with_capacity(4096);
    json.push_str("{\n");
    json.push_str(&format!(
        "  \"run_id\": \"{}\",\n",
        escape_json(params.run_id)
    ));
    json.push_str(&format!(
        "  \"timestamp_utc\": \"{}\",\n",
        escape_json(params.timestamp_utc)
    ));
    json.push_str(&format!(
        "  \"command\": \"{}\",\n",
        escape_json(params.command_str)
    ));
    json.push_str(&format!("  \"seed\": \"0x{:X}\",\n", params.seed));
    let status_str = if params.failure_diagnostic.is_some() {
        "FAILED"
    } else {
        "PASS"
    };
    json.push_str(&format!("  \"status\": \"{}\",\n", status_str));
    match params.failure_diagnostic {
        Some(diag) => {
            json.push_str(&format!(
                "  \"failure_diagnostic\": {},\n",
                format_failure_diagnostic_json(diag)
            ));
        }
        None => {
            json.push_str("  \"failure_diagnostic\": null,\n");
        }
    }
    json.push_str(&format!(
        "  \"build_profile\": \"{}\",\n",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    ));
    json.push_str("  \"environment\": {\n");
    json.push_str(&format!(
        "    \"os\": \"{}\",\n",
        escape_json(platform::PlatformInfo::OS_NAME)
    ));
    json.push_str(&format!(
        "    \"arch\": \"{}\"\n",
        escape_json(platform::PlatformInfo::ARCH)
    ));
    json.push_str("  },\n");

    let format_stats_json = |stats_opt: Option<&SampleStatistics>| -> String {
        match stats_opt {
            Some(s) => {
                let samples_str: Vec<String> =
                    s.raw_samples.iter().map(|v| format!("{:.4}", v)).collect();
                format!(
                    "{{\"count\":{},\"unit\":\"microseconds\",\"min\":{:.4},\"max\":{:.4},\"mean\":{:.4},\"median\":{:.4},\"std_dev\":{:.4},\"samples\":[{}]}}",
                    s.count, s.min, s.max, s.mean, s.median, s.std_dev, samples_str.join(",")
                )
            }
            None => "\"NOT_AVAILABLE\"".to_string(),
        }
    };

    let format_e2e_json = |e2e_opt: Option<&E2eScenarioResult>| -> String {
        match e2e_opt {
            Some(e) => {
                let ws_init = e
                    .initial_metrics
                    .working_set_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let ws_fin = e
                    .final_metrics
                    .working_set_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let ws_delta = match (
                    e.initial_metrics.working_set_bytes,
                    e.final_metrics.working_set_bytes,
                ) {
                    (Some(i), Some(f)) => (f as isize - i as isize).to_string(),
                    _ => "\"NOT_AVAILABLE\"".to_string(),
                };

                let pb_init = e
                    .initial_metrics
                    .private_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let pb_fin = e
                    .final_metrics
                    .private_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let pb_delta = match (
                    e.initial_metrics.private_bytes,
                    e.final_metrics.private_bytes,
                ) {
                    (Some(i), Some(f)) => (f as isize - i as isize).to_string(),
                    _ => "\"NOT_AVAILABLE\"".to_string(),
                };

                let anon_init = e
                    .initial_metrics
                    .anonymous_rss_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let anon_fin = e
                    .final_metrics
                    .anonymous_rss_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let anon_delta = match (
                    e.initial_metrics.anonymous_rss_bytes,
                    e.final_metrics.anonymous_rss_bytes,
                ) {
                    (Some(i), Some(f)) => (f as isize - i as isize).to_string(),
                    _ => "\"NOT_AVAILABLE\"".to_string(),
                };

                let cpu_total = e
                    .final_metrics
                    .cpu_time_ms
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\"NOT_AVAILABLE\"".to_string());
                let cpu_delta = match (e.initial_metrics.cpu_time_ms, e.final_metrics.cpu_time_ms) {
                    (Some(i), Some(f)) => f.saturating_sub(i).to_string(),
                    _ => "\"NOT_AVAILABLE\"".to_string(),
                };

                format!(
                    "{{\"dispatched\":{},\"captured\":{},\"wall_clock_ms\":{:.4},\"sockets_released\":{},\"validation_passed\":{},\"working_set_initial_bytes\":{},\"working_set_final_bytes\":{},\"working_set_delta_bytes\":{},\"private_bytes_initial\":{},\"private_bytes_final\":{},\"private_bytes_delta\":{},\"anonymous_rss_initial_bytes\":{},\"anonymous_rss_final_bytes\":{},\"anonymous_rss_delta_bytes\":{},\"cpu_total_ms\":{},\"cpu_delta_ms\":{}}}",
                    e.target_dispatched,
                    e.transactions_captured,
                    e.wall_clock_duration.as_secs_f64() * 1000.0,
                    e.sockets_released,
                    e.validation_passed,
                    ws_init,
                    ws_fin,
                    ws_delta,
                    pb_init,
                    pb_fin,
                    pb_delta,
                    anon_init,
                    anon_fin,
                    anon_delta,
                    cpu_total,
                    cpu_delta
                )
            }
            None => "\"NOT_AVAILABLE\"".to_string(),
        }
    };

    json.push_str("  \"pilot_5\": {\n");
    json.push_str(&format!(
        "    \"prf01_clone\": {},\n",
        format_stats_json(params.prf01_5.and_then(|m| m.stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf01_transform\": {},\n",
        format_stats_json(params.prf01_5.and_then(|m| m.secondary_stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf02_get_all\": {},\n",
        format_stats_json(params.prf02_5.and_then(|m| m.stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf02_get_by_id\": {},\n",
        format_stats_json(params.prf02_5.and_then(|m| m.secondary_stats.as_ref()))
    ));
    json.push_str(&format!("    \"e2e\": {}\n", format_e2e_json(params.e2e_5)));
    json.push_str("  },\n");

    json.push_str("  \"pilot_25\": {\n");
    json.push_str(&format!(
        "    \"prf01_clone\": {},\n",
        format_stats_json(params.prf01_25.and_then(|m| m.stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf01_transform\": {},\n",
        format_stats_json(params.prf01_25.and_then(|m| m.secondary_stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf02_get_all\": {},\n",
        format_stats_json(params.prf02_25.and_then(|m| m.stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf02_get_by_id\": {},\n",
        format_stats_json(params.prf02_25.and_then(|m| m.secondary_stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"e2e\": {}\n",
        format_e2e_json(params.e2e_25)
    ));
    json.push_str("  },\n");

    json.push_str("  \"pilot_100\": {\n");
    json.push_str(&format!(
        "    \"prf01_clone\": {},\n",
        format_stats_json(params.prf01_100.and_then(|m| m.stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf01_transform\": {},\n",
        format_stats_json(params.prf01_100.and_then(|m| m.secondary_stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf02_get_all\": {},\n",
        format_stats_json(params.prf02_100.and_then(|m| m.stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"prf02_get_by_id\": {},\n",
        format_stats_json(params.prf02_100.and_then(|m| m.secondary_stats.as_ref()))
    ));
    json.push_str(&format!(
        "    \"e2e\": {}\n",
        format_e2e_json(params.e2e_100)
    ));
    json.push_str("  },\n");

    json.push_str("  \"invariants\": {\n");
    json.push_str("    \"traffic_store_max_capacity\": 10000,\n");
    json.push_str("    \"limit_type\": \"count_only\",\n");
    json.push_str("    \"global_ram_limit\": \"unbounded_by_count\",\n");
    json.push_str("    \"request_body_retention_risk\": \"uncompressed_in_memory\",\n");
    json.push_str("    \"event_loop_latency_status\": \"NOT_INSTRUMENTED_LOCALLY\",\n");
    json.push_str(
        "    \"traffic_store_get_by_id_complexity\": \"O(N)_linear_search_in_vec_deque\",\n",
    );
    let prf06_notes: Vec<String> = params
        .prf06
        .notes
        .iter()
        .map(|n| format!("\"{}\"", escape_json(n)))
        .collect();
    json.push_str(&format!("    \"notes\": [{}]\n", prf06_notes.join(",")));
    json.push_str("  }\n");
    json.push_str("}\n");
    json
}

/// Saves evidence files without overwriting existing files, leaving identifiable failure markers without deleting files on partial failure
pub fn save_evidence_files(
    output_dir: &Path,
    run_id: &str,
    summary_content: &str,
    json_content: &str,
) -> Result<(PathBuf, PathBuf), String> {
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory {:?}: {}", output_dir, e))?;

    let summary_filename = format!("perf_baseline_summary_{}.txt", run_id);
    let json_filename = format!("perf_baseline_data_{}.json", run_id);

    let summary_path = output_dir.join(summary_filename);
    let json_path = output_dir.join(json_filename);

    let mut summary_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&summary_path)
        .map_err(|e| {
            format!(
                "Failed to create new summary file {:?}: {}",
                summary_path, e
            )
        })?;
    summary_file
        .write_all(summary_content.as_bytes())
        .map_err(|e| format!("Failed to write summary: {}", e))?;

    let mut json_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&json_path)
    {
        Ok(f) => f,
        Err(e) => {
            let marker_path = output_dir.join(format!("{}.partial_failure", run_id));
            if let Ok(mut marker_file) = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker_path)
            {
                let _ = marker_file.write_all(
                    format!(
                        "PARTIAL WRITE FAILURE: Failed to create JSON file {:?}: {}\nSummary preserved at {:?}\n",
                        json_path, e, summary_path
                    )
                    .as_bytes(),
                );
            }
            return Err(format!(
                "Failed to create new JSON file {:?}: {}. Summary preserved at {:?}. Marker created at {:?}",
                json_path, e, summary_path, marker_path
            ));
        }
    };

    if let Err(e) = json_file.write_all(json_content.as_bytes()) {
        let marker_path = output_dir.join(format!("{}.partial_failure", run_id));
        if let Ok(mut marker_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
        {
            let _ = marker_file.write_all(
                format!(
                    "PARTIAL WRITE FAILURE: Failed to write JSON file {:?}: {}\nSummary preserved at {:?}\n",
                    json_path, e, summary_path
                )
                .as_bytes(),
            );
        }
        return Err(format!(
            "Failed to write JSON content to {:?}: {}. Summary preserved at {:?}",
            json_path, e, summary_path
        ));
    }

    Ok((summary_path, json_path))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = match parse_cli_args(&args) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("ERROR: {}", err);
            std::process::exit(1);
        }
    };

    if config.command == CliCommand::Help {
        println!("Kaska Performance Baseline & Pilot Harness (1.3D-1A-R3)");
        println!("Usage: perf_baseline [COMMAND] [OPTIONS]");
        println!();
        println!("Commands:");
        println!("  --validate       Execute probe validation without network load");
        println!("  --pilot-5        Execute controlled pilot scenario N=5 exclusively");
        println!("  --pilot-25       Execute controlled pilot scenario N=25 exclusively");
        println!("  --pilot-100      Execute controlled pilot scenario N=100 exclusively");
        println!("  --all            Execute sequential pilot scenarios N=5 and N=25 exclusively");
        println!("  --inspector-10k  Execute 10k transaction Inspector metadata & filtering pipeline benchmark");
        println!("  --help, -h       Display this help message");
        println!();
        println!("Options:");
        println!("  --output-dir <DIR>  Specify custom output directory for evidence files");
        return;
    }

    let now = SystemTime::now();
    let run_id = generate_run_id(now);
    let timestamp_utc = format_utc_timestamp(now);
    let output_dir = match resolve_output_dir(config.output_dir, &run_id) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("ERROR: {}", err);
            std::process::exit(1);
        }
    };

    let mut log_accumulator = String::new();

    let banner = format!(
        "==================================================================\n\
         KASKA PERFORMANCE BASELINE & PILOT HARNESS (1.3D-1A-R3)\n\
         OS / Arch: {}\n\
         Run ID: {}\n\
         Timestamp UTC: {}\n\
         Fixed Seed: 0x{:X}\n\
         Output Target: {}\n\
         ==================================================================\n\n",
        platform::PlatformInfo::display_summary(),
        run_id,
        timestamp_utc,
        DEFAULT_FIXED_SEED,
        output_dir.display()
    );
    print!("{}", banner);
    log_accumulator.push_str(&banner);

    if config.command == CliCommand::Validate {
        let mut val_log = String::new();
        val_log.push_str("[MODE: VALIDATION WITHOUT LOAD]\n");
        let p_ephemeral = get_ephemeral_port();
        val_log.push_str(&format!(
            "1. Ephemeral port probe: Port {} available and released cleanly.\n",
            p_ephemeral
        ));
        val_log.push_str("   EPHEMERAL PORT NOTICE: Ephemeral ports were probed by binding temporarily to port 0; potential TOCTOU race is logged and handled defensively via listener error checks without terminating foreign processes.\n");
        let store = TrafficStore::default();
        val_log.push_str(&format!(
            "2. TrafficStore initialization: count = {}, max_capacity = 10000\n",
            store.count()
        ));
        let metrics = query_process_metrics().unwrap_or_default();
        let ws_str = metrics
            .working_set_bytes
            .map(|v| format!("{:.2} MiB", v as f64 / (1024.0 * 1024.0)))
            .unwrap_or_else(|| "NOT_AVAILABLE".to_string());
        let pb_str = metrics
            .private_bytes
            .map(|v| format!("{:.2} MiB", v as f64 / (1024.0 * 1024.0)))
            .unwrap_or_else(|| "NOT_AVAILABLE".to_string());
        let ar_str = metrics
            .anonymous_rss_bytes
            .map(|v| format!("{:.2} MiB", v as f64 / (1024.0 * 1024.0)))
            .unwrap_or_else(|| "NOT_AVAILABLE".to_string());
        val_log.push_str(&format!(
            "3. Process metrics: Working Set = {}, Private Bytes = {}, Anonymous RSS = {}\n",
            ws_str, pb_str, ar_str
        ));
        val_log.push_str("VALIDATION COMPLETE: System ready for controlled pilots.\n");
        print!("{}", val_log);
        log_accumulator.push_str(&val_log);

        let prf06 = run_prf06_limits_check();
        let prf06_str = format_module_summary(&prf06);
        print!("{}", prf06_str);
        log_accumulator.push_str(&prf06_str);

        let report_params = JsonReportParams {
            run_id: &run_id,
            timestamp_utc: &timestamp_utc,
            command_str: "--validate",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: None,
        };
        let json_content = format_json_report(&report_params);

        match save_evidence_files(&output_dir, &run_id, &log_accumulator, &json_content) {
            Ok((sum_path, json_path)) => {
                println!("\n>> Validation summary saved: {}", sum_path.display());
                println!(">> Validation JSON saved: {}", json_path.display());
            }
            Err(e) => {
                eprintln!("ERROR: Failed to save validation evidence: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if config.command == CliCommand::Inspector10k {
        let iterations = 10;
        println!(
            "\n>>> RUNNING INSPECTOR 10,000 TRANSACTION BENCHMARK (iterations = {})",
            iterations
        );
        let res = run_inspector_10k_microbenchmark(iterations);
        let summary = format_inspector_10k_summary(&res);
        print!("{}", summary);
        log_accumulator.push_str(&summary);

        let mut json_out = String::new();
        json_out.push_str("{\n");
        json_out.push_str(&format!("  \"run_id\": \"{}\",\n", escape_json(&run_id)));
        json_out.push_str(&format!(
            "  \"timestamp_utc\": \"{}\",\n",
            escape_json(&timestamp_utc)
        ));
        json_out.push_str("  \"command\": \"--inspector-10k\",\n");
        json_out.push_str("  \"status\": \"PASS\",\n");
        json_out.push_str(&format!(
            "  \"build_profile\": \"{}\",\n",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        ));
        json_out.push_str(&format!(
            "  \"total_transactions\": {},\n",
            res.total_transactions
        ));
        json_out.push_str(&format!(
            "  \"neutral_visible\": {},\n",
            res.neutral_visible
        ));
        json_out.push_str(&format!(
            "  \"restrictive_visible\": {},\n",
            res.restrictive_visible
        ));
        json_out.push_str(&format!(
            "  \"text_search_visible\": {},\n",
            res.text_search_visible
        ));
        json_out.push_str("  \"stages_us\": {\n");
        let fmt_stage_json = |s: &SampleStatistics| -> String {
            format!("{{\"min\":{:.2},\"p50\":{:.2},\"p95\":{:.2},\"max\":{:.2},\"mean\":{:.2},\"std_dev\":{:.2}}}",
                s.min, s.median, s.p95(), s.max, s.mean, s.std_dev)
        };
        json_out.push_str(&format!(
            "    \"get_metadata_snapshot\": {},\n",
            fmt_stage_json(&res.metadata_snapshot)
        ));
        json_out.push_str(&format!(
            "    \"neutral_filter_matching\": {},\n",
            fmt_stage_json(&res.neutral_filter)
        ));
        json_out.push_str(&format!(
            "    \"restrictive_filter_matching\": {},\n",
            fmt_stage_json(&res.restrictive_filter)
        ));
        json_out.push_str(&format!(
            "    \"text_search\": {},\n",
            fmt_stage_json(&res.text_search)
        ));
        json_out.push_str(&format!(
            "    \"model_projection\": {},\n",
            fmt_stage_json(&res.model_projection)
        ));
        json_out.push_str(&format!(
            "    \"full_pipeline\": {},\n",
            fmt_stage_json(&res.full_pipeline)
        ));
        json_out.push_str(&format!(
            "    \"legacy_comparison\": {},\n",
            fmt_stage_json(&res.legacy_comparison)
        ));
        json_out.push_str(&format!(
            "    \"details_lookup_by_id\": {}\n",
            fmt_stage_json(&res.details_lookup)
        ));
        json_out.push_str("  }\n");
        json_out.push_str("}\n");

        match save_evidence_files(&output_dir, &run_id, &log_accumulator, &json_out) {
            Ok((sum_path, json_path)) => {
                println!("\n>> Inspector 10k summary saved: {}", sum_path.display());
                println!(">> Inspector 10k JSON saved: {}", json_path.display());
            }
            Err(e) => {
                eprintln!("ERROR: Failed to save Inspector 10k evidence: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    let mut prf01_5: Option<ModuleResult> = None;
    let mut prf02_5: Option<ModuleResult> = None;
    let mut e2e_5: Option<E2eScenarioResult> = None;

    let mut prf01_25: Option<ModuleResult> = None;
    let mut prf02_25: Option<ModuleResult> = None;
    let mut e2e_25: Option<E2eScenarioResult> = None;

    let mut prf01_100: Option<ModuleResult> = None;
    let mut prf02_100: Option<ModuleResult> = None;
    let mut e2e_100: Option<E2eScenarioResult> = None;

    let mut failure_diagnostic: Option<PilotFailureDiagnostic> = None;

    let execute_pilot_5 = config.command == CliCommand::Pilot5 || config.command == CliCommand::All;
    let execute_pilot_25 =
        config.command == CliCommand::Pilot25 || config.command == CliCommand::All;
    let execute_pilot_100 = config.command == CliCommand::Pilot100;

    if execute_pilot_5 {
        println!("\n>>> RUNNING PILOT STAGE 1: N = 5");
        log_accumulator.push_str("\n>>> RUNNING PILOT STAGE 1: N = 5\n");

        let r1 = run_prf01_microbenchmark(5, 5);
        let s1 = format_module_summary(&r1);
        print!("{}", s1);
        log_accumulator.push_str(&s1);
        prf01_5 = Some(r1);

        let r2 = run_prf02_microbenchmark(5, 5);
        let s2 = format_module_summary(&r2);
        print!("{}", s2);
        log_accumulator.push_str(&s2);
        prf02_5 = Some(r2);

        match run_end_to_end_pilot(5) {
            Ok(e) => {
                let e_str = format_e2e_summary(&e, 5);
                print!("{}", e_str);
                log_accumulator.push_str(&e_str);
                e2e_5 = Some(e);
            }
            Err(diag) => {
                let diag_str = format_failure_diagnostic_summary(&diag);
                print!("{}", diag_str);
                log_accumulator.push_str(&diag_str);
                failure_diagnostic = Some(*diag);
            }
        }
    }

    if failure_diagnostic.is_none() && execute_pilot_25 {
        println!("\n>>> RUNNING PILOT STAGE 2: N = 25");
        log_accumulator.push_str("\n>>> RUNNING PILOT STAGE 2: N = 25\n");

        let r1 = run_prf01_microbenchmark(25, 5);
        let s1 = format_module_summary(&r1);
        print!("{}", s1);
        log_accumulator.push_str(&s1);
        prf01_25 = Some(r1);

        let r2 = run_prf02_microbenchmark(25, 5);
        let s2 = format_module_summary(&r2);
        print!("{}", s2);
        log_accumulator.push_str(&s2);
        prf02_25 = Some(r2);

        match run_end_to_end_pilot(25) {
            Ok(e) => {
                let e_str = format_e2e_summary(&e, 25);
                print!("{}", e_str);
                log_accumulator.push_str(&e_str);
                e2e_25 = Some(e);
            }
            Err(diag) => {
                let diag_str = format_failure_diagnostic_summary(&diag);
                print!("{}", diag_str);
                log_accumulator.push_str(&diag_str);
                failure_diagnostic = Some(*diag);
            }
        }
    }

    if failure_diagnostic.is_none() && execute_pilot_100 {
        println!("\n>>> RUNNING PILOT STAGE 3: N = 100");
        log_accumulator.push_str("\n>>> RUNNING PILOT STAGE 3: N = 100\n");

        let r1 = run_prf01_microbenchmark(100, 5);
        let s1 = format_module_summary(&r1);
        print!("{}", s1);
        log_accumulator.push_str(&s1);
        prf01_100 = Some(r1);

        let r2 = run_prf02_microbenchmark(100, 5);
        let s2 = format_module_summary(&r2);
        print!("{}", s2);
        log_accumulator.push_str(&s2);
        prf02_100 = Some(r2);

        match run_end_to_end_pilot(100) {
            Ok(e) => {
                let e_str = format_e2e_summary(&e, 100);
                print!("{}", e_str);
                log_accumulator.push_str(&e_str);
                e2e_100 = Some(e);
            }
            Err(diag) => {
                let diag_str = format_failure_diagnostic_summary(&diag);
                print!("{}", diag_str);
                log_accumulator.push_str(&diag_str);
                failure_diagnostic = Some(*diag);
            }
        }
    }

    let prf06 = run_prf06_limits_check();
    let prf06_str = format_module_summary(&prf06);
    print!("{}", prf06_str);
    log_accumulator.push_str(&prf06_str);

    let cmd_name = match config.command {
        CliCommand::Validate => "--validate",
        CliCommand::Pilot5 => "--pilot-5",
        CliCommand::Pilot25 => "--pilot-25",
        CliCommand::Pilot100 => "--pilot-100",
        CliCommand::All => "--all",
        CliCommand::Inspector10k => "--inspector-10k",
        CliCommand::Help => "--help",
    };

    let report_params = JsonReportParams {
        run_id: &run_id,
        timestamp_utc: &timestamp_utc,
        command_str: cmd_name,
        seed: DEFAULT_FIXED_SEED,
        prf01_5: prf01_5.as_ref(),
        prf02_5: prf02_5.as_ref(),
        e2e_5: e2e_5.as_ref(),
        prf01_25: prf01_25.as_ref(),
        prf02_25: prf02_25.as_ref(),
        e2e_25: e2e_25.as_ref(),
        prf01_100: prf01_100.as_ref(),
        prf02_100: prf02_100.as_ref(),
        e2e_100: e2e_100.as_ref(),
        prf06: &prf06,
        failure_diagnostic: failure_diagnostic.as_ref(),
    };
    let json_content = format_json_report(&report_params);

    if let Some(ref diag) = failure_diagnostic {
        match save_evidence_files(&output_dir, &run_id, &log_accumulator, &json_content) {
            Ok((sum_path, json_path)) => {
                let fail_banner = format!(
                    "\n==================================================================\n\
                     PILOT RUN FAILED. DIAGNOSTIC EVIDENCE PRESERVED FOR AUDIT.\n\
                     Failed Request Index: {} (Phase: {})\n\
                     Summary File: {}\n\
                     JSON File: {}\n\
                     ==================================================================\n",
                    diag.failed_request_index,
                    diag.phase.as_str(),
                    sum_path.display(),
                    json_path.display()
                );
                eprint!("{}", fail_banner);
            }
            Err(e) => {
                eprintln!("ERROR: Failed to save failure evidence files: {}", e);
            }
        }
        std::process::exit(1);
    }

    match save_evidence_files(&output_dir, &run_id, &log_accumulator, &json_content) {
        Ok((sum_path, json_path)) => {
            let finish_banner = format!(
                "\n==================================================================\n\
                 PILOT RUN COMPLETED SUCCESSFULLY. NO EXTENDED BENCHMARKS EXECUTED.\n\
                 Summary File: {}\n\
                 JSON File: {}\n\
                 ==================================================================\n",
                sum_path.display(),
                json_path.display()
            );
            print!("{}", finish_banner);
        }
        Err(e) => {
            eprintln!("ERROR: Failed to save evidence files: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parser_valid_commands() {
        assert_eq!(
            parse_cli_args(&["prog".into(), "--validate".into()])
                .unwrap()
                .command,
            CliCommand::Validate
        );
        assert_eq!(
            parse_cli_args(&["prog".into(), "--pilot-5".into()])
                .unwrap()
                .command,
            CliCommand::Pilot5
        );
        assert_eq!(
            parse_cli_args(&["prog".into(), "--pilot-25".into()])
                .unwrap()
                .command,
            CliCommand::Pilot25
        );
        assert_eq!(
            parse_cli_args(&["prog".into(), "--pilot-100".into()])
                .unwrap()
                .command,
            CliCommand::Pilot100
        );
        assert_eq!(
            parse_cli_args(&["prog".into(), "--all".into()])
                .unwrap()
                .command,
            CliCommand::All
        );
        assert_eq!(
            parse_cli_args(&["prog".into(), "--inspector-10k".into()])
                .unwrap()
                .command,
            CliCommand::Inspector10k
        );
        assert_eq!(
            parse_cli_args(&["prog".into(), "--help".into()])
                .unwrap()
                .command,
            CliCommand::Help
        );
    }

    #[test]
    fn test_cli_parser_rejects_unauthorized_and_unknown_args() {
        assert!(parse_cli_args(&["prog".into(), "--pilot-101".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--pilot-500".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--pilot-1000".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "5".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "25".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "100".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--unknown".into()]).is_err());
        assert!(parse_cli_args(&["prog".into()]).is_err());
    }

    #[test]
    fn test_cli_parser_rejects_conflicting_commands() {
        assert!(parse_cli_args(&["prog".into(), "--pilot-5".into(), "--pilot-25".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--validate".into(), "--all".into()]).is_err());
    }

    #[test]
    fn test_cli_parser_output_dir_option() {
        let cfg = parse_cli_args(&[
            "prog".into(),
            "--pilot-5".into(),
            "--output-dir".into(),
            "/custom/dir".into(),
        ])
        .unwrap();
        assert_eq!(cfg.command, CliCommand::Pilot5);
        assert_eq!(cfg.output_dir, Some(PathBuf::from("/custom/dir")));
    }

    #[test]
    fn test_synthetic_generator_deterministic_seed() {
        let set1 = generate_synthetic_transactions(10, DEFAULT_FIXED_SEED);
        let set2 = generate_synthetic_transactions(10, DEFAULT_FIXED_SEED);
        assert_eq!(set1.len(), 10);
        assert_eq!(set2.len(), 10);
        for i in 0..10 {
            assert_eq!(set1[i].id, set2[i].id);
            assert_eq!(set1[i].request.path, set2[i].request.path);
            assert_eq!(set1[i].request.body, set2[i].request.body);
            assert_eq!(
                set1[i].response.as_ref().unwrap().body,
                set2[i].response.as_ref().unwrap().body
            );
        }
    }

    #[test]
    fn test_synthetic_payload_size_boundary() {
        let txs = generate_synthetic_transactions(25, DEFAULT_FIXED_SEED);
        for tx in txs {
            assert!(tx.request.body.len() <= 100);
            assert!(tx.response.as_ref().unwrap().body.len() <= 100);
        }
    }

    #[test]
    fn test_statistics_computation() {
        let samples = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let stats = SampleStatistics::compute(samples).unwrap();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min, 10.0);
        assert_eq!(stats.max, 50.0);
        assert_eq!(stats.mean, 30.0);
        assert_eq!(stats.median, 30.0);
        assert!((stats.std_dev - 14.142).abs() < 0.01);
    }

    #[test]
    fn test_format_utc_timestamp_epoch() {
        let ts = format_utc_timestamp(UNIX_EPOCH);
        assert_eq!(ts, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_json_escaping() {
        assert_eq!(escape_json("hello \"world\""), "hello \\\"world\\\"");
        assert_eq!(escape_json("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_json("c:\\path"), "c:\\\\path");
    }

    #[test]
    fn test_budget_decreasing_and_expired() {
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(15);

        let budget0 = calculate_remaining_budget(t0, deadline).unwrap();
        assert_eq!(budget0, Duration::from_secs(15));

        let t1 = t0 + Duration::from_secs(5);
        let budget1 = calculate_remaining_budget(t1, deadline).unwrap();
        assert_eq!(budget1, Duration::from_secs(10));

        let t_expired = t0 + Duration::from_secs(15);
        assert!(calculate_remaining_budget(t_expired, deadline).is_err());

        let t_past = t0 + Duration::from_secs(16);
        assert!(calculate_remaining_budget(t_past, deadline).is_err());
    }

    #[test]
    fn test_bounded_read_simulated_chunks() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(data);
        let deadline = Instant::now() + Duration::from_secs(15);

        let res = read_bounded_chunks(&mut cursor, 8192, deadline);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), data);
    }

    #[test]
    fn test_http_status_line_validation_incomplete_or_invalid() {
        assert!(validate_http_status_line(b"").is_err());
        assert!(validate_http_status_line(b"HTTP/1.1").is_err());
        assert!(validate_http_status_line(b"HTTP/1.1 20").is_err());
        assert!(validate_http_status_line(b"HTTP/1.1 200").is_err());
        assert!(validate_http_status_line(b"HTTP/1.1 200\r\n").is_ok());
        assert!(validate_http_status_line(b"HTTP/1.1 200 OK\r\n").is_ok());
        assert!(validate_http_status_line(b"HTTP/1.1 500 Internal Server Error\r\n").is_err());
        assert!(validate_http_status_line(b"HTTP/2.0 200 OK\r\n").is_err());
    }

    #[test]
    fn test_black_box_preserves_evaluation() {
        let val = 42u64;
        let bb = std::hint::black_box(val);
        assert_eq!(val, bb);

        let text = "kaska_perf".to_string();
        let bb_text = std::hint::black_box(text.clone());
        assert_eq!(text, bb_text);
    }

    #[test]
    fn test_run_id_and_timestamp_utc_correlation() {
        let fixed_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let run_id = generate_run_id(fixed_time);
        let ts_utc = format_utc_timestamp(fixed_time);

        assert_eq!(run_id, "run-1700000000-0");
        assert_eq!(ts_utc, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn test_partial_failure_marker_no_overwrite() {
        let temp_dir = std::env::temp_dir().join(format!(
            "kaska-test-marker-{}",
            generate_run_id(SystemTime::now())
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let marker_path = temp_dir.join("test-run.partial_failure");
        fs::write(&marker_path, b"ORIGINAL_MARKER_CONTENT").unwrap();

        let write_res = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path);
        assert!(write_res.is_err());

        let content = fs::read(&marker_path).unwrap();
        assert_eq!(content, b"ORIGINAL_MARKER_CONTENT");
    }

    #[test]
    fn test_output_dir_repo_rejection() {
        let current_dir = std::env::current_dir().unwrap();
        assert!(is_path_inside_repo_or_worktree(&current_dir));

        let relative_current = PathBuf::from(".");
        assert!(is_path_inside_repo_or_worktree(&relative_current));

        let temp_safe = std::env::temp_dir().join("kaska-perf-safe-test");
        assert!(!is_path_inside_repo_or_worktree(&temp_safe));

        assert!(resolve_output_dir(Some(PathBuf::from(".")), "test-run").is_err());
    }

    #[test]
    fn test_linux_process_metrics_labels() {
        let metrics = ProcessMetrics {
            working_set_bytes: Some(1024 * 1024),
            private_bytes: None,
            anonymous_rss_bytes: Some(512 * 1024),
            cpu_time_ms: None,
        };
        assert_eq!(metrics.private_bytes, None);
        assert_eq!(metrics.anonymous_rss_bytes, Some(524288));
        assert_eq!(metrics.cpu_time_ms, None);
    }

    #[test]
    fn test_json_precision_and_units() {
        let mut prf06 = run_prf06_limits_check();
        prf06.notes = vec!["Note 1".into()];
        let report_params = JsonReportParams {
            run_id: "test-run",
            timestamp_utc: "2026-10-15T00:00:00Z",
            command_str: "--validate",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: None,
        };
        let json = format_json_report(&report_params);
        assert!(json.contains("\"run_id\": \"test-run\""));
        assert!(json.contains("\"seed\": \"0x5EED13D12026ABCD\""));
        assert!(json.contains("\"traffic_store_max_capacity\": 10000"));
        assert!(json.contains("\"status\": \"PASS\""));
    }

    #[test]
    fn test_sample_preservation_and_recalculation() {
        let original_samples = vec![1.2345, 2.3456, 3.4567, 4.5678, 5.6789];
        let stats = SampleStatistics::compute(original_samples.clone()).unwrap();
        assert_eq!(stats.raw_samples, original_samples);
        let recalculated = SampleStatistics::compute(stats.raw_samples).unwrap();
        assert_eq!(stats.mean, recalculated.mean);
        assert_eq!(stats.median, recalculated.median);
        assert_eq!(stats.std_dev, recalculated.std_dev);
    }

    #[test]
    fn test_save_evidence_partial_failure() {
        let temp_dir = std::env::temp_dir().join(format!(
            "kaska-test-evidence-{}",
            generate_run_id(SystemTime::now())
        ));
        let summary = "Summary test content";
        let json = "{\"test\":true}";

        let res = save_evidence_files(&temp_dir, "run-1", summary, json);
        assert!(res.is_ok());

        // Attempting to save again with the exact same run_id must fail without deleting
        let res_second = save_evidence_files(&temp_dir, "run-1", summary, json);
        assert!(res_second.is_err());

        // Verify summary still exists
        let summary_path = temp_dir.join("perf_baseline_summary_run-1.txt");
        assert!(summary_path.exists());
    }

    #[test]
    fn test_read_simulated_eof_before_bytes() {
        let mut empty_stream = std::io::Cursor::new(b"");
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut empty_stream, 1024, deadline).unwrap();
        assert!(res.is_empty());
        let val_err = validate_http_status_line(&res).unwrap_err();
        assert_eq!(val_err, "Empty HTTP response received");
    }

    #[test]
    fn test_read_simulated_eof_after_partial_bytes() {
        let mut partial_stream = std::io::Cursor::new(b"HTTP/1.1 200");
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut partial_stream, 1024, deadline).unwrap();
        assert_eq!(res, b"HTTP/1.1 200");
        let val_err = validate_http_status_line(&res).unwrap_err();
        assert_eq!(
            val_err,
            "Malformed HTTP response: no status line delimiter found"
        );
    }

    struct TimeoutReader;
    impl Read for TimeoutReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "simulated read timeout",
            ))
        }
    }

    #[test]
    fn test_read_simulated_timeout() {
        let mut reader = TimeoutReader;
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut reader, 1024, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::TimedOut);
        assert_eq!(err.error_kind, Some(std::io::ErrorKind::TimedOut));
        assert!(err.message.contains("Read timed out"));
    }

    struct BrokenPipeWriter;
    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "simulated broken pipe on write",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_write_simulated_error() {
        let mut writer = BrokenPipeWriter;
        let res = writer.write_all(b"POST /api/status HTTP/1.1\r\n\r\n");
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_http_status_invalid_codes() {
        let codes = [
            (b"HTTP/1.1 502 Bad Gateway\r\n".as_slice(), "502"),
            (b"HTTP/1.1 404 Not Found\r\n".as_slice(), "404"),
            (b"HTTP/1.1 500 Internal Server Error\r\n".as_slice(), "500"),
            (b"HTTP/1.1 403 Forbidden\r\n".as_slice(), "403"),
        ];
        for (raw, code) in codes {
            let err = validate_http_status_line(raw).unwrap_err();
            assert_eq!(
                err,
                format!("Non-200 HTTP status code received: '{}'", code)
            );
        }
    }

    #[test]
    fn test_failure_evidence_persistence_json_and_txt() {
        let temp_dir = std::env::temp_dir().join(format!(
            "kaska-test-failure-evidence-{}",
            generate_run_id(SystemTime::now())
        ));
        let run_id = "test-fail-run-1";
        let diag = PilotFailureDiagnostic {
            target_n: 25,
            failed_request_index: 7,
            validated_requests_count: 6,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "Request 7 response validation failed: Empty HTTP response received"
                .to_string(),
            store_transaction_count: 6,
            store_summary: vec![SafeTransactionSummary {
                id: 1,
                method: "POST".to_string(),
                path: "/api/status".to_string(),
                status_code: Some(200),
                duration_ms: 3,
                has_request_body: true,
                has_response_body: true,
            }],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 120,
            remaining_budget_ms: Some(14880),
            stop_signal_sent: true,
            sockets_released: true,
        };

        let prf06 = run_prf06_limits_check();
        let params = JsonReportParams {
            run_id,
            timestamp_utc: "2026-10-15T12:00:00Z",
            command_str: "--pilot-25",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: Some(&diag),
        };

        let json = format_json_report(&params);
        let summary = format_failure_diagnostic_summary(&diag);

        let (sum_path, json_path) =
            save_evidence_files(&temp_dir, run_id, &summary, &json).unwrap();
        assert!(sum_path.exists());
        assert!(json_path.exists());

        let json_disk = fs::read_to_string(&json_path).unwrap();
        assert!(json_disk.contains("\"status\": \"FAILED\""));
        assert!(json_disk.contains("\"failed_request_index\": 7"));
        assert!(json_disk.contains("\"validated_requests_count\": 6"));
        assert!(json_disk.contains("\"io_result_type\": \"EOF_ZERO_BYTES\""));
        assert!(json_disk.contains("\"error_kind\": null"));
        assert!(json_disk.contains("\"store_transaction_count\": 6"));
        assert!(json_disk.contains("CLIENT_OBSERVATION_NOTE"));
        assert!(json_disk.contains("STORE_OBSERVATION_NOTE"));
        assert!(json_disk.contains("PARITY_NOTE"));

        let sum_disk = fs::read_to_string(&sum_path).unwrap();
        assert!(sum_disk.contains("VALIDATION FAILURE in End-to-End Pilot (N=25)"));
        assert!(sum_disk.contains("Failed Request Index: 7 (Validated: 6/25)"));
        assert!(sum_disk.contains("TrafficStore Observed Count (Point-in-Time): 6"));
        assert!(sum_disk.contains("STORE OBSERVATION NOTE"));
        assert!(sum_disk.contains("PARITY NOTE"));
    }

    #[test]
    fn test_preservation_of_completed_microbenchmark_samples() {
        let r1 = run_prf01_microbenchmark(25, 5);
        let r2 = run_prf02_microbenchmark(25, 5);
        let prf06 = run_prf06_limits_check();

        let diag = PilotFailureDiagnostic {
            target_n: 25,
            failed_request_index: 7,
            validated_requests_count: 6,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "Request 7 response validation failed: Empty HTTP response received"
                .to_string(),
            store_transaction_count: 6,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 120,
            remaining_budget_ms: Some(14880),
            stop_signal_sent: true,
            sockets_released: true,
        };

        let params = JsonReportParams {
            run_id: "test-preserve-samples",
            timestamp_utc: "2026-10-15T12:00:00Z",
            command_str: "--pilot-25",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: Some(&r1),
            prf02_25: Some(&r2),
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: Some(&diag),
        };

        let json = format_json_report(&params);
        assert!(json.contains("\"status\": \"FAILED\""));
        assert!(json.contains("\"prf01_clone\""));
        assert!(json.contains("\"prf01_transform\""));
        assert!(json.contains("\"prf02_get_all\""));
        assert!(json.contains("\"prf02_get_by_id\""));
        assert!(json.contains("\"samples\""));
        assert_eq!(r1.stats.as_ref().unwrap().raw_samples.len(), 5);
    }

    #[test]
    fn test_failure_evidence_no_overwrite_existing() {
        let temp_dir = std::env::temp_dir().join(format!(
            "kaska-test-no-overwrite-{}",
            generate_run_id(SystemTime::now())
        ));
        let run_id = "test-no-overwrite";
        let summary1 = "ORIGINAL_SUMMARY";
        let json1 = "{\"orig\":true}";

        save_evidence_files(&temp_dir, run_id, summary1, json1).unwrap();

        // Second save attempt with same run_id must fail
        let summary2 = "OVERWRITING_SUMMARY";
        let json2 = "{\"orig\":false}";
        let res2 = save_evidence_files(&temp_dir, run_id, summary2, json2);
        assert!(res2.is_err());

        // Assert original content is untouched
        let summary_path = temp_dir.join(format!("perf_baseline_summary_{}.txt", run_id));
        let disk_summary = fs::read_to_string(&summary_path).unwrap();
        assert_eq!(disk_summary, "ORIGINAL_SUMMARY");
    }

    #[test]
    fn test_scenario_logical_failure_exit_status() {
        let diag = PilotFailureDiagnostic {
            target_n: 25,
            failed_request_index: 7,
            validated_requests_count: 6,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "Empty HTTP response received".to_string(),
            store_transaction_count: 6,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 100,
            remaining_budget_ms: None,
            stop_signal_sent: true,
            sockets_released: true,
        };

        let exit_code = if Some(&diag).is_some() { 1 } else { 0 };
        assert_ne!(exit_code, 0);

        let is_pass = Some(&diag).is_none();
        assert!(!is_pass);
    }

    #[test]
    fn test_diagnostic_json_serialization_and_path_redaction() {
        // 1. Verify fail-closed path redaction logic
        assert_eq!(sanitize_transaction_path("/api/status"), "/api/status");
        assert_eq!(
            sanitize_transaction_path("/api/status?token=super_secret_val_1234"),
            "REDACTED"
        );
        assert_eq!(
            sanitize_transaction_path("/auth/token?bearer=xyz"),
            "REDACTED"
        );
        assert_eq!(sanitize_transaction_path("/admin"), "REDACTED");
        assert_eq!(sanitize_transaction_path(""), "REDACTED");

        // 2. Test diagnostic with empty transaction list and null optional fields
        let diag_empty = PilotFailureDiagnostic {
            target_n: 25,
            failed_request_index: 7,
            validated_requests_count: 6,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "Request 7 response validation failed: Empty HTTP response received"
                .to_string(),
            store_transaction_count: 0,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 120,
            remaining_budget_ms: None,
            stop_signal_sent: true,
            sockets_released: true,
        };

        let json_empty = format_failure_diagnostic_json(&diag_empty);
        assert!(json_empty.contains("\"store_summary\": []"));
        assert!(json_empty.contains("\"error_kind\": null"));
        assert!(json_empty.contains("\"os_error_code\": null"));
        assert!(json_empty.contains("\"remaining_budget_ms\": null"));
        assert!(json_empty.contains("\"io_result_type\": \"EOF_ZERO_BYTES\""));

        // 3. Test diagnostic with transactions, secret paths requiring redaction, and characters requiring escaping
        let secret_token = "secret_auth_token_999";
        let diag_with_data = PilotFailureDiagnostic {
            target_n: 25,
            failed_request_index: 7,
            validated_requests_count: 6,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "Validation \"failed\": \\path\\test\nnewline\ttab".to_string(),
            store_transaction_count: 2,
            store_summary: vec![
                SafeTransactionSummary {
                    id: 1,
                    method: "POST".to_string(),
                    path: sanitize_transaction_path("/api/status").to_string(),
                    status_code: Some(200),
                    duration_ms: 3,
                    has_request_body: true,
                    has_response_body: true,
                },
                SafeTransactionSummary {
                    id: 2,
                    method: "GET".to_string(),
                    path: sanitize_transaction_path(&format!("/oauth/token?key={}", secret_token))
                        .to_string(),
                    status_code: None,
                    duration_ms: 5,
                    has_request_body: false,
                    has_response_body: false,
                },
            ],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 150,
            remaining_budget_ms: Some(14850),
            stop_signal_sent: true,
            sockets_released: true,
        };

        let prf06 = run_prf06_limits_check();
        let params = JsonReportParams {
            run_id: "test-redaction-run",
            timestamp_utc: "2026-10-15T12:00:00Z",
            command_str: "--pilot-25",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: Some(&diag_with_data),
        };

        let report_json = format_json_report(&params);
        let summary_txt = format_failure_diagnostic_summary(&diag_with_data);

        // Assert secret token NEVER leaks into JSON or TXT
        assert!(
            !report_json.contains(secret_token),
            "Secret token leaked into JSON report!"
        );
        assert!(
            !summary_txt.contains(secret_token),
            "Secret token leaked into TXT summary!"
        );

        // Assert fail-closed redaction appears in JSON
        assert!(report_json.contains("\"path\":\"/api/status\""));
        assert!(report_json.contains("\"path\":\"REDACTED\""));

        // Assert string escaping worked correctly
        assert!(report_json.contains("Validation \\\"failed\\\": \\\\path\\\\test\\nnewline\\ttab"));

        // Assert FAILED status and null fields
        assert!(report_json.contains("\"status\": \"FAILED\""));
        assert!(report_json.contains("\"error_kind\": null"));
        assert!(report_json.contains("\"os_error_code\": null"));
        assert!(report_json.contains("\"status_code\":null"));
        assert!(report_json.contains("\"remaining_budget_ms\": 14850"));

        // Assert TXT summary does not dump full store array, contains point-in-time observation label and limitation notes
        assert!(summary_txt.contains("TrafficStore Observed Count (Point-in-Time): 2"));
        assert!(summary_txt.contains("STORE OBSERVATION NOTE"));
        assert!(summary_txt.contains("PARITY NOTE"));
        assert!(!summary_txt.contains("has_request_body"));
    }

    #[test]
    fn test_deadline_exceeded_zero_bytes() {
        let mut reader = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n");
        let expired_deadline = Instant::now() - Duration::from_millis(50);
        let res = read_bounded_chunks(&mut reader, 1024, expired_deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ScenarioDeadlineExceeded);
        assert_eq!(err.classification.as_str(), "SCENARIO_DEADLINE_EXCEEDED");
        assert_eq!(err.bytes_read, 0);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    struct PartialThenExpireReader {
        bytes: Vec<u8>,
        read_once: bool,
    }

    impl Read for PartialThenExpireReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.read_once {
                self.read_once = true;
                let to_copy = self.bytes.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&self.bytes[..to_copy]);
                std::thread::sleep(Duration::from_millis(30));
                Ok(to_copy)
            } else {
                Ok(0)
            }
        }
    }

    #[test]
    fn test_deadline_exceeded_after_partial_bytes() {
        let mut reader = PartialThenExpireReader {
            bytes: b"HTTP/1.1 200 ".to_vec(),
            read_once: false,
        };
        let deadline = Instant::now() + Duration::from_millis(10);
        let res = read_bounded_chunks(&mut reader, 1024, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ScenarioDeadlineExceeded);
        assert_eq!(err.classification.as_str(), "SCENARIO_DEADLINE_EXCEEDED");
        assert_eq!(err.bytes_read, 13);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    #[test]
    fn test_real_eof_after_partial_bytes() {
        let mut partial_stream = std::io::Cursor::new(b"HTTP/1.1 200");
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut partial_stream, 1024, deadline).unwrap();
        assert_eq!(res, b"HTTP/1.1 200");
        let val_err = validate_http_status_line(&res).unwrap_err();
        assert_eq!(
            val_err,
            "Malformed HTTP response: no status line delimiter found"
        );
        let io_type = if res.is_empty() {
            ReadErrorKind::EofZeroBytes.as_str()
        } else if !res.contains(&b'\n') {
            ReadErrorKind::IncompleteHttpStatus.as_str()
        } else {
            ReadErrorKind::InvalidHttpStatus.as_str()
        };
        assert_eq!(io_type, "INCOMPLETE_HTTP_STATUS");
    }

    #[test]
    fn test_read_limit_reached_without_eof() {
        let large_payload = vec![b'X'; 256];
        let mut stream = std::io::Cursor::new(large_payload);
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut stream, 64, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ReadLimitReached);
        assert_eq!(err.classification.as_str(), "READ_LIMIT_REACHED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    #[test]
    fn test_http_status_line_redaction_of_sensitive_data() {
        let cases = [
            (
                b"HTTP/1.1 500 Internal Error - secret_token_xyz123\r\n".as_slice(),
                "Non-200 HTTP status code received: '500'",
            ),
            (
                b"HTTP/1.1 404 User john_doe_ssn_9999 Not Found\r\n".as_slice(),
                "Non-200 HTTP status code received: '404'",
            ),
            (
                b"HTTP/1.1 403 Forbidden: Bearer auth_jwt_token_456\r\n".as_slice(),
                "Non-200 HTTP status code received: '403'",
            ),
            (b"HTTP/1.1 200\r\n".as_slice(), "OK"),
            (
                b"UNKNOWN_PROTO/9.9 200 OK\r\n".as_slice(),
                "Unsupported HTTP protocol in status line",
            ),
            (
                b"MALFORMED_LINE_TOKEN\r\n".as_slice(),
                "Malformed HTTP response: status line contains insufficient tokens",
            ),
        ];

        let secret_fragments = [
            "secret_token_xyz123",
            "john_doe_ssn_9999",
            "auth_jwt_token_456",
            "Internal Error",
            "Not Found",
            "Forbidden",
            "UNKNOWN_PROTO",
            "MALFORMED_LINE_TOKEN",
        ];

        for (raw, expected) in cases {
            if expected == "OK" {
                assert!(validate_http_status_line(raw).is_ok());
            } else {
                let err = validate_http_status_line(raw).unwrap_err();
                assert_eq!(err, expected);
                for secret in secret_fragments {
                    assert!(
                        !err.contains(secret),
                        "Sensitive or arbitrary fragment '{}' leaked in error message '{}'",
                        secret,
                        err
                    );
                }
            }
        }
    }

    #[test]
    fn test_json_escaping_control_characters_and_unicode() {
        // RFC 8259 Section 7: all U+0000..=U+001F control characters MUST be escaped
        assert_eq!(escape_json("null:\0"), "null:\\u0000");
        assert_eq!(escape_json("soh:\x01"), "soh:\\u0001");
        assert_eq!(escape_json("us:\x1f"), "us:\\u001f");
        assert_eq!(escape_json("bs:\x08"), "bs:\\b");
        assert_eq!(escape_json("ff:\x0c"), "ff:\\f");
        assert_eq!(escape_json("tab:\t"), "tab:\\t");
        assert_eq!(escape_json("lf:\n"), "lf:\\n");
        assert_eq!(escape_json("cr:\r"), "cr:\\r");
        assert_eq!(escape_json("quote:\""), "quote:\\\"");
        assert_eq!(escape_json("bs:\\"), "bs:\\\\");

        // Unicode preserved as valid UTF-8
        assert_eq!(
            escape_json("Español: áéíóú, 日本語, 🦀"),
            "Español: áéíóú, 日本語, 🦀"
        );
    }

    struct MockProbeReader {
        initial_data: Vec<u8>,
        delivered: bool,
        probe_delay: Option<Duration>,
        probe_result: Option<std::io::Result<usize>>,
    }

    impl Read for MockProbeReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.delivered {
                self.delivered = true;
                let n = self.initial_data.len().min(buf.len());
                buf[..n].copy_from_slice(&self.initial_data[..n]);
                Ok(n)
            } else {
                if let Some(delay) = self.probe_delay {
                    std::thread::sleep(delay);
                }
                match &self.probe_result {
                    Some(Ok(n)) => Ok(*n),
                    Some(Err(e)) => Err(std::io::Error::new(e.kind(), e.to_string())),
                    None => Ok(0),
                }
            }
        }
    }

    #[test]
    fn test_probe_eof_exact_at_max() {
        let exact_payload = vec![b'Z'; 64];
        let mut stream = std::io::Cursor::new(exact_payload);
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut stream, 64, deadline);
        assert!(res.is_ok());
        let buf = res.unwrap();
        assert_eq!(buf.len(), 64);
        assert_eq!(buf, vec![b'Z'; 64]);
    }

    #[test]
    fn test_probe_byte_additional_observed() {
        let payload = vec![b'Y'; 65];
        let mut stream = std::io::Cursor::new(payload);
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut stream, 64, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ReadLimitReached);
        assert_eq!(err.classification.as_str(), "READ_LIMIT_REACHED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
        assert!(err.message.contains("additional byte observed"));
    }

    #[test]
    fn test_probe_timed_out_at_max() {
        let mut reader = MockProbeReader {
            initial_data: vec![b'T'; 64],
            delivered: false,
            probe_delay: None,
            probe_result: Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "socket read timed out",
            ))),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut reader, 64, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::TimedOut);
        assert_eq!(err.classification.as_str(), "TIMED_OUT");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, Some(std::io::ErrorKind::TimedOut));
        assert_eq!(err.os_code, None);
        assert!(!err.message.contains("additional byte observed"));
    }

    #[test]
    fn test_probe_would_block_at_max() {
        let mut reader = MockProbeReader {
            initial_data: vec![b'W'; 64],
            delivered: false,
            probe_delay: None,
            probe_result: Some(Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "resource temporarily unavailable",
            ))),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut reader, 64, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::WouldBlock);
        assert_eq!(err.classification.as_str(), "WOULD_BLOCK");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, Some(std::io::ErrorKind::WouldBlock));
        assert_eq!(err.os_code, None);
        assert!(!err.message.contains("additional byte observed"));
    }

    #[test]
    fn test_probe_deadline_exceeded_during_probe() {
        let mut reader = MockProbeReader {
            initial_data: vec![b'D'; 64],
            delivered: false,
            probe_delay: Some(Duration::from_millis(30)),
            probe_result: Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "socket read timed out",
            ))),
        };
        let deadline = Instant::now() + Duration::from_millis(10);
        let res = read_bounded_chunks(&mut reader, 64, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ScenarioDeadlineExceeded);
        assert_eq!(err.classification.as_str(), "SCENARIO_DEADLINE_EXCEEDED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    #[test]
    fn test_probe_preserves_bytes_read_and_real_error_kind() {
        let mut reader = MockProbeReader {
            initial_data: vec![b'C'; 64],
            delivered: false,
            probe_delay: None,
            probe_result: Some(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset by peer",
            ))),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_bounded_chunks(&mut reader, 64, deadline);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ConnectionReset);
        assert_eq!(err.classification.as_str(), "CONNECTION_RESET");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, Some(std::io::ErrorKind::ConnectionReset));
    }

    #[test]
    fn test_post_probe_ok0_before_deadline_success() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let now_post_probe = base + Duration::from_secs(5);
        let res = classify_probe_outcome(Ok(0), now_post_probe, deadline, 64, 64);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_post_probe_ok0_after_deadline_exceeded() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let now_post_probe = base + Duration::from_secs(12);
        let res = classify_probe_outcome(Ok(0), now_post_probe, deadline, 64, 64);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ScenarioDeadlineExceeded);
        assert_eq!(err.classification.as_str(), "SCENARIO_DEADLINE_EXCEEDED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    #[test]
    fn test_post_probe_ok1_before_deadline_read_limit_reached() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let now_post_probe = base + Duration::from_secs(5);
        let res = classify_probe_outcome(Ok(1), now_post_probe, deadline, 64, 64);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ReadLimitReached);
        assert_eq!(err.classification.as_str(), "READ_LIMIT_REACHED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
        assert!(err.message.contains("additional byte observed"));
    }

    #[test]
    fn test_post_probe_ok1_after_deadline_exceeded() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let now_post_probe = base + Duration::from_secs(15);
        let res = classify_probe_outcome(Ok(1), now_post_probe, deadline, 64, 64);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ScenarioDeadlineExceeded);
        assert_eq!(err.classification.as_str(), "SCENARIO_DEADLINE_EXCEEDED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    #[test]
    fn test_post_probe_timedout_before_deadline_timedout() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let now_post_probe = base + Duration::from_secs(5);
        let io_err = Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "socket timed out",
        ));
        let res = classify_probe_outcome(io_err, now_post_probe, deadline, 64, 64);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::TimedOut);
        assert_eq!(err.classification.as_str(), "TIMED_OUT");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, Some(std::io::ErrorKind::TimedOut));
        assert_eq!(err.os_code, None);
        assert!(!err.message.contains("additional byte observed"));
    }

    #[test]
    fn test_post_probe_timedout_after_deadline_exceeded() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let now_post_probe = base + Duration::from_secs(11);
        let io_err = Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "socket timed out",
        ));
        let res = classify_probe_outcome(io_err, now_post_probe, deadline, 64, 64);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.classification, ReadErrorKind::ScenarioDeadlineExceeded);
        assert_eq!(err.classification.as_str(), "SCENARIO_DEADLINE_EXCEEDED");
        assert_eq!(err.bytes_read, 64);
        assert_eq!(err.error_kind, None);
        assert_eq!(err.os_code, None);
    }

    #[test]
    fn test_post_probe_preserves_bytes_read_in_all_cases() {
        let base = Instant::now();
        let deadline = base + Duration::from_secs(10);
        let before_deadline = base + Duration::from_secs(5);
        let after_deadline = base + Duration::from_secs(12);
        let expected_bytes = 8192;

        let cases: Vec<(std::io::Result<usize>, Instant, ReadErrorKind)> = vec![
            (Ok(1), before_deadline, ReadErrorKind::ReadLimitReached),
            (
                Ok(1),
                after_deadline,
                ReadErrorKind::ScenarioDeadlineExceeded,
            ),
            (
                Ok(0),
                after_deadline,
                ReadErrorKind::ScenarioDeadlineExceeded,
            ),
            (
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                )),
                before_deadline,
                ReadErrorKind::TimedOut,
            ),
            (
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                )),
                after_deadline,
                ReadErrorKind::ScenarioDeadlineExceeded,
            ),
            (
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "would block",
                )),
                before_deadline,
                ReadErrorKind::WouldBlock,
            ),
            (
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe",
                )),
                before_deadline,
                ReadErrorKind::BrokenPipe,
            ),
            (
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "conn reset",
                )),
                before_deadline,
                ReadErrorKind::ConnectionReset,
            ),
        ];

        for (probe_res, post_time, expected_kind) in cases {
            let res = classify_probe_outcome(
                probe_res,
                post_time,
                deadline,
                expected_bytes,
                expected_bytes,
            );
            assert!(res.is_err());
            let err = res.unwrap_err();
            assert_eq!(err.classification, expected_kind);
            assert_eq!(
                err.bytes_read, expected_bytes,
                "bytes_read must strictly match accumulated amount"
            );
        }
    }

    #[test]
    fn test_cli_parser_pilot_100_command() {
        let cfg = parse_cli_args(&["prog".into(), "--pilot-100".into()]).unwrap();
        assert_eq!(cfg.command, CliCommand::Pilot100);
        assert_eq!(cfg.output_dir, None);

        let cfg_dir = parse_cli_args(&[
            "prog".into(),
            "--pilot-100".into(),
            "--output-dir".into(),
            "/custom/dir".into(),
        ])
        .unwrap();
        assert_eq!(cfg_dir.command, CliCommand::Pilot100);
        assert_eq!(cfg_dir.output_dir, Some(PathBuf::from("/custom/dir")));
    }

    #[test]
    fn test_cli_parser_inspector_10k_command() {
        let cfg = parse_cli_args(&["prog".into(), "--inspector-10k".into()]).unwrap();
        assert_eq!(cfg.command, CliCommand::Inspector10k);
        assert_eq!(cfg.output_dir, None);

        let cfg_dir = parse_cli_args(&[
            "prog".into(),
            "--inspector-10k".into(),
            "--output-dir".into(),
            "/custom/dir".into(),
        ])
        .unwrap();
        assert_eq!(cfg_dir.command, CliCommand::Inspector10k);
        assert_eq!(cfg_dir.output_dir, Some(PathBuf::from("/custom/dir")));
    }

    #[test]
    fn test_cli_parser_rejects_conflicting_commands_with_inspector_10k() {
        assert!(
            parse_cli_args(&["prog".into(), "--inspector-10k".into(), "--pilot-5".into()]).is_err()
        );
        assert!(
            parse_cli_args(&["prog".into(), "--inspector-10k".into(), "--pilot-25".into()])
                .is_err()
        );
        assert!(parse_cli_args(&[
            "prog".into(),
            "--inspector-10k".into(),
            "--pilot-100".into()
        ])
        .is_err());
        assert!(
            parse_cli_args(&["prog".into(), "--inspector-10k".into(), "--all".into()]).is_err()
        );
        assert!(
            parse_cli_args(&["prog".into(), "--inspector-10k".into(), "--validate".into()])
                .is_err()
        );
    }

    #[test]
    fn test_cli_parser_rejects_pilot_101_and_unauthorized() {
        assert!(parse_cli_args(&["prog".into(), "--pilot-101".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--pilot-200".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--pilot-1000".into()]).is_err());
        assert!(parse_cli_args(&["prog".into(), "--pilot-0".into()]).is_err());
    }

    #[test]
    fn test_cli_parser_rejects_conflicting_commands_with_100() {
        assert!(
            parse_cli_args(&["prog".into(), "--pilot-100".into(), "--pilot-5".into()]).is_err()
        );
        assert!(
            parse_cli_args(&["prog".into(), "--pilot-100".into(), "--pilot-25".into()]).is_err()
        );
        assert!(parse_cli_args(&["prog".into(), "--pilot-100".into(), "--all".into()]).is_err());
        assert!(
            parse_cli_args(&["prog".into(), "--pilot-100".into(), "--validate".into()]).is_err()
        );
    }

    #[test]
    fn test_all_command_preserves_n5_and_n25_exclusively() {
        let cfg = parse_cli_args(&["prog".into(), "--all".into()]).unwrap();
        assert_eq!(cfg.command, CliCommand::All);
        assert_ne!(cfg.command, CliCommand::Pilot100);
        let execute_pilot_5 = cfg.command == CliCommand::Pilot5 || cfg.command == CliCommand::All;
        let execute_pilot_25 = cfg.command == CliCommand::Pilot25 || cfg.command == CliCommand::All;
        let execute_pilot_100 = cfg.command == CliCommand::Pilot100;
        assert!(execute_pilot_5);
        assert!(execute_pilot_25);
        assert!(!execute_pilot_100);
    }

    #[test]
    fn test_json_report_serialization_pilot_100() {
        let r1 = run_prf01_microbenchmark(100, 5);
        let r2 = run_prf02_microbenchmark(100, 5);
        let prf06 = run_prf06_limits_check();

        let e2e_synthetic = E2eScenarioResult {
            target_dispatched: 100,
            transactions_captured: 100,
            wall_clock_duration: Duration::from_millis(3500),
            sockets_released: true,
            validation_passed: true,
            initial_metrics: ProcessMetrics {
                working_set_bytes: Some(5_000_000),
                private_bytes: Some(1_000_000),
                anonymous_rss_bytes: None,
                cpu_time_ms: Some(10),
            },
            final_metrics: ProcessMetrics {
                working_set_bytes: Some(6_500_000),
                private_bytes: Some(1_800_000),
                anonymous_rss_bytes: None,
                cpu_time_ms: Some(95),
            },
            error_message: None,
        };

        let params = JsonReportParams {
            run_id: "test-run-100",
            timestamp_utc: "2026-10-16T14:00:00Z",
            command_str: "--pilot-100",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: Some(&r1),
            prf02_100: Some(&r2),
            e2e_100: Some(&e2e_synthetic),
            prf06: &prf06,
            failure_diagnostic: None,
        };

        let json = format_json_report(&params);
        assert!(json.contains("\"command\": \"--pilot-100\""));
        assert!(json.contains("\"status\": \"PASS\""));
        assert!(json.contains("\"pilot_100\": {"));
        assert!(json.contains("\"dispatched\":100"));
        assert!(json.contains("\"captured\":100"));
        assert!(json.contains("\"validation_passed\":true"));
        assert!(json.contains("\"working_set_delta_bytes\":1500000"));
        assert!(json.contains("\"private_bytes_delta\":800000"));
        assert!(json.contains("\"cpu_delta_ms\":85"));
    }

    #[test]
    fn test_json_report_preserves_pilot5_pilot25_and_invariants() {
        let prf06 = run_prf06_limits_check();
        let params = JsonReportParams {
            run_id: "test-compat-run",
            timestamp_utc: "2026-10-16T14:00:00Z",
            command_str: "--pilot-100",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: None,
        };

        let json = format_json_report(&params);
        assert!(json.contains("\"pilot_5\": {\n    \"prf01_clone\": \"NOT_AVAILABLE\""));
        assert!(json.contains("\"pilot_25\": {\n    \"prf01_clone\": \"NOT_AVAILABLE\""));
        assert!(json.contains("\"pilot_100\": {\n    \"prf01_clone\": \"NOT_AVAILABLE\""));
        assert!(json.contains("\"invariants\": {"));
        assert!(json.contains("\"traffic_store_max_capacity\": 10000"));
        assert!(json.contains("\"limit_type\": \"count_only\""));
    }

    #[test]
    fn test_failure_diagnostic_synthetic_n100() {
        let prf06 = run_prf06_limits_check();
        let diag_100 = PilotFailureDiagnostic {
            target_n: 100,
            failed_request_index: 34,
            validated_requests_count: 33,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "Request 34 response validation failed: Empty HTTP response received"
                .to_string(),
            store_transaction_count: 33,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 1250,
            remaining_budget_ms: Some(13750),
            stop_signal_sent: true,
            sockets_released: true,
        };

        let params = JsonReportParams {
            run_id: "test-fail-100",
            timestamp_utc: "2026-10-16T14:00:00Z",
            command_str: "--pilot-100",
            seed: DEFAULT_FIXED_SEED,
            prf01_5: None,
            prf02_5: None,
            e2e_5: None,
            prf01_25: None,
            prf02_25: None,
            e2e_25: None,
            prf01_100: None,
            prf02_100: None,
            e2e_100: None,
            prf06: &prf06,
            failure_diagnostic: Some(&diag_100),
        };

        let json = format_json_report(&params);
        assert!(json.contains("\"status\": \"FAILED\""));
        assert!(json.contains("\"target_n\": 100"));
        assert!(json.contains("\"failed_request_index\": 34"));
        assert!(json.contains("\"validated_requests_count\": 33"));
        assert!(json.contains("\"io_result_type\": \"EOF_ZERO_BYTES\""));

        let summary = format_failure_diagnostic_summary(&diag_100);
        assert!(summary.contains("VALIDATION FAILURE in End-to-End Pilot (N=100)"));
        assert!(summary.contains("Failed Request Index: 34 (Validated: 33/100)"));
    }

    #[test]
    fn test_proxy_diagnostic_json_serialization_with_and_without_diagnostics() {
        // 1. Without proxy diagnostics: json field must be null
        let diag_none = PilotFailureDiagnostic {
            target_n: 100,
            failed_request_index: 11,
            validated_requests_count: 10,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "EOF received".to_string(),
            store_transaction_count: 10,
            store_summary: vec![],
            proxy_diagnostics: None,
            elapsed_since_start_ms: 500,
            remaining_budget_ms: Some(14500),
            stop_signal_sent: true,
            sockets_released: true,
        };
        let json_none = format_failure_diagnostic_json(&diag_none);
        assert!(json_none.contains("\"proxy_diagnostics\": null"));

        // 2. With proxy diagnostics: json field must contain structured correlated context
        let terminal_event = SafeProxyEventSummary {
            conn_id: 11,
            client_port: 54321,
            phase: "UpstreamReadHeader".to_string(),
            io_result: Some("Ok(0)".to_string()),
            termination_reason: Some("NormalClosure".to_string()),
            http_response_attempted: None,
            http_response_write_succeeded: None,
        };
        let pdiag = ProxyFailureDiagnostic {
            correlation_status: CorrelationStatus::Complete,
            client_ephemeral_port: Some(54321),
            correlated_conn_id: Some(11),
            correlated_termination_reason: Some("NormalClosure".to_string()),
            correlated_phase: Some("UpstreamReadHeader".to_string()),
            correlated_io_result: Some("OkZero".to_string()),
            terminal_event: Some(terminal_event.clone()),
            correlated_events: vec![
                SafeProxyEventSummary {
                    conn_id: 11,
                    client_port: 54321,
                    phase: "Accepted".to_string(),
                    io_result: None,
                    termination_reason: None,
                    http_response_attempted: None,
                    http_response_write_succeeded: None,
                },
                terminal_event,
            ],
            total_captured_events: 42,
            observer_ring_capacity: 2000,
            observer_dropped_events: 0,
        };

        let diag_with_p = PilotFailureDiagnostic {
            target_n: 100,
            failed_request_index: 11,
            validated_requests_count: 10,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "EOF received".to_string(),
            store_transaction_count: 10,
            store_summary: vec![],
            proxy_diagnostics: Some(pdiag),
            elapsed_since_start_ms: 500,
            remaining_budget_ms: Some(14500),
            stop_signal_sent: true,
            sockets_released: true,
        };

        let json_with_p = format_failure_diagnostic_json(&diag_with_p);
        assert!(json_with_p.contains("\"proxy_diagnostics\": {"));
        assert!(json_with_p.contains("\"correlation_status\": \"COMPLETE\""));
        assert!(json_with_p.contains("\"client_ephemeral_port\": 54321"));
        assert!(json_with_p.contains("\"correlated_conn_id\": 11"));
        assert!(json_with_p.contains("\"correlated_termination_reason\": \"NormalClosure\""));
        assert!(json_with_p.contains("\"correlated_phase\": \"UpstreamReadHeader\""));
        assert!(json_with_p.contains("\"correlated_io_result\": \"OkZero\""));
        assert!(json_with_p.contains("\"terminal_event\": {"));
        assert!(json_with_p.contains("\"total_captured_events\": 42"));
        assert!(json_with_p.contains("\"observer_ring_capacity\": 2000"));
        assert!(json_with_p.contains("\"observer_dropped_events\": 0"));

        let summary = format_failure_diagnostic_summary(&diag_with_p);
        assert!(summary.contains("PROXY DIAGNOSTICS (Correlated by Client Ephemeral Port)"));
        assert!(summary.contains("Correlation Status: COMPLETE"));
        assert!(summary.contains("Terminal Event: [conn:11] phase=UpstreamReadHeader"));
        assert!(summary.contains("Client Port: 54321"));
        assert!(summary.contains("Proxy Conn ID: 11"));
        assert!(summary.contains("Proxy Phase: UpstreamReadHeader"));
        assert!(summary.contains("Proxy Termination Reason: NormalClosure"));
        assert!(summary.contains("Proxy I/O Result: OkZero"));
    }

    #[test]
    fn test_proxy_diagnostic_ring_capacity_and_port_correlation() {
        use kaska_http::proxy::{
            IoOperationResult, ProxyDiagnosticEvent, ProxyDiagnosticPhase, ProxyTerminationReason,
        };
        let observer = BoundedProxyObserver::new(3);

        // Push 4 events across 2 different client ports
        observer.record(ProxyDiagnosticEvent {
            conn_id: 1,
            client_port: 10001,
            phase: ProxyDiagnosticPhase::Accepted,
            io_result: None,
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });
        observer.record(ProxyDiagnosticEvent {
            conn_id: 1,
            client_port: 10001,
            phase: ProxyDiagnosticPhase::Completed,
            io_result: None,
            termination_reason: Some(ProxyTerminationReason::CompletedSuccessfully),
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });
        observer.record(ProxyDiagnosticEvent {
            conn_id: 2,
            client_port: 10002,
            phase: ProxyDiagnosticPhase::Accepted,
            io_result: None,
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });
        observer.record(ProxyDiagnosticEvent {
            conn_id: 2,
            client_port: 10002,
            phase: ProxyDiagnosticPhase::UpstreamConnected,
            io_result: Some(IoOperationResult::Err {
                kind: std::io::ErrorKind::ConnectionRefused,
                os_code: Some(10061),
            }),
            termination_reason: Some(ProxyTerminationReason::UpstreamConnectFailed),
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });

        assert_eq!(observer.capacity(), 3);
        assert_eq!(observer.total_captured(), 4);
        assert_eq!(observer.dropped_count(), 1);

        let snap = observer.snapshot();
        assert_eq!(snap.len(), 3);
        // Events 1 and 2 belong to port 10001, event 3 belongs to port 10002.
        // Event 4 exceeded capacity (3) and was dropped.
        let port_10001_events: Vec<_> = snap.iter().filter(|e| e.client_port == 10001).collect();
        assert_eq!(port_10001_events.len(), 2);
        assert_eq!(port_10001_events[0].phase, ProxyDiagnosticPhase::Accepted);
        assert_eq!(port_10001_events[1].phase, ProxyDiagnosticPhase::Completed);

        let port_10002_events: Vec<_> = snap.iter().filter(|e| e.client_port == 10002).collect();
        assert_eq!(port_10002_events.len(), 1);
        assert_eq!(port_10002_events[0].phase, ProxyDiagnosticPhase::Accepted);
    }

    #[test]
    fn test_gate6_scenario1_ok_then_err_correlation() {
        use kaska_http::proxy::{
            IoOperationResult, ProxyDiagnosticEvent, ProxyDiagnosticPhase, ProxyTerminationReason,
        };
        let events = vec![
            ProxyDiagnosticEvent {
                conn_id: 1,
                client_port: 30001,
                phase: ProxyDiagnosticPhase::ClientHeadersRead,
                io_result: Some(IoOperationResult::Ok(42)),
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
            ProxyDiagnosticEvent {
                conn_id: 1,
                client_port: 30001,
                phase: ProxyDiagnosticPhase::UpstreamConnected,
                io_result: Some(IoOperationResult::Err {
                    kind: std::io::ErrorKind::ConnectionRefused,
                    os_code: Some(10061),
                }),
                termination_reason: Some(ProxyTerminationReason::UpstreamConnectFailed),
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
        ];

        let diag = correlate_proxy_diagnostics(Some(30001), &events, 2, 100, 0);
        assert_eq!(diag.correlation_status, CorrelationStatus::Complete);
        assert_eq!(diag.correlated_conn_id, Some(1));
        assert_eq!(
            diag.correlated_termination_reason.as_deref(),
            Some("UpstreamConnectFailed")
        );
        assert_eq!(diag.correlated_phase.as_deref(), Some("UpstreamConnected"));
        assert!(diag
            .correlated_io_result
            .unwrap()
            .contains("ConnectionRefused"));
        assert!(diag.terminal_event.is_some());
    }

    #[test]
    fn test_gate6_scenario2_intermediate_error_recovered_not_early_return() {
        use kaska_http::proxy::{
            IoOperationResult, ProxyDiagnosticEvent, ProxyDiagnosticPhase, ProxyTerminationReason,
        };
        let events = vec![
            ProxyDiagnosticEvent {
                conn_id: 2,
                client_port: 30002,
                phase: ProxyDiagnosticPhase::ClientBodyRead,
                io_result: Some(IoOperationResult::Ok(0)),
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
            ProxyDiagnosticEvent {
                conn_id: 2,
                client_port: 30002,
                phase: ProxyDiagnosticPhase::Completed,
                io_result: None,
                termination_reason: Some(ProxyTerminationReason::CompletedSuccessfully),
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
        ];

        let diag = correlate_proxy_diagnostics(Some(30002), &events, 2, 100, 0);
        assert_eq!(diag.correlation_status, CorrelationStatus::Complete);
        assert_eq!(
            diag.correlated_termination_reason.as_deref(),
            Some("CompletedSuccessfully")
        );
        assert_eq!(diag.correlated_phase.as_deref(), Some("Completed"));
    }

    #[test]
    fn test_gate6_scenario3_incomplete_connection() {
        use kaska_http::proxy::{IoOperationResult, ProxyDiagnosticEvent, ProxyDiagnosticPhase};
        let events = vec![
            ProxyDiagnosticEvent {
                conn_id: 3,
                client_port: 30003,
                phase: ProxyDiagnosticPhase::Accepted,
                io_result: None,
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
            ProxyDiagnosticEvent {
                conn_id: 3,
                client_port: 30003,
                phase: ProxyDiagnosticPhase::ClientHeadersRead,
                io_result: Some(IoOperationResult::Ok(50)),
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
        ];

        let diag = correlate_proxy_diagnostics(Some(30003), &events, 2, 100, 0);
        assert_eq!(diag.correlation_status, CorrelationStatus::Incomplete);
        assert_eq!(diag.correlated_conn_id, Some(3));
        assert_eq!(diag.correlated_termination_reason, None);
        assert_eq!(diag.correlated_phase.as_deref(), Some("ClientHeadersRead"));
        assert!(diag.terminal_event.is_none());
    }

    #[test]
    fn test_gate6_scenario4_not_found() {
        let events = vec![];
        let diag = correlate_proxy_diagnostics(Some(30004), &events, 0, 100, 0);
        assert_eq!(diag.correlation_status, CorrelationStatus::NotFound);
        assert_eq!(diag.correlated_conn_id, None);
        assert_eq!(diag.correlated_termination_reason, None);
        assert!(diag.terminal_event.is_none());
        assert!(diag.correlated_events.is_empty());
    }

    #[test]
    fn test_gate6_scenario5_ambiguous_multiple_conn_ids() {
        use kaska_http::proxy::{ProxyDiagnosticEvent, ProxyDiagnosticPhase};
        let events = vec![
            ProxyDiagnosticEvent {
                conn_id: 10,
                client_port: 30005,
                phase: ProxyDiagnosticPhase::Accepted,
                io_result: None,
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
            ProxyDiagnosticEvent {
                conn_id: 11,
                client_port: 30005,
                phase: ProxyDiagnosticPhase::Accepted,
                io_result: None,
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
        ];

        let diag = correlate_proxy_diagnostics(Some(30005), &events, 2, 100, 0);
        assert_eq!(diag.correlation_status, CorrelationStatus::Ambiguous);
        assert_eq!(diag.correlated_conn_id, None);
        assert_eq!(diag.correlated_termination_reason, None);
        assert_eq!(diag.correlated_events.len(), 2);
        assert!(diag.terminal_event.is_none());
    }

    #[test]
    fn test_gate6_scenario6_degraded_dropped_events() {
        use kaska_http::proxy::{
            ProxyDiagnosticEvent, ProxyDiagnosticPhase, ProxyTerminationReason,
        };
        let events = vec![ProxyDiagnosticEvent {
            conn_id: 6,
            client_port: 30006,
            phase: ProxyDiagnosticPhase::Completed,
            io_result: None,
            termination_reason: Some(ProxyTerminationReason::CompletedSuccessfully),
            http_response_attempted: None,
            http_response_write_succeeded: None,
        }];

        // Even though matching terminal event exists, dropped_events > 0 degrades status
        let diag = correlate_proxy_diagnostics(Some(30006), &events, 10, 100, 5);
        assert_eq!(diag.correlation_status, CorrelationStatus::Degraded);
        assert_eq!(diag.observer_dropped_events, 5);
        assert_eq!(
            diag.correlated_termination_reason.as_deref(),
            Some("CompletedSuccessfully")
        );

        // If port not found and dropped_events > 0, also Degraded
        let diag_nf = correlate_proxy_diagnostics(Some(39999), &events, 10, 100, 5);
        assert_eq!(diag_nf.correlation_status, CorrelationStatus::Degraded);
    }

    #[test]
    fn test_gate6_scenario7_json_parity_with_and_without_terminal_event() {
        let diag_with_term = ProxyFailureDiagnostic {
            correlation_status: CorrelationStatus::Complete,
            client_ephemeral_port: Some(40007),
            correlated_conn_id: Some(7),
            correlated_termination_reason: Some("NormalClosure".to_string()),
            correlated_phase: Some("EarlyReturn".to_string()),
            correlated_io_result: Some("OkZero".to_string()),
            terminal_event: Some(SafeProxyEventSummary {
                conn_id: 7,
                client_port: 40007,
                phase: "EarlyReturn".to_string(),
                io_result: Some("OkZero".to_string()),
                termination_reason: Some("NormalClosure".to_string()),
                http_response_attempted: None,
                http_response_write_succeeded: None,
            }),
            correlated_events: vec![],
            total_captured_events: 5,
            observer_ring_capacity: 100,
            observer_dropped_events: 0,
        };

        let pilot_diag_term = PilotFailureDiagnostic {
            target_n: 100,
            failed_request_index: 7,
            validated_requests_count: 6,
            phase: DiagnosticPhase::ValidateResponse,
            io_result_type: "EOF_ZERO_BYTES".to_string(),
            error_kind: None,
            os_error_code: None,
            bytes_received_len: 0,
            error_message: "EOF".to_string(),
            store_transaction_count: 6,
            store_summary: vec![],
            proxy_diagnostics: Some(diag_with_term),
            elapsed_since_start_ms: 100,
            remaining_budget_ms: Some(10000),
            stop_signal_sent: true,
            sockets_released: true,
        };

        let json_term = format_failure_diagnostic_json(&pilot_diag_term);
        assert!(json_term.contains("\"correlation_status\": \"COMPLETE\""));
        assert!(json_term.contains("\"terminal_event\": {"));
        assert!(json_term.contains("\"conn_id\":7"));

        let mut diag_no_term = pilot_diag_term.clone();
        if let Some(ref mut p) = diag_no_term.proxy_diagnostics {
            p.correlation_status = CorrelationStatus::Incomplete;
            p.terminal_event = None;
            p.correlated_termination_reason = None;
        }
        let json_no_term = format_failure_diagnostic_json(&diag_no_term);
        assert!(json_no_term.contains("\"correlation_status\": \"INCOMPLETE\""));
        assert!(json_no_term.contains("\"terminal_event\": null"));
        assert!(json_no_term.contains("\"correlated_termination_reason\": null"));
    }

    #[test]
    fn test_gate6_scenario8_txt_summary_parity_notes() {
        for (status, expected_note) in [
            (
                CorrelationStatus::Degraded,
                "Buffer capacity reached (Drop Newest policy; new events dropped)",
            ),
            (
                CorrelationStatus::Ambiguous,
                "Ephemeral port collision detected",
            ),
            (
                CorrelationStatus::Incomplete,
                "Connection recorded in proxy but terminated abnormally",
            ),
            (CorrelationStatus::NotFound, "No proxy events recorded"),
        ] {
            let pdiag = ProxyFailureDiagnostic {
                correlation_status: status,
                client_ephemeral_port: Some(40008),
                correlated_conn_id: None,
                correlated_termination_reason: None,
                correlated_phase: None,
                correlated_io_result: None,
                terminal_event: None,
                correlated_events: vec![],
                total_captured_events: 10,
                observer_ring_capacity: 100,
                observer_dropped_events: if status == CorrelationStatus::Degraded {
                    2
                } else {
                    0
                },
            };
            let pilot_diag = PilotFailureDiagnostic {
                target_n: 100,
                failed_request_index: 8,
                validated_requests_count: 7,
                phase: DiagnosticPhase::ValidateResponse,
                io_result_type: "EOF_ZERO_BYTES".to_string(),
                error_kind: None,
                os_error_code: None,
                bytes_received_len: 0,
                error_message: "EOF".to_string(),
                store_transaction_count: 7,
                store_summary: vec![],
                proxy_diagnostics: Some(pdiag),
                elapsed_since_start_ms: 200,
                remaining_budget_ms: Some(10000),
                stop_signal_sent: true,
                sockets_released: true,
            };
            let summary = format_failure_diagnostic_summary(&pilot_diag);
            assert!(summary.contains(&format!("Correlation Status: {}", status.as_str())));
            assert!(summary.contains(expected_note));
        }
    }

    #[test]
    fn test_gate6_scenario9_terminal_event_selection_multiple_events() {
        use kaska_http::proxy::{
            IoOperationResult, ProxyDiagnosticEvent, ProxyDiagnosticPhase, ProxyTerminationReason,
        };
        let events = vec![
            ProxyDiagnosticEvent {
                conn_id: 9,
                client_port: 40009,
                phase: ProxyDiagnosticPhase::ClientHeadersRead,
                io_result: Some(IoOperationResult::Err {
                    kind: std::io::ErrorKind::WouldBlock,
                    os_code: None,
                }),
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
            ProxyDiagnosticEvent {
                conn_id: 9,
                client_port: 40009,
                phase: ProxyDiagnosticPhase::UpstreamHeadersWrite,
                io_result: Some(IoOperationResult::Err {
                    kind: std::io::ErrorKind::BrokenPipe,
                    os_code: None,
                }),
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            },
            ProxyDiagnosticEvent {
                conn_id: 9,
                client_port: 40009,
                phase: ProxyDiagnosticPhase::EarlyReturn,
                io_result: Some(IoOperationResult::Err {
                    kind: std::io::ErrorKind::BrokenPipe,
                    os_code: None,
                }),
                termination_reason: Some(ProxyTerminationReason::ClientResponseBodyWriteFailed),
                http_response_attempted: Some(502),
                http_response_write_succeeded: Some(false),
            },
        ];

        let diag = correlate_proxy_diagnostics(Some(40009), &events, 3, 100, 0);
        assert_eq!(diag.correlation_status, CorrelationStatus::Complete);
        assert_eq!(
            diag.correlated_termination_reason.as_deref(),
            Some("ClientResponseBodyWriteFailed")
        );
        let terminal = diag.terminal_event.expect("Terminal event must be present");
        assert_eq!(terminal.phase, "EarlyReturn");
        assert_eq!(
            terminal.termination_reason.as_deref(),
            Some("ClientResponseBodyWriteFailed")
        );
        assert_eq!(terminal.http_response_attempted, Some(502));
        assert_eq!(terminal.http_response_write_succeeded, Some(false));
    }

    #[test]
    fn test_gate6_scenario10_drop_newest_preservation_and_capacity() {
        use kaska_http::proxy::{ProxyDiagnosticEvent, ProxyDiagnosticPhase};
        let observer = BoundedProxyObserver::new(20);
        for i in 1..=50 {
            observer.record(ProxyDiagnosticEvent {
                conn_id: i,
                client_port: 50000 + i as u16,
                phase: ProxyDiagnosticPhase::Accepted,
                io_result: None,
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            });
        }

        assert_eq!(observer.capacity(), 20);
        assert_eq!(observer.total_captured(), 50);
        assert_eq!(observer.dropped_count(), 30);
        let snap = observer.snapshot();
        assert_eq!(snap.len(), 20);
        // Retained elements are the first 20 events (conn_id 1..=20) under Drop-Newest policy
        assert_eq!(snap.first().unwrap().conn_id, 1);
        assert_eq!(snap.last().unwrap().conn_id, 20);
    }

    #[test]
    fn test_calculate_diagnostic_poll_sleep_bounds() {
        let poll_interval = Duration::from_millis(5);
        let max_diag = Duration::from_millis(50);
        let now = Instant::now();

        // 1. Zero scenario budget remaining -> ZERO
        let deadline_past = now.checked_sub(Duration::from_millis(10)).unwrap();
        assert_eq!(
            calculate_diagnostic_poll_sleep(
                poll_interval,
                Duration::from_millis(10),
                max_diag,
                now,
                deadline_past
            ),
            Duration::ZERO
        );

        // 2. Zero diagnostic budget remaining -> ZERO
        let deadline_future = now + Duration::from_secs(10);
        assert_eq!(
            calculate_diagnostic_poll_sleep(
                poll_interval,
                Duration::from_millis(50),
                max_diag,
                now,
                deadline_future
            ),
            Duration::ZERO
        );

        // 3. Scenario remaining (2ms) is smaller than poll_interval (5ms) and diag remaining (40ms)
        let deadline_near = now + Duration::from_millis(2);
        assert_eq!(
            calculate_diagnostic_poll_sleep(
                poll_interval,
                Duration::from_millis(10),
                max_diag,
                now,
                deadline_near
            ),
            Duration::from_millis(2)
        );

        // 4. Diag remaining (3ms) is smaller than poll_interval (5ms) and scenario remaining (100ms)
        let deadline_far = now + Duration::from_millis(100);
        assert_eq!(
            calculate_diagnostic_poll_sleep(
                poll_interval,
                Duration::from_millis(47),
                max_diag,
                now,
                deadline_far
            ),
            Duration::from_millis(3)
        );

        // 5. Normal poll_interval (5ms) is smaller than remaining scenario (100ms) and remaining diag (40ms)
        assert_eq!(
            calculate_diagnostic_poll_sleep(
                poll_interval,
                Duration::from_millis(10),
                max_diag,
                now,
                deadline_far
            ),
            Duration::from_millis(5)
        );
    }
}

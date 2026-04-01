use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::RwLock;

const NTP_SERVERS: &[&str] = &[
    "ntp.aliyun.com:123",
    "ntp.tuna.tsinghua.edu.cn:123",
    "ntp1.tencent.com:123",
    "pool.ntp.org:123",
    "time.google.com:123",
    "time.cloudflare.com:123",
    "time.apple.com:123",
    "time.windows.com:123",
    "time.nist.gov:123",
    "ntp.ubuntu.com:123",
    "time.facebook.com:123",
];

const MAX_ACCEPTABLE_OFFSET_MS: i64 = 2000;
const TRUSTED_POLL_MS: u64 = 30_000;
const UNTRUSTED_POLL_MS: u64 = 5_000;
const DEFAULT_POLL_MS: u64 = 10_000;
const MIN_NTP_RESPONSES: usize = 3;

struct NtpState {
    offset_ms: AtomicI64,
    trusted: AtomicBool,
    poll_interval_ms: AtomicU64,
    last_sync: RwLock<Option<Instant>>,
    successful_syncs: AtomicU64,
    failed_syncs: AtomicU64,
    first_sync_done: AtomicBool,
    last_logged_trusted: AtomicBool,
}

static NTP_STATE: Lazy<NtpState> = Lazy::new(|| NtpState {
    offset_ms: AtomicI64::new(0),
    trusted: AtomicBool::new(false),
    poll_interval_ms: AtomicU64::new(DEFAULT_POLL_MS),
    last_sync: RwLock::new(None),
    successful_syncs: AtomicU64::new(0),
    failed_syncs: AtomicU64::new(0),
    first_sync_done: AtomicBool::new(false),
    last_logged_trusted: AtomicBool::new(false),
});

fn query_ntp_server(server: &str, timeout: Duration) -> Option<i64> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let result = sntpc::simple_get_time(server, &socket);
    match result {
        Ok(time) => {
            let offset_secs = time.sec() as i64 - chrono::Utc::now().timestamp();
            let offset_ms = offset_secs * 1000
                + (time.sec_fraction() as f64 / u32::MAX as f64 * 1000.0) as i64
                - chrono::Utc::now().timestamp_subsec_millis() as i64;
            Some(offset_ms)
        }
        Err(_) => None,
    }
}

fn median(values: &mut [i64]) -> i64 {
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2
    } else {
        values[mid]
    }
}

pub fn sync_ntp() {
    let mut offsets = Vec::new();

    for server in NTP_SERVERS {
        if let Some(offset) = query_ntp_server(server, Duration::from_secs(3)) {
            offsets.push(offset);
        }
    }

    if offsets.len() < MIN_NTP_RESPONSES {
        NTP_STATE.failed_syncs.fetch_add(1, Ordering::Relaxed);
        NTP_STATE.trusted.store(false, Ordering::Release);
        NTP_STATE
            .poll_interval_ms
            .store(UNTRUSTED_POLL_MS, Ordering::Release);
        tracing::warn!(
            "NTP sync: only {}/{} servers responded, marking untrusted",
            offsets.len(),
            NTP_SERVERS.len()
        );
        return;
    }

    let med_offset = median(&mut offsets);

    let filtered: Vec<i64> = offsets
        .iter()
        .filter(|&&o| (o - med_offset).unsigned_abs() < MAX_ACCEPTABLE_OFFSET_MS as u64)
        .copied()
        .collect();

    if filtered.len() < MIN_NTP_RESPONSES {
        NTP_STATE.failed_syncs.fetch_add(1, Ordering::Relaxed);
        NTP_STATE.trusted.store(false, Ordering::Release);
        NTP_STATE
            .poll_interval_ms
            .store(UNTRUSTED_POLL_MS, Ordering::Release);
        tracing::warn!("NTP sync: too many outlier responses, marking untrusted");
        return;
    }

    let avg_offset: i64 = filtered.iter().sum::<i64>() / filtered.len() as i64;

    NTP_STATE.offset_ms.store(avg_offset, Ordering::Release);
    NTP_STATE.successful_syncs.fetch_add(1, Ordering::Relaxed);
    *NTP_STATE.last_sync.write() = Some(Instant::now());

    let trusted = avg_offset.unsigned_abs() < MAX_ACCEPTABLE_OFFSET_MS as u64;
    NTP_STATE.trusted.store(trusted, Ordering::Release);

    let poll = if trusted {
        TRUSTED_POLL_MS
    } else {
        UNTRUSTED_POLL_MS
    };
    NTP_STATE.poll_interval_ms.store(poll, Ordering::Release);

    let is_first = !NTP_STATE.first_sync_done.swap(true, Ordering::Relaxed);
    let prev_trusted = NTP_STATE
        .last_logged_trusted
        .swap(trusted, Ordering::Relaxed);
    let status_changed = trusted != prev_trusted;

    if is_first || status_changed || !trusted {
        tracing::info!(
            "NTP sync: offset={}ms, trusted={}, servers={}/{}, poll={}s",
            avg_offset,
            trusted,
            filtered.len(),
            NTP_SERVERS.len(),
            poll / 1000,
        );
    } else {
        tracing::debug!(
            "NTP sync: offset={}ms, trusted={}, servers={}/{}, poll={}s",
            avg_offset,
            trusted,
            filtered.len(),
            NTP_SERVERS.len(),
            poll / 1000,
        );
    }
}

pub fn ntp_adjusted_timestamp_ms() -> u64 {
    let local_ms = chrono::Utc::now().timestamp_millis();
    let offset = NTP_STATE.offset_ms.load(Ordering::Acquire);
    (local_ms + offset) as u64
}

pub fn ntp_adjusted_timestamp_secs() -> u64 {
    ntp_adjusted_timestamp_ms() / 1000
}

pub fn is_clock_trusted() -> bool {
    NTP_STATE.trusted.load(Ordering::Acquire)
}

pub fn ntp_poll_interval() -> Duration {
    Duration::from_millis(NTP_STATE.poll_interval_ms.load(Ordering::Acquire))
}

pub fn ntp_offset_ms() -> i64 {
    NTP_STATE.offset_ms.load(Ordering::Acquire)
}

pub fn needs_resync() -> bool {
    let guard = NTP_STATE.last_sync.read();
    match *guard {
        None => true,
        Some(last) => last.elapsed() >= ntp_poll_interval(),
    }
}

pub fn start_ntp_sync_task() {
    sync_ntp();
    std::thread::spawn(|| loop {
        let poll = ntp_poll_interval();
        std::thread::sleep(poll);
        sync_ntp();
    });
}

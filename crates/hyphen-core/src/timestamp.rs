//! NTP-adjusted wall clock.
//!
//! Timestamps feed block-time validation, so the node needs a clock maintained
//! by several independent servers that fails closed: when fewer than
//! `MIN_NTP_RESPONSES` servers answer, or the surviving offsets disagree beyond
//! `MAX_ACCEPTABLE_OFFSET_MS`, the clock is marked untrusted and the poll
//! interval drops to a retry interval.
//!
//! The SNTP client is implemented here on purpose. It is one 48-byte request
//! and one 48-byte response over UDP; pulling a dependency tree into the
//! consensus crate for that transaction is not worth the supply-chain surface.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

const NTP_PACKET_LEN: usize = 48;
const NTP_VERSION: u8 = 4;
const NTP_MODE_CLIENT: u8 = 3;
const NTP_MODE_SERVER: u8 = 4;
/// Seconds between the NTP era (1900) and the Unix epoch (1970).
const NTP_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;
const FRACTION_SCALE: i64 = 1 << 32;

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

static NTP_STATE: LazyLock<NtpState> = LazyLock::new(|| NtpState {
    offset_ms: AtomicI64::new(0),
    trusted: AtomicBool::new(false),
    poll_interval_ms: AtomicU64::new(DEFAULT_POLL_MS),
    last_sync: RwLock::new(None),
    successful_syncs: AtomicU64::new(0),
    failed_syncs: AtomicU64::new(0),
    first_sync_done: AtomicBool::new(false),
    last_logged_trusted: AtomicBool::new(false),
});

fn local_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

fn ntp_timestamp(unix_ms: i64) -> [u8; 8] {
    let unix_ms = unix_ms.max(0);
    let seconds = (unix_ms / 1000) as u64 + NTP_EPOCH_OFFSET_SECS;
    let fraction = (unix_ms.rem_euclid(1000) << 32) / 1000;
    let mut encoded = [0u8; 8];
    encoded[..4].copy_from_slice(&(seconds as u32).to_be_bytes());
    encoded[4..].copy_from_slice(&(fraction as u32).to_be_bytes());
    encoded
}

fn read_ntp_ms(raw: &[u8]) -> Option<i64> {
    let seconds = u32::from_be_bytes(raw.get(..4)?.try_into().ok()?) as i64;
    let fraction = u32::from_be_bytes(raw.get(4..8)?.try_into().ok()?) as i64;
    if seconds == 0 {
        return None;
    }
    Some((seconds - NTP_EPOCH_OFFSET_SECS as i64) * 1000 + fraction * 1000 / FRACTION_SCALE)
}

fn build_request() -> [u8; NTP_PACKET_LEN] {
    let mut request = [0u8; NTP_PACKET_LEN];
    request[0] = (NTP_VERSION << 3) | NTP_MODE_CLIENT;
    request[40..].copy_from_slice(&ntp_timestamp(local_unix_ms()));
    request
}

fn query_ntp_server(server: &str, timeout: Duration) -> Option<i64> {
    let address = server.to_socket_addrs().ok()?.find(SocketAddr::is_ipv4)?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let request = build_request();
    let sent_ms = local_unix_ms();
    socket.send_to(&request, address).ok()?;

    let mut response = [0u8; NTP_PACKET_LEN];
    let (length, _) = socket.recv_from(&mut response).ok()?;
    let received_ms = local_unix_ms();
    if length < NTP_PACKET_LEN {
        return None;
    }
    parse_offset_ms(&request, &response, sent_ms, received_ms)
}

/// Validates a server reply and computes `((T2 - T1) + (T3 - T4)) / 2`.
fn parse_offset_ms(
    request: &[u8; NTP_PACKET_LEN],
    response: &[u8; NTP_PACKET_LEN],
    sent_ms: i64,
    received_ms: i64,
) -> Option<i64> {
    let leap_indicator = response[0] >> 6;
    let mode = response[0] & 0x07;
    let stratum = response[1];
    if leap_indicator == 3 || mode != NTP_MODE_SERVER || stratum == 0 || stratum > 15 {
        return None;
    }
    // The originate field must echo the transmit timestamp we sent: that binds
    // the reply to this request and rejects replayed or unsolicited packets.
    if response[24..32] != request[40..48] {
        return None;
    }

    let server_receive_ms = read_ntp_ms(&response[32..40])?;
    let server_transmit_ms = read_ntp_ms(&response[40..48])?;
    let offset = ((server_receive_ms - sent_ms) + (server_transmit_ms - received_ms)) / 2;
    Some(offset)
}

fn query_servers() -> Vec<i64> {
    let handles: Vec<_> = NTP_SERVERS
        .iter()
        .copied()
        .map(|server| std::thread::spawn(move || query_ntp_server(server, QUERY_TIMEOUT)))
        .collect();
    handles
        .into_iter()
        .filter_map(|handle| handle.join().ok().flatten())
        .collect()
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

fn mark_untrusted(reason: &str, responded: usize) {
    NTP_STATE.failed_syncs.fetch_add(1, Ordering::Relaxed);
    NTP_STATE.trusted.store(false, Ordering::Release);
    NTP_STATE
        .poll_interval_ms
        .store(UNTRUSTED_POLL_MS, Ordering::Release);
    *NTP_STATE.last_sync.write() = Some(Instant::now());
    tracing::warn!(
        "NTP sync: {reason} ({responded}/{} servers responded), clock untrusted",
        NTP_SERVERS.len()
    );
}

pub fn sync_ntp() {
    let mut offsets = query_servers();

    if offsets.len() < MIN_NTP_RESPONSES {
        mark_untrusted("too few agreeing servers", offsets.len());
        return;
    }

    let median_offset = median(&mut offsets);
    let filtered: Vec<i64> = offsets
        .into_iter()
        .filter(|offset| (offset - median_offset).unsigned_abs() < MAX_ACCEPTABLE_OFFSET_MS as u64)
        .collect();

    if filtered.len() < MIN_NTP_RESPONSES {
        mark_untrusted("too many outlier responses", filtered.len());
        return;
    }

    let average_offset: i64 = filtered.iter().sum::<i64>() / filtered.len() as i64;

    NTP_STATE.offset_ms.store(average_offset, Ordering::Release);
    NTP_STATE.successful_syncs.fetch_add(1, Ordering::Relaxed);
    *NTP_STATE.last_sync.write() = Some(Instant::now());

    let trusted = average_offset.unsigned_abs() < MAX_ACCEPTABLE_OFFSET_MS as u64;
    NTP_STATE.trusted.store(trusted, Ordering::Release);
    let poll = if trusted {
        TRUSTED_POLL_MS
    } else {
        UNTRUSTED_POLL_MS
    };
    NTP_STATE.poll_interval_ms.store(poll, Ordering::Release);

    let is_first = !NTP_STATE.first_sync_done.swap(true, Ordering::Relaxed);
    let was_trusted = NTP_STATE
        .last_logged_trusted
        .swap(trusted, Ordering::Relaxed);
    let status_changed = trusted != was_trusted;

    if is_first || status_changed || !trusted {
        tracing::info!(
            "NTP sync: offset={}ms, trusted={}, servers={}/{}, poll={}s",
            average_offset,
            trusted,
            filtered.len(),
            NTP_SERVERS.len(),
            poll / 1000,
        );
    } else {
        tracing::debug!(
            "NTP sync: offset={}ms, trusted={}, servers={}/{}, poll={}s",
            average_offset,
            trusted,
            filtered.len(),
            NTP_SERVERS.len(),
            poll / 1000,
        );
    }
}

pub fn ntp_adjusted_timestamp_ms() -> u64 {
    let local_ms = local_unix_ms();
    let offset = NTP_STATE.offset_ms.load(Ordering::Acquire);
    local_ms
        .checked_add(offset)
        .and_then(|adjusted| u64::try_from(adjusted).ok())
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encodes_version_mode_and_transmit_time() {
        let request = build_request();
        assert_eq!(request.len(), NTP_PACKET_LEN);
        assert_eq!(request[0] >> 6, 0, "no leap warning is set");
        assert_eq!((request[0] >> 3) & 0x07, NTP_VERSION);
        assert_eq!(request[0] & 0x07, NTP_MODE_CLIENT);
        assert!(read_ntp_ms(&request[40..48]).is_some());
    }

    #[test]
    fn timestamps_round_trip_through_the_ntp_epoch() {
        let now_ms = 1_800_000_000_123i64;
        let encoded = ntp_timestamp(now_ms);
        let decoded = read_ntp_ms(&encoded).expect("encoded timestamp is readable");
        // The 32-bit fraction resolves to roughly 233 picoseconds, so only the
        // millisecond is expected to survive the round trip.
        assert!((decoded - now_ms).abs() <= 1);
    }

    #[test]
    fn replies_must_echo_the_request_and_be_server_frames() {
        let request = build_request();
        let mut response = request;
        response[0] = (NTP_VERSION << 3) | NTP_MODE_SERVER;
        response[1] = 2;
        // A server echoes the client transmit timestamp in the originate field.
        response[24..32].copy_from_slice(&request[40..48]);
        response[32..40].copy_from_slice(&ntp_timestamp(1_800_000_000_000));
        response[40..48].copy_from_slice(&ntp_timestamp(1_800_000_000_010));

        let offset = parse_offset_ms(&request, &response, 1_800_000_000_000, 1_800_000_000_100)
            .expect("valid reply");
        assert_eq!(offset, (1_800_000_000_010 - 1_800_000_000_100) / 2);

        let mut replayed = response;
        replayed[24..32].copy_from_slice(&[0u8; 8]);
        assert_eq!(
            parse_offset_ms(&request, &replayed, 0, 0),
            None,
            "originate mismatch is rejected"
        );

        let mut wrong_mode = response;
        wrong_mode[0] = (NTP_VERSION << 3) | NTP_MODE_CLIENT;
        assert_eq!(parse_offset_ms(&request, &wrong_mode, 0, 0), None);

        let mut bad_stratum = response;
        bad_stratum[1] = 0;
        assert_eq!(parse_offset_ms(&request, &bad_stratum, 0, 0), None);
    }
}

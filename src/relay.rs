//! relay — patterniha-style local TCP relay. [PARTIAL]
//!
//! A TLS client (v2rayN, the OS, or any local SOCKS/HTTP front) connects to
//! `127.0.0.1:<relay_listen_port>`; each accepted connection is relayed to
//! the configured destination `<connect_ip>:<connect_port>`. An optional
//! operator-supplied `rotate_ips` list selects the next approved IP per
//! connection; the client can never provide a destination. Before the client's
//! real ClientHello is forwarded, the Windows capture pipeline
//! injects a fake ClientHello carrying a benign SNI with a deliberately
//! wrong TCP sequence number (`wrong_seq`), so a stateless DPI whitelists
//! the flow on the benign name while the real server drops the fake.
//!
//! Hardening properties of this build:
//!
//! * **Binds 127.0.0.1 only.** Never `0.0.0.0`; non-loopback accepted peers
//!   (which cannot happen on a loopback listener, but are checked anyway)
//!   are dropped immediately.
//! * **Operator-fixed destination set.** There is no way for a client to ask
//!   the relay to connect somewhere else — rotation is limited to the
//!   validated operator list and can never become an open proxy.
//! * **Fail-closed injection.** After the outbound 3WHS the relay waits up
//!   to [`FAKE_ACK_WAIT`] for the pipeline to confirm that the server
//!   ACKed/dupacked the fake. If `require_inject` is true and that
//!   confirmation never arrives, the relay closes the connection **without
//!   copying the real ClientHello**, so the true SNI never hits the wire.
//! * **Coexistence with patterniha.** The listen socket and the singleton
//!   lock (`singleton.rs`) make running both at once fail loudly with a
//!   message that names patterniha.
//! * **Stealth logging.** Destination endpoints are logged through
//!   [`crate::stealth::redact_endpoint`], never as raw IPs.
//!
//! There is **no Xray/v2ray/sing-box core** here: this is a plain TCP relay
//! plus an injected fake ClientHello.

use crate::error::DpiGuardError;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// How long the relay waits for the fake-SNI injection to be confirmed
/// before acting (drop if `require_inject`, otherwise proceed). 3 s is our
/// own conservative bound for the server's ACK of the fake (same order as
/// the reference Python relay's ~2–3 s wait — stated as similarity, not as
/// a verified quote of its source).
pub const FAKE_ACK_WAIT: Duration = Duration::from_secs(3);

/// TCP keepalive probe interval for relay upstream sockets. Without it, an
/// upstream connection black-holed by a link flap sits in the copy loop
/// forever (no FIN, no RST) holding the client's socket open.
const UPSTREAM_KEEPALIVE: Duration = Duration::from_secs(30);

/// Upper bound on the outbound TCP connect to the real destination.
///
/// This exists for flapping networks: a connect to an unreachable peer
/// otherwise blocks for the OS's own TCP timeout, holding the client's
/// accepted socket (and v2rayN with it) far longer than the operator
/// expects. Failing fast hands control back to the client, whose own
/// retry logic is better placed to decide when to try again.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What the relay must connect to, plus the fail-closed switch.
#[derive(Clone, Debug)]
pub struct RelayTarget {
    /// Primary destination used when `rotate_ips` is empty.
    pub connect_ip: IpAddr,
    /// Optional operator-supplied destination set. Each accepted relay
    /// connection selects the next address in this list; the client still
    /// controls neither the address nor the port, so this is fail-closed
    /// failover/rotation rather than an open-proxy feature.
    pub rotate_ips: Vec<IpAddr>,
    pub connect_port: u16,
    pub fake_sni: String,
    /// If true (the default), the relay drops a connection whose fake
    /// ClientHello was not ACK-confirmed within [`FAKE_ACK_WAIT`].
    pub require_inject: bool,
    /// Idle deadline per relayed connection: if no byte flows in either
    /// direction for this long, both sides are closed. This is what reaps
    /// black-holed upstream sockets after a link flap. Set from
    /// `idle_timeout_secs` by the caller.
    pub idle_timeout: Duration,
}

fn selected_destination_ip(primary: IpAddr, rotate_ips: &[IpAddr], index: usize) -> IpAddr {
    if rotate_ips.is_empty() {
        return primary;
    }
    if index == 0 {
        return rotate_ips[0];
    }
    // Reuse the same bounded/cyclic policy as the transparent connection
    // module. The previous slot is the blocked value, so the helper returns
    // the next operator-approved address without constructing a new list.
    let previous = rotate_ips[(index - 1) % rotate_ips.len()];
    crate::connection::rotate_ip(rotate_ips, previous).unwrap_or(rotate_ips[0])
}

/// Behaviour knobs for relay-mode evasion, carried by the pipeline (which
/// must not know the destination IP).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMode {
    pub fake_sni: String,
    pub connect_port: u16,
    pub mutate_real_sni: bool,
    pub emit_decoy: bool,
    /// Mirror of [`RelayTarget::require_inject`] so the pipeline knows
    /// whether a failed injection must suppress the real ClientHello.
    pub require_inject: bool,
}

/// The real 4-tuple of an established relay connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowInfo {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

/// One-shot gate between the relay I/O task and the capture pipeline. The
/// pipeline calls [`InjectGate::succeed`] when it sees the server dup-ACK
/// the fake ClientHello, or [`InjectGate::fail`] on any handshake error.
/// The relay task calls [`InjectGate::wait`] (with a timeout) and then
/// reads [`InjectGate::was_ok`]. Unlike a bare `Notify`, this carries a
/// success/failure bit so a timeout is distinguishable from a failure.
#[derive(Debug)]
pub struct InjectGate {
    ok: AtomicBool,
    set: AtomicBool,
    notify: tokio::sync::Notify,
}

impl InjectGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ok: AtomicBool::new(false),
            set: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Injection confirmed — the fake was ACKed (or otherwise observed as
    /// having reached the DPI). Safe to relay the real ClientHello.
    pub fn succeed(self: &Arc<Self>) {
        self.ok.store(true, Ordering::SeqCst);
        self.set.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Injection failed (handshake parse error, RST, wrong sequence, ...).
    pub fn fail(self: &Arc<Self>) {
        self.ok.store(false, Ordering::SeqCst);
        self.set.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn was_ok(&self) -> bool {
        self.ok.load(Ordering::SeqCst)
    }

    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::SeqCst)
    }

    /// Wait until the pipeline marks the gate (success or failure), or
    /// `timeout` elapses. Returns true if the gate was set to success.
    pub async fn wait(self: &Arc<Self>, timeout: Duration) -> bool {
        if self.is_set() {
            return self.was_ok();
        }
        tokio::select! {
            _ = self.notify.notified() => self.was_ok(),
            _ = tokio::time::sleep(timeout) => self.was_ok(),
        }
    }
}

/// Source address the OS would use to reach `dst`, discovered with the UDP
/// connect trick (no packets are actually sent).
pub fn local_ip_for(dst: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if dst.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        "::0".parse().ok()?
    };
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect((dst, 1)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Callbacks the relay uses to tell the pipeline about a connection's
/// lifetime.
///
/// `register` is called once per connection *before* the outbound handshake
/// with the real 4-tuple and returns the gate the pipeline uses to report
/// injection success/failure. `unregister` is called exactly once when that
/// connection ends, on **every** exit path — including the fail-closed drop
/// — so the pipeline's bounded flow table does not fill up with dead
/// entries (see `Pipeline::unregister_relay_flow`).
pub struct FlowHooks {
    register: Box<dyn Fn(FlowInfo) -> Arc<InjectGate> + Send + Sync>,
    unregister: Box<dyn Fn(FlowInfo) + Send + Sync>,
}

impl FlowHooks {
    pub fn new<R, U>(register: R, unregister: U) -> Arc<Self>
    where
        R: Fn(FlowInfo) -> Arc<InjectGate> + Send + Sync + 'static,
        U: Fn(FlowInfo) + Send + Sync + 'static,
    {
        Arc::new(Self {
            register: Box::new(register),
            unregister: Box::new(unregister),
        })
    }
}

/// Removes a flow from the pipeline when dropped, so every early return in
/// `handle_conn` (and any future panic) releases the slot.
struct FlowSlot {
    flow: FlowInfo,
    hooks: Arc<FlowHooks>,
}

impl Drop for FlowSlot {
    fn drop(&mut self) {
        (self.hooks.unregister)(self.flow);
    }
}

/// Run the relay accept loop on a dedicated thread.
pub fn run(
    target: RelayTarget,
    listen_port: u16,
    running: Arc<AtomicBool>,
    hooks: Arc<FlowHooks>,
) -> Result<std::thread::JoinHandle<()>, DpiGuardError> {
    std::thread::Builder::new()
        .name("dpi_guard-relay".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("relay tokio runtime failed: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                relay_loop(target, listen_port, running, hooks).await;
            });
        })
        .map_err(|e| DpiGuardError::Io(std::io::Error::new(e.kind(), format!("relay spawn: {e}"))))
}

async fn relay_loop(
    target: RelayTarget,
    listen_port: u16,
    running: Arc<AtomicBool>,
    hooks: Arc<FlowHooks>,
) {
    let addr: SocketAddr = ([127, 0, 0, 1], listen_port).into();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            // Most common real-world cause: patterniha's Python relay is
            // already holding 127.0.0.1:40443. Name it so the operator
            // knows what to stop.
            log::error!(
                "relay bind {addr} failed: {e}. Is another instance of dpi_guard or the \
                 patterniha Python relay already listening on this port?"
            );
            return;
        }
    };
    log::info!(
        "relay listening on {addr} -> {} (fake SNI {:?}, require_inject={}, rotate_ips={})",
        crate::stealth::redact_socket_addr(&SocketAddr::new(
            target.connect_ip,
            target.connect_port
        )),
        target.fake_sni,
        target.require_inject,
        target.rotate_ips.len()
    );
    let mut rotation_index = 0usize;

    while running.load(Ordering::SeqCst) {
        let accept = tokio::select! {
            r = listener.accept() => r,
            _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
        };
        let (client, peer) = match accept {
            Ok(x) => x,
            Err(e) => {
                log::debug!("relay accept error: {e}");
                continue;
            }
        };
        // Defence in depth: a socket bound to 127.0.0.1 can only ever see
        // loopback peers, but check and drop anything else.
        if !peer.ip().is_loopback() {
            log::warn!(
                "relay: dropping non-loopback peer {}",
                crate::stealth::redact_socket_addr(&peer)
            );
            drop(client);
            continue;
        }
        let mut target = target.clone();
        if !target.rotate_ips.is_empty() {
            // The accept loop is single-threaded, so advancing this index
            // needs no additional lock. Each connection receives one
            // operator-approved address; the client cannot select it.
            target.connect_ip =
                selected_destination_ip(target.connect_ip, &target.rotate_ips, rotation_index);
            rotation_index = rotation_index.wrapping_add(1);
        }
        let cb = hooks.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(client, target, cb).await {
                log::debug!("relay conn ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    client: TcpStream,
    target: RelayTarget,
    hooks: Arc<FlowHooks>,
) -> Result<(), DpiGuardError> {
    let local_ip = local_ip_for(target.connect_ip).ok_or_else(|| {
        DpiGuardError::Resolution("cannot determine local IP for relay socket".into())
    })?;
    let socket = if target.connect_ip.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }?;
    socket.bind(SocketAddr::new(local_ip, 0))?;
    let sport = socket.local_addr()?.port();
    let flow = FlowInfo {
        src: local_ip,
        sport,
        dst: target.connect_ip,
        dport: target.connect_port,
    };
    let gate = (hooks.register)(flow);
    // From here on every return path — the connect error, the connect
    // timeout, the fail-closed drop, and the normal end of the copy loop —
    // releases the pipeline's flow-table slot when this guard drops.
    let _slot = FlowSlot {
        flow,
        hooks: hooks.clone(),
    };

    let server = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        socket.connect(SocketAddr::new(target.connect_ip, target.connect_port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            log::debug!(
                "relay: connect failed: {e} (destination {})",
                crate::stealth::redact_socket_addr(&SocketAddr::new(
                    target.connect_ip,
                    target.connect_port
                ))
            );
            return Err(e.into());
        }
        Err(_) => {
            // Without a timeout, a SYN to an unreachable or black-holed
            // destination holds the client's already-accepted socket open
            // for the OS's full TCP connect timeout (tens of seconds on
            // Windows). On a link that flaps constantly that looks exactly
            // like the relay hanging, and v2rayN sits waiting with it.
            log::warn!(
                "relay: connect timed out after {CONNECT_TIMEOUT:?}; the link is down or the \
                 destination is unreachable. Failing fast so the client can retry."
            );
            return Err(DpiGuardError::Resolution(
                "relay connect timed out (link down or destination unreachable)".into(),
            ));
        }
    };
    let _ = server.set_nodelay(true);
    // Keepalive on the UPSTREAM socket: a link flap can black-hole the
    // remote end without ever delivering a FIN/RST, leaving the copy loop
    // below waiting forever. Probes every UPSTREAM_KEEPALIVE let the OS
    // detect the dead peer and error the read.
    {
        let sock = socket2::SockRef::from(&server);
        let ka = socket2::TcpKeepalive::new()
            .with_time(UPSTREAM_KEEPALIVE)
            .with_interval(UPSTREAM_KEEPALIVE);
        if let Err(e) = sock.set_tcp_keepalive(&ka) {
            log::debug!("relay: could not enable TCP keepalive: {e}");
        }
    }

    // Wait for the fake-SNI injection result. The pipeline observes the
    // outbound final ACK, injects the fake, and signals success once it
    // sees the server dup-ACK it.
    let ok = gate.wait(FAKE_ACK_WAIT).await;

    if target.require_inject && !ok {
        crate::observability::relay_fail_closed();
        // Fail CLOSED: drop both sides without copying a single byte of
        // the client's real ClientHello. This is the whole point.
        log::warn!(
            "relay: fake injection not confirmed for {} within {:?}; dropping connection \
             (relay_require_inject=true — real SNI was NOT forwarded)",
            crate::stealth::redact_socket_addr(&SocketAddr::new(
                target.connect_ip,
                target.connect_port
            )),
            FAKE_ACK_WAIT
        );
        drop(server);
        drop(client);
        return Ok(());
    }
    if !ok {
        log::warn!(
            "relay: fake injection not confirmed but relay_require_inject=false; \
             proceeding (fail-open)"
        );
    } else {
        log::info!(
            "relay: fake injection confirmed for {}; relaying real data",
            crate::stealth::redact_socket_addr(&SocketAddr::new(
                target.connect_ip,
                target.connect_port
            ))
        );
    }

    let (mut client_r, mut client_w) = client.into_split();
    let (mut server_r, mut server_w) = server.into_split();
    // Idle-deadline copy: any connection with no traffic in either
    // direction for `idle_timeout` is reaped. Combined with keepalive this
    // bounds how long a black-holed link-flap socket can hold resources.
    let a = copy_with_idle_deadline(&mut client_r, &mut server_w, target.idle_timeout);
    let b = copy_with_idle_deadline(&mut server_r, &mut client_w, target.idle_timeout);
    let _ = tokio::join!(a, b);
    let _ = client_w.shutdown().await;
    Ok(())
}

/// `tokio::io::copy` with a per-read idle deadline: returns
/// `TimedOut` when no byte arrives within `idle`, so idle/black-holed
/// relayed connections get reaped instead of living forever.
async fn copy_with_idle_deadline<R, W>(r: &mut R, w: &mut W, idle: Duration) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relay connection idle deadline exceeded",
                ))
            }
        };
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Pure handshake state machine (wrong_seq). No I/O; tests are declared but
// the current Rust test run is unavailable.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsAction {
    Pass,
    InjectFake,
    Complete,
    Fail,
}

#[derive(Debug)]
pub struct HandshakeMonitor {
    syn_seq: i64,
    syn_ack_seq: i64,
    fake_sent: bool,
    scheduled_fake: bool,
}

fn add1(seq: i64) -> u32 {
    ((seq + 1) & 0xFFFF_FFFF) as u32
}

impl Default for HandshakeMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeMonitor {
    pub fn new() -> Self {
        Self {
            syn_seq: -1,
            syn_ack_seq: -1,
            fake_sent: false,
            scheduled_fake: false,
        }
    }

    /// Sequence number stamped on the fake ClientHello. It occupies
    /// `[syn_seq+1-len, syn_seq+1)`: ends exactly where the server next
    /// expects data, so a real TCP stack ACKs it as already received and
    /// drops it, while a stateless DPI still parses the TLS record.
    pub fn fake_seq_for(&self, payload_len: usize) -> u32 {
        (self.syn_seq + 1 - payload_len as i64) as u32
    }

    /// Sequence number for a fake ClientHello that should NOT use the
    /// wrong-seq trick (config `enable_wrong_seq = false`).
    ///
    /// `syn_seq + 1` is exactly where the server expects the next byte, so
    /// the packet sits at a legitimate position in the stream instead of
    /// being slid back by its own length. This makes the fake less likely to
    /// be dropped by a real stack and less likely to fool a DPI — which is
    /// the trade-off the operator asked for by turning the flag off.
    pub fn correct_seq_for(&self, _payload_len: usize) -> u32 {
        (self.syn_seq + 1) as u32
    }

    pub fn mark_fake_sent(&mut self) {
        self.fake_sent = true;
    }

    /// Mark the handshake as failed so later packets return [`HsAction::Fail`].
    /// Called from the packet pipeline when fake ClientHello construction fails.
    pub fn fail(&mut self) {
        self.scheduled_fake = true;
        self.fake_sent = false;
    }

    // 8 args mirror the TCP wire flags (SYN/ACK/RST/FIN + seq/ack/payload);
    // bundling them into a struct would only move the verbosity around.
    #[allow(clippy::too_many_arguments)]
    pub fn on_outbound(
        &mut self,
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
        seq: u32,
        ack_num: u32,
        payload_len: usize,
    ) -> HsAction {
        if self.scheduled_fake {
            return HsAction::Fail;
        }
        if syn && !ack && !rst && !fin && payload_len == 0 {
            if ack_num != 0 {
                return HsAction::Fail;
            }
            if self.syn_seq != -1 && self.syn_seq as u32 != seq {
                return HsAction::Fail;
            }
            self.syn_seq = seq as i64;
            return HsAction::Pass;
        }
        if ack && !syn && !rst && !fin && payload_len == 0 {
            if self.syn_seq == -1 || seq != add1(self.syn_seq) {
                return HsAction::Fail;
            }
            if self.syn_ack_seq == -1 || ack_num != add1(self.syn_ack_seq) {
                return HsAction::Fail;
            }
            self.scheduled_fake = true;
            return HsAction::InjectFake;
        }
        HsAction::Fail
    }

    // Same wire-flag signature contract as `on_outbound`.
    #[allow(clippy::too_many_arguments)]
    pub fn on_inbound(
        &mut self,
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
        seq: u32,
        ack_num: u32,
        payload_len: usize,
    ) -> HsAction {
        if self.syn_seq == -1 {
            return HsAction::Fail;
        }
        if ack && syn && !rst && !fin && payload_len == 0 {
            if self.syn_ack_seq != -1 && self.syn_ack_seq as u32 != seq {
                return HsAction::Fail;
            }
            if ack_num != add1(self.syn_seq) {
                return HsAction::Fail;
            }
            self.syn_ack_seq = seq as i64;
            return HsAction::Pass;
        }
        if ack && !syn && !rst && !fin && payload_len == 0 && self.fake_sent {
            if self.syn_ack_seq == -1 || seq != add1(self.syn_ack_seq) {
                return HsAction::Fail;
            }
            if ack_num != add1(self.syn_seq) {
                return HsAction::Fail;
            }
            return HsAction::Complete;
        }
        HsAction::Fail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_uses_operator_set_and_wraps() {
        let primary: IpAddr = "203.0.113.1".parse().unwrap();
        let ips: Vec<IpAddr> = ["1.1.1.1", "1.0.0.1"]
            .into_iter()
            .map(|raw| raw.parse().unwrap())
            .collect();
        assert_eq!(selected_destination_ip(primary, &[], 0), primary);
        assert_eq!(selected_destination_ip(primary, &ips, 0), ips[0]);
        assert_eq!(selected_destination_ip(primary, &ips, 1), ips[1]);
        assert_eq!(selected_destination_ip(primary, &ips, 2), ips[0]);
    }

    #[test]
    fn rotation_is_not_an_open_proxy_selector() {
        let primary: IpAddr = "203.0.113.1".parse().unwrap();
        let ips: Vec<IpAddr> = ["1.1.1.1", "1.0.0.1"]
            .into_iter()
            .map(|raw| raw.parse().unwrap())
            .collect();
        // The selector only accepts the preconfigured slice; there is no
        // caller-provided host/port argument anywhere in this path.
        for index in 0..8 {
            assert!(ips.contains(&selected_destination_ip(primary, &ips, index)));
        }
    }

    fn run_happy_path(mon: &mut HandshakeMonitor) {
        assert_eq!(
            mon.on_outbound(true, false, false, false, 1000, 0, 0),
            HsAction::Pass
        );
        assert_eq!(
            mon.on_inbound(true, true, false, false, 5000, 1001, 0),
            HsAction::Pass
        );
        assert_eq!(
            mon.on_outbound(false, true, false, false, 1001, 5001, 0),
            HsAction::InjectFake
        );
    }

    #[test]
    fn fake_seq_lands_one_past_syn() {
        let mut mon = HandshakeMonitor::new();
        run_happy_path(&mut mon);
        assert_eq!(mon.fake_seq_for(517), 1000 + 1 - 517);
        assert_eq!(mon.fake_seq_for(5000), ((1001 - 5000) as i64) as u32);
    }

    #[test]
    fn happy_path_completes_after_dup_ack() {
        let mut mon = HandshakeMonitor::new();
        run_happy_path(&mut mon);
        mon.mark_fake_sent();
        assert_eq!(
            mon.on_inbound(false, true, false, false, 5001, 1001, 0),
            HsAction::Complete
        );
    }

    /// Worst case a client waits before the relay gives up: connect timeout
    /// plus the fake-injection wait. Both must stay bounded, otherwise a
    /// flapping link makes the relay look hung instead of failing fast and
    /// letting the client (v2rayN) retry.
    #[test]
    fn client_facing_wait_is_bounded() {
        let worst = CONNECT_TIMEOUT + FAKE_ACK_WAIT;
        assert!(
            worst <= Duration::from_secs(15),
            "a client could wait {worst:?}; keep CONNECT_TIMEOUT + FAKE_ACK_WAIT bounded"
        );
        // The connect timeout must dominate: failing to reach the
        // destination should never be reported as an injection failure.
        assert!(CONNECT_TIMEOUT > FAKE_ACK_WAIT);
    }

    #[test]
    fn fail_makes_later_packets_fail() {
        let mut mon = HandshakeMonitor::new();
        mon.on_outbound(true, false, false, false, 1000, 0, 0);
        mon.fail();
        assert_eq!(
            mon.on_outbound(false, true, false, false, 1001, 5001, 0),
            HsAction::Fail
        );
        assert_eq!(
            mon.on_inbound(false, true, false, false, 5001, 1001, 0),
            HsAction::Fail
        );
    }

    #[test]
    fn wrong_seq_is_rejected() {
        let mut mon = HandshakeMonitor::new();
        mon.on_outbound(true, false, false, false, 1000, 0, 0);
        mon.on_inbound(false, true, false, false, 5000, 1001, 0);
        assert_eq!(
            mon.on_outbound(false, true, false, false, 999, 5001, 0),
            HsAction::Fail
        );
    }

    #[test]
    fn inject_gate_records_success_and_failure() {
        let g = InjectGate::new();
        assert!(!g.is_set());
        let g2 = g.clone();
        g2.succeed();
        assert!(g.is_set());
        assert!(g.was_ok());

        let h = InjectGate::new();
        h.fail();
        assert!(h.is_set());
        assert!(!h.was_ok());
    }

    #[tokio::test]
    async fn inject_gate_wait_returns_state() {
        let g = InjectGate::new();
        let g2 = g.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            g2.succeed();
        });
        assert!(g.wait(Duration::from_secs(2)).await);

        let h = InjectGate::new();
        // Unset gate times out -> false.
        assert!(!h.wait(Duration::from_millis(50)).await);
    }

    fn test_flow() -> FlowInfo {
        FlowInfo {
            src: "10.0.0.2".parse().unwrap(),
            sport: 51000,
            dst: "203.0.113.9".parse().unwrap(),
            dport: 443,
        }
    }

    /// The `FlowSlot` guard must unregister exactly once when it drops,
    /// which is what makes every early return in `handle_conn` — including
    /// the fail-closed path — release the pipeline's flow-table slot.
    #[test]
    fn flow_slot_unregisters_on_drop() {
        use std::sync::atomic::AtomicUsize;

        let registered = Arc::new(AtomicUsize::new(0));
        let unregistered = Arc::new(AtomicUsize::new(0));
        let r = registered.clone();
        let u = unregistered.clone();
        let hooks = FlowHooks::new(
            move |_flow| {
                r.fetch_add(1, Ordering::SeqCst);
                InjectGate::new()
            },
            move |_flow| {
                u.fetch_add(1, Ordering::SeqCst);
            },
        );

        {
            let flow = test_flow();
            let _gate = (hooks.register)(flow);
            let _slot = FlowSlot {
                flow,
                hooks: hooks.clone(),
            };
            assert_eq!(registered.load(Ordering::SeqCst), 1);
            assert_eq!(
                unregistered.load(Ordering::SeqCst),
                0,
                "must not unregister while the connection is live"
            );
        }

        assert_eq!(
            unregistered.load(Ordering::SeqCst),
            1,
            "dropping the slot must release the flow exactly once"
        );
    }

    /// Regression for the feedback loop: repeated fail-closed connections
    /// must not accumulate slots. Each iteration registers and then drops
    /// without ever confirming injection, exactly like the
    /// `require_inject && !ok` branch of `handle_conn`.
    #[test]
    fn repeated_fail_closed_connections_do_not_accumulate() {
        use std::collections::HashSet;
        use std::sync::Mutex;

        let live: Arc<Mutex<HashSet<(u16, u16)>>> = Arc::new(Mutex::new(HashSet::new()));
        let add = live.clone();
        let del = live.clone();
        let hooks = FlowHooks::new(
            move |f: FlowInfo| {
                add.lock().unwrap().insert((f.sport, f.dport));
                InjectGate::new()
            },
            move |f: FlowInfo| {
                del.lock().unwrap().remove(&(f.sport, f.dport));
            },
        );

        for i in 0..1000u16 {
            let flow = FlowInfo {
                src: "10.0.0.2".parse().unwrap(),
                sport: 40000 + i,
                dst: "203.0.113.9".parse().unwrap(),
                dport: 443,
            };
            let gate = (hooks.register)(flow);
            let _slot = FlowSlot {
                flow,
                hooks: hooks.clone(),
            };
            // Injection never confirmed: the gate stays unset, the relay
            // would take the fail-closed branch and return early.
            assert!(!gate.is_set());
        }

        assert!(
            live.lock().unwrap().is_empty(),
            "every fail-closed connection must have released its slot"
        );
    }
}

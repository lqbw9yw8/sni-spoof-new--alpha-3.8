//! Criterion benchmark suite for the dpi_guard hot paths.
//!
//! Methodology (Max Woolf, "agentic iteration" / benchmaxxing with
//! guardrails): heterogeneous + adversarial inputs, a frozen True
//! Performance Baseline, and optimization only against real library code
//! — never benchmark hacks, never `unsafe`, never feature removal.
//!
//! Input diversity notes:
//! - SNI lengths: 4 B ("a.io"), 11 B ("example.com"), 38 B, 79 B (max-label
//!   chains), because mutation/fragmentation costs scale with name length.
//! - Packet sizes: minimal hello (~110 B), typical hello (~150 B), and
//!   1400 B MTU-edge app data for the passthrough/checksum paths.
//! - Cache states: warm strategy tables, warm DNS cache, fresh flows.
//! - Adversarial: non-TLS payload on port 443, app data, empty ACK.

use std::net::IpAddr;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dpi_guard::config::{merge_partial, parse, redacted_toml, Settings};
use dpi_guard::dns_cache::DnsCache;
use dpi_guard::fragmentation;
use dpi_guard::packet::{
    recalc_ipv4_checksum, tcp_checksum_v4, tcp_checksum_v6, wrap_ipv4_tcp, wrap_ipv6_tcp,
    TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN,
};
use dpi_guard::pipeline::Pipeline;
use dpi_guard::relay::FlowInfo;
use dpi_guard::sni_mutations::{self, MutationProfile};
use dpi_guard::strategy::StrategyTable;

// ─────────────────────────────────────────────────────────────────────────────
// Heterogeneous SNI corpus
// ─────────────────────────────────────────────────────────────────────────────

const SNIS: [&str; 4] = [
    "a.io",                                            // 4 B, shortest realistic
    "example.com",                                     // 11 B, the common case
    "www.client-online.example-bank.co.uk",            // 38 B, subdomain chain
    "mail.very-long-subdomain.example-holding-ltd.co", // 49 B label-heavy
];

/// Build an outbound ClientHello packet with per-iteration-varying flow
// (sport + seq) so the pipeline treats each packet as a fresh connection,
// exactly like real traffic.
fn ch_pkt(sni: &str, i: usize) -> Vec<u8> {
    let hello = fragmentation::encode_client_hello(sni);
    wrap_ipv4_tcp(
        &hello,
        [10, (i >> 8) as u8, i as u8, 1],
        [1, 1, 1, 1],
        40000 + (i % 20000) as u16,
        443,
        1000 + 1460 * i as u32,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
    )
}

fn ch_pkt6(sni: &str, i: usize) -> Vec<u8> {
    let hello = fragmentation::encode_client_hello(sni);
    wrap_ipv6_tcp(
        &hello,
        [
            0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i as u8,
        ],
        [0x26, 0, 0x1c, 0x9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        40000 + (i % 20000) as u16,
        443,
        1000 + 1460 * i as u32,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
    )
}

fn pipeline_with(mut s: Settings) -> Pipeline {
    s.enable_decoys = false;
    Pipeline::new(s)
}

/// 1400 B of realistic TLS 1.3 app-data (no ClientHello inside).
fn app_data_pkt(i: usize) -> Vec<u8> {
    let mut payload = vec![0u8; 1400];
    payload[0] = 0x17; // application_data
    payload[1] = 0x03;
    payload[2] = 0x03;
    for (n, b) in payload[5..].iter_mut().enumerate() {
        *b = (n + i) as u8;
    }
    wrap_ipv4_tcp(
        &payload,
        [10, 0, 0, 2],
        [1, 1, 1, 1],
        40000 + (i % 20000) as u16,
        443,
        2000 + 1400 * i as u32,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
    )
}

fn empty_ack(i: usize) -> Vec<u8> {
    wrap_ipv4_tcp(
        &[],
        [10, 0, 0, 3],
        [1, 1, 1, 1],
        40000 + (i % 20000) as u16,
        443,
        9000 + i as u32,
        TCP_FLAG_ACK,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Checksums / header math — runs for every single packet
// ─────────────────────────────────────────────────────────────────────────────

fn bench_checksums(c: &mut Criterion) {
    let mut g = c.benchmark_group("packet_checksums");
    let small = vec![0x5au8; 517];
    let big = vec![0xa5u8; 1400];

    g.bench_function("tcp_v4_517", |b| {
        b.iter(|| {
            tcp_checksum_v4(
                black_box([10, 0, 0, 1]),
                black_box([1, 1, 1, 1]),
                black_box(&small),
            )
        })
    });
    g.bench_function("tcp_v4_1400", |b| {
        b.iter(|| {
            tcp_checksum_v4(
                black_box([10, 0, 0, 1]),
                black_box([1, 1, 1, 1]),
                black_box(&big),
            )
        })
    });
    g.bench_function("tcp_v6_1400", |b| {
        b.iter(|| {
            tcp_checksum_v6(
                black_box([0x20; 16]),
                black_box([0x26; 16]),
                black_box(&big),
            )
        })
    });
    let mut pkt = app_data_pkt(0);
    g.bench_function("recalc_ipv4_1400", |b| {
        b.iter(|| {
            recalc_ipv4_checksum(black_box(&mut pkt));
        })
    });
    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Pipeline::handle — the per-captured-packet hot path
// ─────────────────────────────────────────────────────────────────────────────

fn bench_pipeline(c: &mut Criterion) {
    let mut g = c.benchmark_group("pipeline_handle");
    g.throughput(Throughput::Bytes(150));

    // 2a. Zero-work passthrough (port 22 is never intercepted).
    {
        let pkts: Vec<Vec<u8>> = (0..512)
            .map(|i| {
                let hello = fragmentation::encode_client_hello("example.com");
                wrap_ipv4_tcp(
                    &hello,
                    [10, 0, 0, 1],
                    [1, 1, 1, 1],
                    50000 + i as u16,
                    22,
                    i as u32,
                    TCP_FLAG_ACK | TCP_FLAG_PSH,
                )
            })
            .collect();
        let mut p = pipeline_with(Settings::default());
        let mut i = 0usize;
        g.bench_function("passthrough_port22", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }

    // 2b. 1400 B app-data on 443 (no ClientHello → sniff + pass).
    {
        let pkts: Vec<Vec<u8>> = (0..512).map(app_data_pkt).collect();
        let mut p = pipeline_with(Settings::default());
        let mut i = 0usize;
        g.throughput(Throughput::Bytes(1400));
        g.bench_function("appdata_1400_no_hello", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }

    // 2c. Empty ACK on 443.
    {
        let pkts: Vec<Vec<u8>> = (0..512).map(empty_ack).collect();
        let mut p = pipeline_with(Settings::default());
        let mut i = 0usize;
        g.bench_function("empty_ack_443", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }
    g.throughput(Throughput::Bytes(150));

    // 2d. Full mutation path per profile, no fragmentation.
    for (name, profile) in [
        ("stealth", "Stealth"),
        ("russiadpi", "RussiaDpi"),
        ("chinagfw", "ChinaGfw"),
        ("nestedcloak", "NestedCloak"),
    ] {
        let pkts: Vec<Vec<u8>> = (0..512).map(|i| ch_pkt("example.com", i)).collect();
        let mut p = pipeline_with(Settings {
            mutation_profile: profile.into(),
            enable_sni_fragmentation: false,
            enable_combined_fragmentation: false,
            ..Settings::default()
        });
        let mut i = 0usize;
        g.bench_function(BenchmarkId::new("mutate", name), |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }

    // 2e. Mutation + fragmentation ladders.
    {
        let pkts: Vec<Vec<u8>> = (0..512).map(|i| ch_pkt("example.com", i)).collect();
        let mut p = pipeline_with(Settings {
            enable_sni_fragmentation: true,
            enable_frag_by_sni: true,
            ..Settings::default()
        });
        let mut i = 0usize;
        g.bench_function("frag_by_sni", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }
    {
        let pkts: Vec<Vec<u8>> = (0..512).map(|i| ch_pkt("example.com", i)).collect();
        let mut p = pipeline_with(Settings {
            enable_sni_fragmentation: true,
            enable_tls_record_fragmentation: true,
            ..Settings::default()
        });
        let mut i = 0usize;
        g.bench_function("tls_record_frag", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }
    {
        let pkts: Vec<Vec<u8>> = (0..512).map(|i| ch_pkt("example.com", i)).collect();
        let mut p = pipeline_with(Settings {
            enable_sni_fragmentation: true,
            enable_combined_fragmentation: true,
            ..Settings::default()
        });
        let mut i = 0usize;
        g.bench_function("combined_frag", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }

    // 2f. Full relay handshake (SYN → SYN-ACK → ACK[inject] → dup-ACK →
    // real hello passthrough) on a fresh flow per iteration.
    {
        let mut p = pipeline_with(Settings::default());
        p.configure_relay(Some(dpi_guard::relay::RelayMode {
            fake_sni: "benign.com".into(),
            connect_port: 443,
            mutate_real_sni: false,
            emit_decoy: false,
            require_inject: true,
        }));
        let sport = std::cell::Cell::new(51000u16);
        let tcp5 = |src: [u8; 4],
                    dst: [u8; 4],
                    sp: u16,
                    dp: u16,
                    seq: u32,
                    ack: u32,
                    flags: u8,
                    payload: &[u8]| {
            let mut pkt = wrap_ipv4_tcp(payload, src, dst, sp, dp, seq, flags);
            if let Some(parsed) = dpi_guard::packet::parse_l3l4(&pkt) {
                let off = parsed.l4_offset + dpi_guard::packet::tcp_off::ACK;
                if pkt.len() >= off + 4 {
                    pkt[off..off + 4].copy_from_slice(&ack.to_be_bytes());
                }
            }
            pkt
        };
        g.bench_function("relay_handshake_5step", |b| {
            b.iter_batched(
                // setup: only rotates the source port (no pipeline access)
                || {
                    let sp = sport.get();
                    sport.set(if sp >= 62000 { 51000 } else { sp + 1 });
                    sp
                },
                |sp| {
                    let gate = p.register_relay_flow(FlowInfo {
                        src: IpAddr::from([10, 0, 0, 1]),
                        sport: sp,
                        dst: IpAddr::from([1, 1, 1, 1]),
                        dport: 443,
                    });
                    gate.succeed();
                    let syn = tcp5(
                        [10, 0, 0, 1],
                        [1, 1, 1, 1],
                        sp,
                        443,
                        1000,
                        0,
                        TCP_FLAG_SYN,
                        b"",
                    );
                    let synack = tcp5(
                        [1, 1, 1, 1],
                        [10, 0, 0, 1],
                        443,
                        sp,
                        5000,
                        1001,
                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                        b"",
                    );
                    let ack = tcp5(
                        [10, 0, 0, 1],
                        [1, 1, 1, 1],
                        sp,
                        443,
                        1001,
                        5001,
                        TCP_FLAG_ACK,
                        b"",
                    );
                    let dupack = tcp5(
                        [1, 1, 1, 1],
                        [10, 0, 0, 1],
                        443,
                        sp,
                        5001,
                        1001,
                        TCP_FLAG_ACK,
                        b"",
                    );
                    let hello = fragmentation::encode_client_hello("real.server.example");
                    let real = tcp5(
                        [10, 0, 0, 1],
                        [1, 1, 1, 1],
                        sp,
                        443,
                        1017,
                        5001,
                        TCP_FLAG_ACK | TCP_FLAG_PSH,
                        &hello,
                    );
                    black_box(p.handle(black_box(&syn)).unwrap());
                    black_box(p.handle(black_box(&synack)).unwrap());
                    black_box(p.handle(black_box(&ack)).unwrap());
                    black_box(p.handle(black_box(&dupack)).unwrap());
                    let out = p.handle(black_box(&real)).unwrap();
                    p.unregister_relay_flow(FlowInfo {
                        src: IpAddr::from([10, 0, 0, 1]),
                        sport: sp,
                        dst: IpAddr::from([1, 1, 1, 1]),
                        dport: 443,
                    });
                    sport.set(if sp >= 62000 { 51000 } else { sp + 1 });
                    drop(gate);
                    black_box(out)
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    // 2g. IPv6 hello path.
    {
        let pkts: Vec<Vec<u8>> = (0..512).map(|i| ch_pkt6("example.com", i)).collect();
        let mut p = pipeline_with(Settings {
            mutation_profile: "RussiaDpi".into(),
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let mut i = 0usize;
        g.bench_function("mutate_ipv6", |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }

    // 2h. SNI length scaling on the plain mutate path.
    for sni in SNIS {
        let pkts: Vec<Vec<u8>> = (0..512).map(|i| ch_pkt(sni, i)).collect();
        let mut p = pipeline_with(Settings {
            mutation_profile: "RussiaDpi".into(),
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let mut i = 0usize;
        g.bench_function(BenchmarkId::new("sni_len", sni.len()), |b| {
            b.iter(|| {
                i = (i + 1) & 511;
                black_box(p.handle(black_box(&pkts[i])).unwrap())
            })
        });
    }

    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ClientHello parsing & fragmentation primitives
// ─────────────────────────────────────────────────────────────────────────────

fn bench_fragmentation(c: &mut Criterion) {
    let mut g = c.benchmark_group("fragmentation");

    for sni in SNIS {
        let hello = fragmentation::encode_client_hello(sni);
        g.bench_function(BenchmarkId::new("parse_client_hello", sni.len()), |b| {
            b.iter(|| fragmentation::parse_client_hello(black_box(&hello)).unwrap())
        });
    }

    let hello = fragmentation::encode_client_hello("www.client-online.example-bank.co.uk");
    g.bench_function("tls_split_before_sni", |b| {
        b.iter(|| fragmentation::tls_record_split_before_sni(black_box(&hello)).unwrap())
    });
    g.bench_function("tls_split_mid_sni", |b| {
        b.iter(|| fragmentation::tls_record_split_mid_sni(black_box(&hello)).unwrap())
    });
    g.bench_function("sni_byte_chunk", |b| {
        b.iter(|| fragmentation::fragment_sni_byte_chunk(black_box(&hello)).unwrap())
    });
    g.bench_function("nested_cloak", |b| {
        b.iter(|| {
            fragmentation::nested_cloak(
                black_box(&hello),
                black_box(b"mail.microsoft.com"),
                black_box(b"real.example.co.uk"),
                black_box(0xFF01),
            )
            .unwrap()
        })
    });
    g.bench_function("splice_sni", |b| {
        b.iter(|| {
            fragmentation::splice_sni(black_box(&hello), black_box(b"cloudflare.com")).unwrap()
        })
    });
    let stream = vec![0x17u8; 8192];
    g.bench_function("persistent_frag_8k_100", |b| {
        b.iter(|| fragmentation::persistent_fragmentation(black_box(&stream), black_box(100)))
    });
    let hs = vec![0x16u8; 5000];
    g.bench_function("tls_records_5000_100", |b| {
        b.iter(|| fragmentation::fragment_as_tls_records(black_box(&hs), black_box(100)))
    });
    g.bench_function("smart_split_points", |b| {
        b.iter(|| fragmentation::calculate_smart_split_points(black_box(&hello)).unwrap())
    });
    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SNI mutations
// ─────────────────────────────────────────────────────────────────────────────

fn bench_mutations(c: &mut Criterion) {
    let mut g = c.benchmark_group("sni_mutations");
    for profile in MutationProfile::ALL {
        let sni = b"www.client-online.example-bank.co.uk".to_vec();
        g.bench_function(BenchmarkId::new("mutate_sni_full", profile.as_str()), |b| {
            b.iter(|| sni_mutations::mutate_sni_full(black_box(&sni), black_box(profile)))
        });
    }
    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Strategy table — scored per ClientHello + per feedback event
// ─────────────────────────────────────────────────────────────────────────────

fn warm_table() -> StrategyTable {
    let table = StrategyTable::new();
    let domains: Vec<String> = (0..32).map(|d| format!("host{d}.example.com")).collect();
    let techs: Vec<String> = (0..16).map(|t| format!("tech{t}")).collect();
    for (di, d) in domains.iter().enumerate() {
        for (ti, t) in techs.iter().enumerate() {
            for k in 0..3 {
                table.update_score(d, t, (di + ti + k) % 4 != 0);
            }
        }
    }
    table
}

fn bench_strategy(c: &mut Criterion) {
    let mut g = c.benchmark_group("strategy");
    let table = warm_table();
    let cands: Vec<String> = (0..16).map(|t| format!("tech{t}")).collect();
    let cands: Vec<&str> = cands.iter().map(String::as_str).collect();

    g.bench_function("score_of_warm", |b| {
        b.iter(|| table.score_of(black_box("host7.example.com"), black_box("tech9")))
    });
    g.bench_function("select_best_16", |b| {
        b.iter(|| table.select_best(black_box("host7.example.com"), black_box(&cands)))
    });
    g.bench_function("select_rotating_16", |b| {
        b.iter(|| table.select_rotating(black_box("host7.example.com"), black_box(&cands)))
    });
    g.bench_function("per_domain_scores", |b| {
        b.iter(|| table.per_domain_scores(black_box("host7.example.com")))
    });
    g.bench_function("update_score", |b| {
        b.iter(|| table.update_score(black_box("host7.example.com"), black_box("tech9"), true))
    });
    g.bench_function("scores_hashed_32d", |b| b.iter(|| table.scores_hashed()));
    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ECH crypto (HPKE: X25519 + HKDF + ChaCha20-Poly1305)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_crypto(c: &mut Criterion) {
    let mut g = c.benchmark_group("hpke_crypto");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = vec![0x11u8; 45];
    for size in [517usize, 8192] {
        let pt = vec![0xaau8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::new("seal", size), |b| {
            b.iter(|| {
                dpi_guard::hpke::chacha20_poly1305_seal(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&aad),
                    black_box(&pt),
                )
            })
        });
        let ct = dpi_guard::hpke::chacha20_poly1305_seal(&key, &nonce, &aad, &pt);
        g.bench_function(BenchmarkId::new("open", size), |b| {
            b.iter(|| {
                dpi_guard::hpke::chacha20_poly1305_open(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&aad),
                    black_box(&ct),
                )
                .unwrap()
            })
        });
    }
    g.throughput(Throughput::Bytes(1));
    let sk = [0x07u8; 32];
    g.bench_function("x25519", |b| {
        b.iter(|| dpi_guard::hpke::x25519_base(black_box(&sk)))
    });
    let msg = vec![0x33u8; 1024];
    g.bench_function("poly1305_1k", |b| {
        b.iter(|| dpi_guard::hpke::poly1305_mac(black_box(&msg), black_box(&key)))
    });
    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. DNS cache (per-outbound-lookup) + stealth hashing (per score row)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_dns_and_hash(c: &mut Criterion) {
    let mut g = c.benchmark_group("dns_and_hash");

    let mut cache = DnsCache::new();
    for d in 0..256 {
        cache.insert_with_ttl(
            &format!("host{d}.example.com"),
            vec![IpAddr::from([1, 2, 3, (d % 254 + 1) as u8])],
            Duration::from_secs(300),
        );
    }
    let now = std::time::Instant::now();
    g.bench_function("lookup_hit", |b| {
        b.iter(|| cache.lookup(black_box("host7.example.com"), black_box(now)))
    });
    g.bench_function("lookup_miss", |b| {
        b.iter(|| cache.lookup(black_box("nope.example.com"), black_box(now)))
    });

    let salt = b"pepper".to_vec();
    g.bench_function("hash_sensitive", |b| {
        b.iter(|| {
            dpi_guard::stealth::hash_sensitive(black_box("host7.example.com"), black_box(&salt))
        })
    });

    // QUIC classification (per UDP packet).
    let mut quic_pkt = vec![0u8; 1200];
    quic_pkt[0] = 0xc3; // long header, fixed bit, initial
    quic_pkt[1] = 0x00;
    quic_pkt[5] = 0x01; // version 1
    quic_pkt[1 + 5] = 0x01;
    g.bench_function("is_quic_initial", |b| {
        b.iter(|| dpi_guard::quic::is_quic_initial(black_box(&quic_pkt)))
    });
    g.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Config parse / merge / redact (startup + hot-reload path)
// ─────────────────────────────────────────────────────────────────────────────

const BASE_TOML: &str = include_str!("../dpi_guard.toml.example");

fn bench_config(c: &mut Criterion) {
    let mut g = c.benchmark_group("config");
    g.bench_function("parse_example", |b| {
        b.iter(|| parse(black_box(BASE_TOML)).unwrap())
    });
    let base = parse(BASE_TOML).unwrap();
    let partial = r#"
mutation_profile = "NestedCloak"
enable_decoys = false
relay_fake_sni = "www.bing.com"
win_divert_sha256 = ["c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2", "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"]
"#;
    g.bench_function("merge_partial", |b| {
        b.iter(|| merge_partial(black_box(&base), black_box(partial)).unwrap())
    });
    g.bench_function("redacted_toml", |b| {
        b.iter(|| redacted_toml(black_box(&base)).unwrap())
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_checksums,
    bench_pipeline,
    bench_fragmentation,
    bench_mutations,
    bench_strategy,
    bench_crypto,
    bench_dns_and_hash,
    bench_config,
);
criterion_main!(benches);

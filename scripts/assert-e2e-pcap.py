#!/usr/bin/env python3
"""Assert the relay's observable fake-SNI handshake in a pktmon pcapng.

This intentionally uses only the Python standard library. It checks the
wire evidence rather than trusting backend log text:
  * a fake ClientHello with the configured benign SNI was captured;
  * a real ClientHello was captured later, not before the fake;
  * the server sent repeated pure ACKs with the same ACK number after the
    fake (the duplicate-ACK confirmation used by the relay gate).
"""
from __future__ import annotations

import argparse
import ipaddress
import struct
import sys
from dataclasses import dataclass


@dataclass
class Packet:
    index: int
    timestamp: int
    outbound: bool
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes


TCP_ACK = 0x10
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_FIN = 0x01


def blocks(data: bytes):
    """Yield (block_type, block_bytes) from a little-endian pcapng file."""
    off = 0
    while off + 12 <= len(data):
        block_type, length = struct.unpack_from("<II", data, off)
        if length < 12 or off + length > len(data):
            raise ValueError(f"invalid pcapng block at {off}: length={length}")
        yield block_type, data[off : off + length]
        off += length


def unwrap_packet(link_type: int, raw: bytes) -> bytes | None:
    # pktmon normally emits Ethernet (DLT_EN10MB). Keep the fallback for
    # captures configured as raw IP, so a runner image change is explicit but
    # not needlessly brittle.
    if link_type == 1:
        if len(raw) < 14:
            return None
        if raw[12:14] != b"\x08\x00":
            return None
        return raw[14:]
    if raw and (raw[0] >> 4) == 4:
        return raw
    return None


def parse_packets(path: str, remote: str) -> list[Packet]:
    data = open(path, "rb").read()
    link_type = 1
    packets: list[Packet] = []
    remote_ip = ipaddress.ip_address(remote).packed
    for kind, block in blocks(data):
        if kind == 1:  # Interface Description Block
            if len(block) >= 12:
                link_type = struct.unpack_from("<H", block, 8)[0]
        if kind != 6 or len(block) < 32:  # Enhanced Packet Block
            continue
        _interface, ts_hi, ts_lo, caplen, _origlen = struct.unpack_from(
            "<IIIII", block, 8
        )
        raw = block[28 : 28 + caplen]
        ip = unwrap_packet(link_type, raw)
        if ip is None or len(ip) < 20:
            continue
        version = ip[0] >> 4
        if version != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl + 20 or ip[9] != 6:
            continue
        src, dst = ip[12:16], ip[16:20]
        if src != remote_ip and dst != remote_ip:
            continue
        total_len = struct.unpack_from("!H", ip, 2)[0]
        ip_end = min(len(ip), total_len) if total_len else len(ip)
        tcp = ip[ihl:ip_end]
        data_offset = ((tcp[12] >> 4) & 0x0F) * 4
        if data_offset < 20 or len(tcp) < data_offset:
            continue
        src_port, dst_port, seq, ack = struct.unpack_from("!HHII", tcp, 0)
        # The pktmon filter is part of the workflow, but keep this parser
        # defensive so a broader capture cannot satisfy the assertion with a
        # different TCP service on the same remote IP.
        if not ((dst == remote_ip and dst_port == 443) or (src == remote_ip and src_port == 443)):
            continue
        flags = tcp[13]
        payload = tcp[data_offset:]
        packets.append(
            Packet(
                index=len(packets),
                timestamp=(ts_hi << 32) | ts_lo,
                outbound=dst == remote_ip and dst_port == 443,
                src_port=src_port,
                dst_port=dst_port,
                seq=seq,
                ack=ack,
                flags=flags,
                payload=payload,
            )
        )
    return packets


def client_hello_sni(payload: bytes) -> str | None:
    # The relay's test ClientHello is one packet. This parser also accepts a
    # single TLS record starting at an offset, which handles link-layer
    # metadata or a coalesced TCP segment without implementing TLS.
    for start in range(0, min(len(payload), 8)):
        if len(payload) < start + 9 or payload[start] != 0x16:
            continue
        record_len = struct.unpack_from("!H", payload, start + 3)[0]
        record_end = start + 5 + record_len
        if record_end > len(payload) or payload[start + 5] != 1:
            continue
        hs_len = int.from_bytes(payload[start + 6 : start + 9], "big")
        body = payload[start + 9 : start + 9 + hs_len]
        if len(body) < 34:
            continue
        pos = 34  # client_version + random
        if pos >= len(body):
            continue
        session_len = body[pos]
        pos += 1 + session_len
        if pos + 2 > len(body):
            continue
        cipher_len = struct.unpack_from("!H", body, pos)[0]
        pos += 2 + cipher_len
        if pos >= len(body):
            continue
        compression_len = body[pos]
        pos += 1 + compression_len
        if pos + 2 > len(body):
            continue
        ext_len = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        end = min(len(body), pos + ext_len)
        while pos + 4 <= end:
            ext_type, ext_size = struct.unpack_from("!HH", body, pos)
            pos += 4
            ext = body[pos : pos + ext_size]
            pos += ext_size
            if ext_type != 0 or len(ext) < 5:
                continue
            list_len = struct.unpack_from("!H", ext, 0)[0]
            cursor, limit = 2, min(len(ext), 2 + list_len)
            while cursor + 3 <= limit:
                name_type = ext[cursor]
                name_len = struct.unpack_from("!H", ext, cursor + 1)[0]
                name = ext[cursor + 3 : cursor + 3 + name_len]
                cursor += 3 + name_len
                if name_type == 0:
                    try:
                        return name.decode("ascii")
                    except UnicodeDecodeError:
                        return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapng")
    parser.add_argument("--remote", required=True)
    parser.add_argument("--fake", required=True)
    parser.add_argument("--real", required=True)
    args = parser.parse_args()

    packets = parse_packets(args.pcapng, args.remote)
    if not packets:
        raise AssertionError("no IPv4/TCP packets to the configured remote endpoint")

    hellos: list[tuple[int, str, Packet]] = []
    for packet in packets:
        if packet.outbound:
            sni = client_hello_sni(packet.payload)
            if sni:
                hellos.append((packet.index, sni, packet))
    fake_events = [(i, packet) for i, sni, packet in hellos if sni == args.fake]
    if not fake_events:
        raise AssertionError(f"no captured fake ClientHello with SNI {args.fake!r}")
    first_fake, fake_packet = min(fake_events, key=lambda event: event[0])
    local_port = fake_packet.src_port
    real_indices = [
        i
        for i, sni, packet in hellos
        if sni == args.real and packet.src_port == local_port and packet.dst_port == 443
    ]
    if not real_indices:
        raise AssertionError(
            f"no captured real ClientHello with SNI {args.real!r}; fail-closed relay may have dropped it"
        )
    first_real = min(real_indices)
    if first_real <= first_fake:
        raise AssertionError(
            f"real ClientHello appeared before fake (fake index {first_fake}, real index {first_real})"
        )

    # A duplicate ACK is a pure ACK (no payload/SYN/RST/FIN) repeated with the
    # same ACK number after the fake. The source is implicitly the configured
    # remote because parse_packets marks only remote->local packets inbound.
    seen: dict[int, int] = {}
    duplicate_ack = None
    duplicate_ack_index = None
    for packet in packets:
        if (
            packet.index <= first_fake
            or packet.outbound
            or packet.src_port != 443
            or packet.dst_port != local_port
        ):
            continue
        if packet.payload or not (packet.flags & TCP_ACK):
            continue
        if packet.flags & (TCP_SYN | TCP_RST | TCP_FIN):
            continue
        count = seen.get(packet.ack, 0) + 1
        seen[packet.ack] = count
        if count >= 2:
            duplicate_ack = packet.ack
            duplicate_ack_index = packet.index
            break
    if duplicate_ack is None or duplicate_ack_index is None:
        raise AssertionError("no repeated server pure ACK was captured after the fake ClientHello")
    if first_real <= duplicate_ack_index:
        raise AssertionError(
            f"real ClientHello appeared before duplicate-ACK confirmation (real index {first_real}, dup-ACK index {duplicate_ack_index})"
        )

    print(
        "[E2E ASSERTIONS] fake ClientHello before real ClientHello; "
        f"duplicate ACK ack={duplicate_ack}; packets={len(packets)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, ValueError, OSError) as exc:
        print(f"[E2E ASSERTIONS] FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)

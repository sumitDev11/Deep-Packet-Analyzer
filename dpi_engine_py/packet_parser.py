from __future__ import annotations

from dataclasses import dataclass
import struct

from .pcap_reader import RawPacket


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    IPV4 = 0x0800
    IPV6 = 0x86DD
    ARP = 0x0806


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


@dataclass
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_length: int = 0
    payload_data: bytes = b""


def _mac_to_string(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def _ip_to_string(ip_bytes: bytes) -> str:
    # C++ code treated uint32 as little-endian print order.
    return ".".join(str(b) for b in ip_bytes)


def protocol_to_string(proto: int) -> str:
    if proto == Protocol.ICMP:
        return "ICMP"
    if proto == Protocol.TCP:
        return "TCP"
    if proto == Protocol.UDP:
        return "UDP"
    return f"Unknown({proto})"


def tcp_flags_to_string(flags: int) -> str:
    out = []
    if flags & TCPFlags.SYN:
        out.append("SYN")
    if flags & TCPFlags.ACK:
        out.append("ACK")
    if flags & TCPFlags.FIN:
        out.append("FIN")
    if flags & TCPFlags.RST:
        out.append("RST")
    if flags & TCPFlags.PSH:
        out.append("PSH")
    if flags & TCPFlags.URG:
        out.append("URG")
    return " ".join(out) if out else "none"


def parse_packet(raw: RawPacket) -> ParsedPacket | None:
    data = raw.data
    pkt = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
    if len(data) < 14:
        return None

    pkt.dest_mac = _mac_to_string(data[0:6])
    pkt.src_mac = _mac_to_string(data[6:12])
    pkt.ether_type = struct.unpack("!H", data[12:14])[0]
    off = 14

    if pkt.ether_type == EtherType.IPV4:
        if len(data) < off + 20:
            return None
        ip0 = data[off]
        pkt.ip_version = (ip0 >> 4) & 0x0F
        ihl = ip0 & 0x0F
        if pkt.ip_version != 4:
            return None
        ip_len = ihl * 4
        if ip_len < 20 or len(data) < off + ip_len:
            return None

        ip = data[off : off + ip_len]
        pkt.ttl = ip[8]
        pkt.protocol = ip[9]
        pkt.src_ip = _ip_to_string(ip[12:16])
        pkt.dest_ip = _ip_to_string(ip[16:20])
        pkt.has_ip = True
        off += ip_len

        if pkt.protocol == Protocol.TCP:
            if len(data) < off + 20:
                return None
            pkt.src_port, pkt.dest_port = struct.unpack("!HH", data[off : off + 4])
            pkt.seq_number = struct.unpack("!I", data[off + 4 : off + 8])[0]
            pkt.ack_number = struct.unpack("!I", data[off + 8 : off + 12])[0]
            tcp_off = (data[off + 12] >> 4) & 0x0F
            tcp_len = tcp_off * 4
            pkt.tcp_flags = data[off + 13]
            if tcp_len < 20 or len(data) < off + tcp_len:
                return None
            pkt.has_tcp = True
            off += tcp_len
        elif pkt.protocol == Protocol.UDP:
            if len(data) < off + 8:
                return None
            pkt.src_port, pkt.dest_port = struct.unpack("!HH", data[off : off + 4])
            pkt.has_udp = True
            off += 8

    if off < len(data):
        pkt.payload_length = len(data) - off
        pkt.payload_data = data[off:]
    else:
        pkt.payload_length = 0
        pkt.payload_data = b""
    return pkt

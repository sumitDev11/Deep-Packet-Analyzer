from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict, deque
from queue import Queue, Empty, Full
from threading import Lock, Thread, Event
import argparse
import struct
import time
from typing import Optional

from .pcap_reader import PcapReader
from .packet_parser import parse_packet
from .sni_extractor import extract_sni, extract_http_host
from .app_types import (
    AppType,
    FiveTuple,
    app_type_to_string,
    five_tuple_hash,
    parse_ipv4_to_le_int,
    sni_to_app_type,
)


class TSQueue:
    def __init__(self, max_size: int = 10000) -> None:
        self.q: Queue = Queue(maxsize=max_size)
        self.shutdown_event = Event()

    def push(self, item) -> None:
        while not self.shutdown_event.is_set():
            try:
                self.q.put(item, timeout=0.1)
                return
            except Full:
                continue

    def pop(self, timeout_ms: int = 100):
        try:
            return self.q.get(timeout=timeout_ms / 1000.0)
        except Empty:
            return None

    def shutdown(self) -> None:
        self.shutdown_event.set()

    def size(self) -> int:
        return self.q.qsize()


@dataclass
class Packet:
    packet_id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int
    payload_offset: int
    payload_length: int


@dataclass
class FlowEntry:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


class Rules:
    def __init__(self) -> None:
        self._lock = Lock()
        self._blocked_ips: set[int] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: list[str] = []

    def block_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(parse_ipv4_to_le_int(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        with self._lock:
            for a in AppType:
                if app_type_to_string(a) == app:
                    self._blocked_apps.add(a)
                    print(f"[Rules] Blocked app: {app}")
                    return
        print(f"[Rules] Unknown app: {app}")

    def block_domain(self, domain: str) -> None:
        with self._lock:
            self._blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        with self._lock:
            if src_ip in self._blocked_ips:
                return True
            if app in self._blocked_apps:
                return True
            sni_l = sni.lower()
            for d in self._blocked_domains:
                if d in sni_l:
                    return True
            return False


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded: int = 0
    dropped: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    app_counts: dict[AppType, int] = field(default_factory=lambda: defaultdict(int))
    detected_snis: dict[str, AppType] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock)

    def record_app(self, app: AppType, sni: str) -> None:
        with self.lock:
            self.app_counts[app] += 1
            if sni:
                self.detected_snis[sni] = app


class FastPath:
    def __init__(self, fp_id: int, rules: Rules, stats: Stats, output_queue: TSQueue) -> None:
        self.fp_id = fp_id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue = TSQueue()
        self.flows: dict[FiveTuple, FlowEntry] = {}
        self.running = Event()
        self.thread: Optional[Thread] = None
        self._processed = 0

    def start(self) -> None:
        self.running.set()
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running.clear()
        self.input_queue.shutdown()
        if self.thread:
            self.thread.join()

    @property
    def processed(self) -> int:
        return self._processed

    def run(self) -> None:
        while self.running.is_set():
            pkt = self.input_queue.pop(100)
            if pkt is None:
                continue
            self._processed += 1

            flow = self.flows.get(pkt.tuple)
            if flow is None:
                flow = FlowEntry(tuple=pkt.tuple)
                self.flows[pkt.tuple] = flow
            flow.packets += 1
            flow.bytes += len(pkt.data)

            if not flow.classified:
                self.classify_flow(pkt, flow)
            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(pkt.tuple.src_ip, flow.app_type, flow.sni)

            self.stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                with self.stats.lock:
                    self.stats.dropped += 1
            else:
                with self.stats.lock:
                    self.stats.forwarded += 1
                self.output_queue.push(pkt)

    def classify_flow(self, pkt: Packet, flow: FlowEntry) -> None:
        if pkt.payload_offset >= len(pkt.data):
            return
        payload = pkt.data[pkt.payload_offset:]
        if pkt.tuple.dst_port == 443 and len(payload) > 5:
            sni = extract_sni(payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return
        if pkt.tuple.dst_port == 80 and len(payload) > 10:
            host = extract_http_host(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return
        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return
        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class LoadBalancer:
    def __init__(self, lb_id: int, fps: list[FastPath]) -> None:
        self.lb_id = lb_id
        self.fps = fps
        self.input_queue = TSQueue()
        self.running = Event()
        self.thread: Optional[Thread] = None
        self._dispatched = 0

    def start(self) -> None:
        self.running.set()
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running.clear()
        self.input_queue.shutdown()
        if self.thread:
            self.thread.join()

    @property
    def dispatched(self) -> int:
        return self._dispatched

    def run(self) -> None:
        n = max(1, len(self.fps))
        while self.running.is_set():
            pkt = self.input_queue.pop(100)
            if pkt is None:
                continue
            fp_idx = five_tuple_hash(pkt.tuple) % n
            self.fps[fp_idx].input_queue.push(pkt)
            self._dispatched += 1


@dataclass
class Config:
    num_lbs: int = 2
    fps_per_lb: int = 2


class DPIEngine:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.rules = Rules()
        self.stats = Stats()
        self.output_queue = TSQueue()
        self.fps: list[FastPath] = []
        self.lbs: list[LoadBalancer] = []

        total_fps = cfg.num_lbs * cfg.fps_per_lb
        print()
        print("+--------------------------------------------------------------+")
        print("|              DPI ENGINE v2.0 (Multi-threaded)               |")
        print("+--------------------------------------------------------------+")
        print(
            f"| Load Balancers: {cfg.num_lbs:2d}    FPs per LB: {cfg.fps_per_lb:2d}"
            f"    Total FPs: {total_fps:2d}     |"
        )
        print("+--------------------------------------------------------------+")
        print()

        for i in range(total_fps):
            self.fps.append(FastPath(i, self.rules, self.stats, self.output_queue))
        for lb in range(cfg.num_lbs):
            chunk = self.fps[lb * cfg.fps_per_lb : (lb + 1) * cfg.fps_per_lb]
            self.lbs.append(LoadBalancer(lb, chunk))

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules.block_app(app)

    def block_domain(self, dom: str) -> None:
        self.rules.block_domain(dom)

    def process(self, input_file: str, output_file: str) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        try:
            out = open(output_file, "wb")
        except OSError:
            print("Cannot open output file")
            return False

        out.write(reader.raw_header_bytes)

        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        output_running = Event()
        output_running.set()

        def writer():
            while output_running.is_set() or self.output_queue.size() > 0:
                pkt = self.output_queue.pop(50)
                if pkt is None:
                    continue
                phdr = struct.pack("<IIII", pkt.ts_sec, pkt.ts_usec, len(pkt.data), len(pkt.data))
                out.write(phdr)
                out.write(pkt.data)

        writer_thread = Thread(target=writer, daemon=True)
        writer_thread.start()

        print("[Reader] Processing packets...")
        pkt_id = 0
        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break
            parsed = parse_packet(raw)
            if parsed is None:
                continue
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            with self.stats.lock:
                self.stats.total_packets += 1
                self.stats.total_bytes += len(raw.data)
                if parsed.has_tcp:
                    self.stats.tcp_packets += 1
                elif parsed.has_udp:
                    self.stats.udp_packets += 1

            tup = FiveTuple(
                src_ip=parse_ipv4_to_le_int(parsed.src_ip),
                dst_ip=parse_ipv4_to_le_int(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )

            payload_offset = 14
            if len(raw.data) > 14:
                ip_ihl = raw.data[14] & 0x0F
                payload_offset += ip_ihl * 4
                if parsed.has_tcp and payload_offset + 12 < len(raw.data):
                    tcp_off = (raw.data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                elif parsed.has_udp:
                    payload_offset += 8
            payload_len = max(0, len(raw.data) - payload_offset)

            pkt = Packet(
                packet_id=pkt_id,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                tuple=tup,
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=payload_offset,
                payload_length=payload_len,
            )
            pkt_id += 1
            lb_idx = five_tuple_hash(tup) % max(1, len(self.lbs))
            self.lbs[lb_idx].input_queue.push(pkt)

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        time.sleep(0.5)
        for lb in self.lbs:
            lb.stop()
        for fp in self.fps:
            fp.stop()

        output_running.clear()
        self.output_queue.shutdown()
        writer_thread.join()
        out.close()
        self.print_report()
        return True

    def print_report(self) -> None:
        with self.stats.lock:
            total = max(1, self.stats.total_packets)
            print()
            print("+--------------------------------------------------------------+")
            print("|                      PROCESSING REPORT                       |")
            print("+--------------------------------------------------------------+")
            print(f"| Total Packets: {self.stats.total_packets:17d}                           |")
            print(f"| Total Bytes:   {self.stats.total_bytes:17d}                           |")
            print(f"| TCP Packets:   {self.stats.tcp_packets:17d}                           |")
            print(f"| UDP Packets:   {self.stats.udp_packets:17d}                           |")
            print("+--------------------------------------------------------------+")
            print(f"| Forwarded:     {self.stats.forwarded:17d}                           |")
            print(f"| Dropped:       {self.stats.dropped:17d}                           |")
            print("+--------------------------------------------------------------+")
            print("| THREAD STATISTICS                                            |")
            for i, lb in enumerate(self.lbs):
                print(f"|   LB{i} dispatched: {lb.dispatched:12d}                           |")
            for i, fp in enumerate(self.fps):
                print(f"|   FP{i} processed:  {fp.processed:12d}                           |")
            print("+--------------------------------------------------------------+")
            print("|                   APPLICATION BREAKDOWN                      |")
            print("+--------------------------------------------------------------+")
            sorted_apps = sorted(self.stats.app_counts.items(), key=lambda kv: kv[1], reverse=True)
            for app, count in sorted_apps:
                pct = 100.0 * count / total
                bar = "#" * int(pct / 5)
                print(f"| {app_type_to_string(app):15s} {count:8d} {pct:5.1f}% {bar:20s} |")
            print("+--------------------------------------------------------------+")
            if self.stats.detected_snis:
                print("\n[Detected Domains/SNIs]")
                for sni, app in self.stats.detected_snis.items():
                    print(f"  - {sni} -> {app_type_to_string(app)}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="DPI Engine v2.0 - Multi-threaded Deep Packet Inspection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("input_pcap")
    p.add_argument("output_pcap")
    p.add_argument("--block-ip", action="append", default=[])
    p.add_argument("--block-app", action="append", default=[])
    p.add_argument("--block-domain", action="append", default=[])
    p.add_argument("--lbs", type=int, default=2)
    p.add_argument("--fps", type=int, default=2)
    return p

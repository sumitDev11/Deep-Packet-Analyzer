from __future__ import annotations

from dataclasses import dataclass
import struct


PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self) -> None:
        self._fp = None
        self._needs_swap = False
        self._ghdr: PcapGlobalHeader | None = None
        self._raw_header_bytes: bytes | None = None

    def open(self, filename: str) -> bool:
        self.close()
        try:
            self._fp = open(filename, "rb")
            self._raw_header_bytes = self._fp.read(24)
            if len(self._raw_header_bytes) != 24:
                print("Error: Could not read PCAP global header")
                self.close()
                return False

            magic = struct.unpack("<I", self._raw_header_bytes[:4])[0]
            if magic == PCAP_MAGIC_NATIVE:
                self._needs_swap = False
                fmt = "<IHHIIII"
            elif magic == PCAP_MAGIC_SWAPPED:
                self._needs_swap = True
                fmt = ">IHHIIII"
            else:
                print(f"Error: Invalid PCAP magic number: 0x{magic:08x}")
                self.close()
                return False

            vals = struct.unpack(fmt, self._raw_header_bytes)
            self._ghdr = PcapGlobalHeader(*vals)
            print(f"Opened PCAP file: {filename}")
            print(f"  Version: {self._ghdr.version_major}.{self._ghdr.version_minor}")
            print(f"  Snaplen: {self._ghdr.snaplen} bytes")
            link_note = " (Ethernet)" if self._ghdr.network == 1 else ""
            print(f"  Link type: {self._ghdr.network}{link_note}")
            return True
        except OSError as e:
            print(f"Error: Could not open file: {filename} ({e})")
            self.close()
            return False

    def close(self) -> None:
        if self._fp is not None:
            self._fp.close()
        self._fp = None
        self._needs_swap = False
        self._ghdr = None
        self._raw_header_bytes = None

    @property
    def global_header(self) -> PcapGlobalHeader:
        if self._ghdr is None:
            raise RuntimeError("PCAP not open")
        return self._ghdr

    @property
    def raw_header_bytes(self) -> bytes:
        if self._raw_header_bytes is None:
            raise RuntimeError("PCAP not open")
        return self._raw_header_bytes

    def read_next_packet(self) -> RawPacket | None:
        if self._fp is None or self._ghdr is None:
            return None

        hdr = self._fp.read(16)
        if len(hdr) != 16:
            return None

        fmt = ">IIII" if self._needs_swap else "<IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, hdr)
        if incl_len > self._ghdr.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._fp.read(incl_len)
        if len(data) != incl_len:
            print("Error: Could not read packet data")
            return None

        return RawPacket(PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len), data)

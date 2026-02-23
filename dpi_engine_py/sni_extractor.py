from __future__ import annotations

from typing import Optional


def _u16_be(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off + 1]


def _u24_be(b: bytes, off: int) -> int:
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    if len(payload) < 9:
        return False
    if payload[0] != 0x16:
        return False
    version = _u16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False
    rec_len = _u16_be(payload, 3)
    if rec_len > len(payload) - 5:
        return False
    if payload[5] != 0x01:
        return False
    return True


def extract_sni(payload: bytes) -> Optional[str]:
    if not is_tls_client_hello(payload):
        return None

    off = 5
    _ = _u24_be(payload, off + 1)  # handshake length
    off += 4
    off += 2  # client version
    off += 32  # random
    if off >= len(payload):
        return None

    sid_len = payload[off]
    off += 1 + sid_len
    if off + 2 > len(payload):
        return None

    ciphers_len = _u16_be(payload, off)
    off += 2 + ciphers_len
    if off >= len(payload):
        return None

    comp_len = payload[off]
    off += 1 + comp_len
    if off + 2 > len(payload):
        return None

    exts_len = _u16_be(payload, off)
    off += 2
    exts_end = min(off + exts_len, len(payload))

    while off + 4 <= exts_end:
        ext_type = _u16_be(payload, off)
        ext_len = _u16_be(payload, off + 2)
        off += 4
        if off + ext_len > exts_end:
            break
        if ext_type == 0x0000:
            if ext_len < 5:
                break
            sni_list_len = _u16_be(payload, off)
            if sni_list_len < 3:
                break
            sni_type = payload[off + 2]
            sni_len = _u16_be(payload, off + 3)
            if sni_type != 0x00:
                break
            if sni_len > ext_len - 5:
                break
            raw = payload[off + 5 : off + 5 + sni_len]
            try:
                return raw.decode("ascii", errors="ignore")
            except Exception:
                return None
        off += ext_len

    return None


def is_http_request(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    return payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def extract_http_host(payload: bytes) -> Optional[str]:
    if not is_http_request(payload):
        return None
    lower = payload.lower()
    idx = lower.find(b"\r\nhost:")
    if idx < 0:
        idx = lower.find(b"host:")
        if idx != 0:
            return None
    start = idx + (7 if lower[idx:idx + 2] == b"\r\n" else 5)
    while start < len(payload) and payload[start:start + 1] in (b" ", b"\t"):
        start += 1
    end = start
    while end < len(payload) and payload[end:end + 1] not in (b"\r", b"\n"):
        end += 1
    if end <= start:
        return None
    host = payload[start:end].decode("ascii", errors="ignore")
    if ":" in host:
        host = host.split(":", 1)[0]
    return host or None

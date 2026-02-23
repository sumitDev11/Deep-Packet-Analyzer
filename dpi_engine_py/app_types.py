from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AppType(Enum):
    UNKNOWN = 0
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


APP_LABELS = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    return APP_LABELS.get(app, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    s = sni.lower()

    if any(x in s for x in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE
    if any(x in s for x in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE
    if any(x in s for x in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK
    if any(x in s for x in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM
    if any(x in s for x in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP
    if any(x in s for x in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER
    if any(x in s for x in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX
    if any(x in s for x in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON
    if any(x in s for x in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")):
        return AppType.MICROSOFT
    if any(x in s for x in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE
    if any(x in s for x in ("telegram", "t.me")):
        return AppType.TELEGRAM
    if any(x in s for x in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK
    if any(x in s for x in ("spotify", "scdn.co")):
        return AppType.SPOTIFY
    if "zoom" in s:
        return AppType.ZOOM
    if any(x in s for x in ("discord", "discordapp")):
        return AppType.DISCORD
    if any(x in s for x in ("github", "githubusercontent")):
        return AppType.GITHUB
    if any(x in s for x in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    return AppType.HTTPS


def parse_ipv4_to_le_int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    out = 0
    for i, p in enumerate(parts):
        try:
            out |= (int(p) & 0xFF) << (8 * i)
        except ValueError:
            return 0
    return out


def format_le_int_ipv4(ip: int) -> str:
    return ".".join(str((ip >> shift) & 0xFF) for shift in (0, 8, 16, 24))


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FiveTuple":
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def to_string(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{format_le_int_ipv4(self.src_ip)}:{self.src_port}"
            f" -> {format_le_int_ipv4(self.dst_ip)}:{self.dst_port} ({proto})"
        )


def five_tuple_hash(t: FiveTuple) -> int:
    h = 0
    fields = (t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.protocol)
    for f in fields:
        h ^= int(f) + 0x9E3779B9 + ((h << 6) & 0xFFFFFFFFFFFFFFFF) + (h >> 2)
    return h & 0xFFFFFFFFFFFFFFFF

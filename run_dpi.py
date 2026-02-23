from __future__ import annotations

import argparse
from typing import List

from dpi_engine_py.engine import DPIEngine, Config


def _split_csv(value: str) -> List[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def _prompt(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    out = input(f"{prompt}{suffix}: ").strip()
    return out if out else default


def _run_interactive() -> int:
    print("\nInteractive DPI Mode\n")
    input_pcap = _prompt("Input PCAP path", ".\\test_dpi.pcap")
    output_pcap = _prompt("Output PCAP path", ".\\output_py.pcap")

    lbs_raw = _prompt("Load balancer threads (--lbs)", "2")
    fps_raw = _prompt("Fast-path threads per LB (--fps)", "2")
    try:
        lbs = max(1, int(lbs_raw))
        fps = max(1, int(fps_raw))
    except ValueError:
        print("Invalid thread values. Use integers.")
        return 1

    print("\nOptional blocking rules (comma-separated, leave empty to skip):")
    block_ips = _split_csv(_prompt("Block IPs", ""))
    block_apps = _split_csv(_prompt("Block apps (e.g. YouTube,Facebook)", ""))
    block_domains = _split_csv(_prompt("Block domains (substring match)", ""))

    print("\nStarting DPI processing...\n")
    cfg = Config(num_lbs=lbs, fps_per_lb=fps)
    engine = DPIEngine(cfg)
    for ip in block_ips:
        engine.block_ip(ip)
    for app in block_apps:
        engine.block_app(app)
    for dom in block_domains:
        engine.block_domain(dom)

    if not engine.process(input_pcap, output_pcap):
        return 1
    print(f"\nOutput written to: {output_pcap}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DPI Engine v2.0 - Multi-threaded Deep Packet Inspection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input_pcap", nargs="?")
    parser.add_argument("output_pcap", nargs="?")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    parser.add_argument("--interactive", action="store_true", help="Run interactive prompt mode")
    args = parser.parse_args()

    if args.interactive or (args.input_pcap is None and args.output_pcap is None):
        return _run_interactive()

    if not args.input_pcap or not args.output_pcap:
        parser.error("input_pcap and output_pcap are required in non-interactive mode")

    cfg = Config(num_lbs=args.lbs, fps_per_lb=args.fps)
    engine = DPIEngine(cfg)
    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for dom in args.block_domain:
        engine.block_domain(dom)

    if not engine.process(args.input_pcap, args.output_pcap):
        return 1
    print(f"\nOutput written to: {args.output_pcap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

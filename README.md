# DPI Engine (Python Only)

This project is now fully Python.

## Requirements

- Python 3.10+ (tested on Python 3.13)
- No third-party packages required

## Project Layout

- `run_dpi.py`: main DPI engine CLI
- `analyze_pcap.py`: packet analyzer CLI
- `dpi_engine_py/`: core engine modules
- `generate_test_pcap.py`: test PCAP generator
- `test_dpi.pcap`: sample input capture

## Run DPI Engine

```powershell
cd X:\Packet_analyzer-main
python .\run_dpi.py .\test_dpi.pcap .\output_py.pcap --block-app YouTube
```

Interactive mode:

```powershell
python .\run_dpi.py --interactive
```

### Blocking Options

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain_substring>`
- repeat flags multiple times if needed

### Thread Options

- `--lbs <n>`: load balancer threads
- `--fps <n>`: fast-path threads per LB

## Run Packet Analyzer

```powershell
python .\analyze_pcap.py .\test_dpi.pcap 10
```

## Core Features

- PCAP parsing
- Ethernet/IPv4/TCP/UDP parsing
- TLS ClientHello SNI extraction
- HTTP Host extraction
- Flow tracking (5-tuple)
- Rule-based blocking
- Multi-threaded pipeline:
  - Reader -> LB threads -> FP threads -> Output writer
- Filtered PCAP output generation

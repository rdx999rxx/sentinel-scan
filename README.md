# SentinelScan

SentinelScan is a Python-based network scanning and asset enumeration tool built around Nmap.

## Features

- Host discovery
- TCP port scanning
- Service and version detection
- Basic port risk classification
- JSON report generation
- CSV report generation
- Command-line interface

## Architecture

Nmap
  ↓
XML Output
  ↓
Python Parser
  ↓
Risk Classification
  ↓
JSON / CSV Reports

## Requirements

- Python 3
- Nmap

## Installation

```bash
git clone YOUR_REPOSITORY_URL
cd sentinel-scan

python3 -m venv venv
source venv/bin/activate


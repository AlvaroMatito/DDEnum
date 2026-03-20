# DDEnum

DDEnum is a Python-based enumeration tool that performs TCP port scanning and launches context-aware enumeration modules based on the detected services.

It is designed to speed up early-stage reconnaissance by combining:
- port discovery
- basic service guessing
- banner grabbing
- web fingerprinting
- DNS enumeration
- SMB/Active Directory-oriented enrichment

## Features

- Concurrent TCP port scanning
- Scan of common ports or all 65535 TCP ports
- Basic banner grabbing
- Service guessing based on well-known ports
- Automatic enumeration modules:
  - `whatweb` for HTTP/HTTPS services
  - `dig` for DNS services
  - `nxc smb` for SMB targets
- Basic detection of AD-related ports
- Multiple output formats:
  - `json`
  - `plain`
  - `both`

## How it works

DDEnum follows a simple workflow:

1. Resolve the target IP or hostname
2. Scan TCP ports
3. Identify open ports
4. Guess likely services
5. Trigger additional modules depending on exposed services
6. Save the results in a machine-readable or human-readable format

## Requirements

- Python 3.10+ recommended
- External tools for enrichment modules:
  - `whatweb`
  - `dig`
  - `nxc`

If one of these tools is not installed, DDEnum will continue running and report that the dependency was not found.

## Installation

Clone the repository:

```bash
git clone https://github.com/AlvaroMatito/DDEnum
cd DDEnum

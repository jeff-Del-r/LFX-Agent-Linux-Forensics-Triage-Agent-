[🇪🇸 Leer en Español](README_ES.md)

# LFX-Agent (Linux Forensics & Triage Agent)

**LFX-Agent** is a lightweight, modular Python CLI tool designed for rapid incident response and digital forensics in Linux environments. It automates volatile memory triage, detects execution anomalies via `/proc`, audits common persistence vectors, and verifies system binary integrity—all using zero-to-minimal external dependencies.

---

## Key Features

* **Volatile Memory & Process Inspection (`memory_proc`):**
  * Detects stealthy execution via unlinked binaries (`/proc/<PID>/exe` marked as `deleted`).
  * Inspects file descriptors (`/proc/<PID>/fd`) for hidden sockets, pipe connections, or deleted payloads in `/tmp` and `/dev/shm`.
  * Audits process environment variables (`/proc/<PID>/environ`) for malicious dynamic library injection (`LD_PRELOAD`).

* **Persistence Vector Auditing (`persistence`):**
  * Audits user and system CRON jobs (`/etc/crontab`, `/var/spool/cron/crontabs/`, `/etc/cron.*`).
  * Scans active `systemd` timers and custom user services.
  * Checks unauthorized key injections in `~/.ssh/authorized_keys` across all system accounts.
  * Inspects shell startup files (`.bashrc`, `.profile`) and global preload files (`/etc/ld.so.preload`).

* **Network & Socket Correlation (`network`):**
  * Correlates active TCP/UDP network connections directly to originating Process IDs (PIDs).
  * Flags network interfaces operating in promiscuous mode (`PROMISC`).

* **System Binary Integrity Check (`integrity`):**
  * Computes SHA-256 hashes of critical binaries (`/bin/bash`, `/bin/ls`, `/bin/ps`, `/bin/ss`) to detect rootkit modifications.

* **Structured Reporting:**
  * Outputs clear console logs during execution.
  * Exports machine-readable JSON reports (`--json`) designed for direct SIEM ingestion (Wazuh, Elastic, Splunk).

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | LFX-Agent Module | Detection Trigger |
| :--- | :--- | :--- | :--- |
| **T1070.004** | Indicator Removal: File Deletion | `memory_proc` | Process running from an unlinked binary (`(deleted)` pointer). |
| **T1574.006** | Hijack Execution Flow: LD_PRELOAD | `memory_proc` / `persistence` | `LD_PRELOAD` detected in process environment or `/etc/ld.so.preload`. |
| **T1053.003** | Scheduled Task/Job: Cron | `persistence` | Non-standard or newly added entries in system/user crontabs. |
| **T1543.002** | Create/Modify System Process: Systemd | `persistence` | Suspicious systemd service or timer unit files. |
| **T1098.004** | Account Manipulation: SSH Authorized Keys | `persistence` | Unrecognized public keys appended to `authorized_keys`. |

---

## Project Structure

```text
lfx-agent/
├── docs/
│   ├── architecture.png    # High-level architecture flow
│   └── mitre_mapping.md    # Detailed MITRE ATT&CK alignment
├── lfx_agent/              # Main application package
│   ├── __init__.py
│   ├── cli.py              # CLI entry point and argument parsing
│   ├── core/
│   │   ├── collector.py    # Collection orchestrator
│   │   └── reporter.py     # JSON and Console output generators
│   └── modules/
│       ├── memory_proc.py  # /proc filesystem inspector
│       ├── network.py      # Socket & network artifact collector
│       ├── persistence.py  # Cron, systemd, and SSH auditor
│       └── integrity.py    # Binary SHA-256 hasher
├── tests/                  # Unit test suite
├── LICENSE                 # MIT License
├── README.md               # English Documentation
├── README_ES.md            # Documentación en Español
└── requirements.txt        # Optional dependencies (e.g., rich, psutil)
```

---

## Quick Start

### Prerequisites
* Linux OS (Ubuntu, Debian, Arch Linux, RHEL, CachyOS, etc.)
* Python 3.8+
* Root/Sudo privileges (required for accessing `/proc/<PID>/environ` and all user crontabs).

### Installation

```bash
git clone [https://github.com/YOUR_USERNAME/lfx-agent.git](https://github.com/YOUR_USERNAME/lfx-agent.git)
cd lfx-agent

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Usage Examples

```bash
sudo python3 -m lfx_agent.cli --all

sudo python3 -m lfx_agent.cli --module memory persistence --json report.json

python3 -m lfx_agent.cli --help
```

---

## Sample JSON Output

```json
{
  "scan_metadata": {
    "timestamp": "2026-08-17T09:40:00Z",
    "hostname": "target-server",
    "agent_version": "0.1.0"
  },
  "findings": [
    {
      "module": "memory_proc",
      "pid": 4096,
      "severity": "CRITICAL",
      "issue": "Process running from deleted executable",
      "executable_path": "/tmp/netcat (deleted)",
      "command_line": "/tmp/netcat -lvp 4444 -e /bin/bash",
      "mitre_id": "T1070.004"
    }
  ]
}
```

---

## License

Distributed under the MIT License. See `LICENSE` for more information.

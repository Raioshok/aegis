# In-Guest Telemetry & Training Gateway (`aegis-daemon`)

The Aegis daemon hosts an asynchronous HTTP microservice on **port 9090** designed for autonomous malware detonation and telemetry synchronization across isolated Hyper-V guest virtual machines and WSL2 sandboxes.

---

## 1. Gateway Network Topology

```text
                  Windows Host Machine (Hyper-V Root Partition)
            +-------------------------------------------------------+
            |  Aegis Host Daemon & Telemetry Gateway (:9090)        |
            |  Endpoints:                                           |
            |    • http://127.0.0.1:9090                            |
            |    • http://172.31.0.1:9090   (Hyper-V vSwitch)       |
            |    • http://172.18.32.1:9090  (WSL2 vEthernet)        |
            +---------------------------+---------------------------+
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             │                                                     │
             v                                                     v
+-----------------------------+               +-----------------------------+
|   Hyper-V Lab VM            |               |   WSL2 Sandbox Distro       |
|   Aegis-Lab-Ubuntu          |               |   Ubuntu 26.04 Standard     |
|   IP: 172.31.6.23           |               |   IP: 172.18.32.x           |
|                             |               |                             |
|   Dynamic Detonation Runner |               |   Landlock/Seccomp Runner   |
|   (sandbox_runner.py)       |               |   (sandbox_runner.py)       |
+-----------------------------+               +-----------------------------+
```

---

## 2. Gateway API Endpoints

### `GET /health`
Returns gateway operational status and active engine components.
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_secs": 1842
}
```

### `GET /train.py` & `GET /train.sh`
Delivers the automated in-guest dynamic detonation script. Guest VMs can bootstrap and begin detonation runs with a single command:
```bash
curl -s http://172.31.0.1:9090/train.sh | bash
```

### `POST /api/v1/telemetry/report`
Ingests dynamic execution logs and IoCs from guest sandboxes.
* **Payload Structure (`TelemetryReport`)**:
  ```json
  {
    "guest_os": "Ubuntu 26.04 LTS (WSL2)",
    "test_id": "det-20261021-0914",
    "sample_name": "Wiper/HermeticWiper.exe",
    "sample_sha256": "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf",
    "detected": true,
    "detections": [
      {
        "engine": "YARA",
        "threat": "Wiper_Hermetic_Caddy_DriveZero",
        "severity": "Critical",
        "detail": "HermeticWiper raw drive access and partition table destruction"
      }
    ],
    "countermeasures_triggered": ["ChaChaQuarantine", "LandlockBlock"],
    "missed_evasion_indicators": [],
    "timestamp": 1792576440
  }
  ```

### `POST /api/v1/train/feedback`
Feeds newly discovered threat hashes and evasion indicators directly into the threat database cache.

### `GET /api/v1/telemetry/stats`
Returns aggregated laboratory execution statistics.
```json
{
  "total_reports": 31,
  "detected_count": 20,
  "missed_count": 11,
  "detection_rate_pct": 64.5,
  "recent_threats": [
    "HMBlocker.exe",
    "SuperDeath2.exe",
    "FritzFrog Botnet",
    "NoEscape.exe"
  ]
}
```

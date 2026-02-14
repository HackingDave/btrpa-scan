# btrpa-scan

A Bluetooth Low Energy (BLE) scanner with advanced Resolvable Private Address (RPA) resolution. Discover nearby BLE devices, track a specific device by MAC address, or resolve privacy-randomized addresses using an Identity Resolving Key (IRK).

**Written by:** David Kennedy ([@HackingDave](https://twitter.com/HackingDave))
**Company:** [TrustedSec](https://www.trustedsec.com)

## Features

- **Discover All Devices** - Scan for all broadcasting BLE devices in range with signal strength, estimated distance, manufacturer data, and service UUIDs
- **Targeted Search** - Search for a specific device by MAC address and monitor every detection
- **IRK Resolution** - Resolve Resolvable Private Addresses against a known Identity Resolving Key to identify a device using randomized addresses for privacy
- **RSSI Filtering** - Filter out weak signals with a minimum RSSI threshold
- **RSSI Averaging** - Sliding window average smooths noisy BLE RSSI readings for more stable distance estimates
- **Active Scanning** - Send SCAN_REQ to get SCAN_RSP with additional service UUIDs and device names that passive scanning misses
- **Environment Presets** - Indoor, outdoor, and free-space path-loss models for more accurate distance estimation
- **Proximity Alerts** - Audible/visual alert when a device is estimated within a configurable distance
- **Live TUI** - Curses-based live-updating table sorted by signal strength
- **Real-Time CSV Log** - Stream each detection to a CSV file as it happens
- **Batch Export** - Export results to CSV, JSON, or JSONL at end of scan
- **GPS Location Stamping** - Tag each detection with GPS coordinates via gpsd; tracks per-device best location (strongest RSSI = closest proximity). On by default, degrades gracefully if gpsd is unavailable
- **Multi-Adapter** - Scan with multiple Bluetooth adapters simultaneously (Linux)
- **Verbose/Quiet Modes** - Verbose mode shows additional details (e.g. non-matching RPAs in IRK mode); quiet mode suppresses per-device output and shows only the summary

## Requirements

- Python 3.7+
- Bluetooth hardware
- OS support: macOS, Linux, Windows
- **gpsd** (optional) — required for GPS location stamping

### Installing gpsd

GPS location stamping requires the `gpsd` daemon running with a connected GPS receiver. If gpsd is not running, btrpa-scan continues normally without GPS.

| Platform | Install | Start |
|----------|---------|-------|
| **macOS** | `brew install gpsd` | `gpsd -n /dev/tty.usbserial-*` |
| **Debian/Ubuntu** | `sudo apt install gpsd gpsd-clients` | `sudo systemctl start gpsd` |
| **Fedora/RHEL** | `sudo dnf install gpsd gpsd-clients` | `sudo systemctl start gpsd` |
| **Arch** | `sudo pacman -S gpsd` | `sudo systemctl start gpsd` |
| **Windows** | Use gpsd via WSL or MSYS2 | See WSL instructions above |

To verify gpsd is working:

```bash
# Check that gpsd is listening
gpspipe -w -n 5
# Or use the curses monitor
cgps
```

### Platform Notes

| Platform | Notes |
|----------|-------|
| **macOS** | Uses CoreBluetooth. IRK mode leverages an undocumented API to retrieve real Bluetooth addresses instead of UUIDs. |
| **Linux** | May require `root` or `CAP_NET_ADMIN` capability for scanning. |
| **Windows** | Native WinRT Bluetooth API — real MAC addresses available natively. TUI requires `pip install windows-curses`. |

## Installation

```bash
git clone https://github.com/hackingdave/btrpa-scan.git
cd btrpa-scan
pip install -r requirements.txt
```

## Usage

```
usage: btrpa-scan.py [-h] [-a] [--irk HEX] [-t TIMEOUT]
                     [--output {csv,json,jsonl}] [-o FILE] [--log FILE]
                     [-v | -q] [--min-rssi DBM] [--rssi-window N] [--active]
                     [--environment {free_space,indoor,outdoor}]
                     [--alert-within METERS] [--tui] [--no-gps]
                     [--adapters LIST] [mac]

BLE Scanner — discover all devices or hunt for a specific one

positional arguments:
  mac                   Target MAC address to search for (omit to scan all)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Scan for all broadcasting devices
  --irk HEX             Resolve RPAs using this Identity Resolving Key (32 hex chars)
  -t, --timeout TIMEOUT Scan timeout in seconds (default: 30, or infinite for --irk)
  --output {csv,json,jsonl}
                        Batch output format written at end of scan
  -o, --output-file FILE
                        Output file path (default: btrpa-scan-results.<format>)
  --log FILE            Stream detections to a CSV file in real time
  -v, --verbose         Verbose mode — show additional details
  -q, --quiet           Quiet mode — suppress per-device output, show summary only
  --min-rssi DBM        Minimum RSSI threshold (e.g. -70) — ignore weaker signals
  --rssi-window N       RSSI sliding window size for averaging (default: 1 = no averaging)
  --active              Use active scanning (sends SCAN_REQ for additional data)
  --environment {free_space,indoor,outdoor}
                        Distance estimation path-loss model (default: free_space)
  --alert-within METERS Proximity alert when device is within this distance
  --tui                 Live-updating terminal table instead of scrolling output
  --no-gps              Disable GPS location stamping (GPS is on by default via gpsd)
  --adapters LIST       Comma-separated Bluetooth adapter names (e.g. hci0,hci1)
```

### Mode 1: Discover All Devices

Scan for all broadcasting BLE devices (default 30-second timeout):

```bash
python3 btrpa-scan.py --all
```

With a custom timeout:

```bash
python3 btrpa-scan.py --all -t 60
```

### Mode 2: Targeted Search

Search for a specific device by MAC address:

```bash
python3 btrpa-scan.py AA:BB:CC:DD:EE:FF
```

### Mode 3: IRK Resolution

Resolve Resolvable Private Addresses using an Identity Resolving Key. This mode runs indefinitely by default until stopped with `Ctrl+C`:

```bash
python3 btrpa-scan.py --irk 0123456789ABCDEF0123456789ABCDEF
```

The IRK can be provided in several formats:

| Format | Example |
|--------|---------|
| Plain hex | `0123456789ABCDEF0123456789ABCDEF` |
| Colon-separated | `01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF` |
| Dash-separated | `01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF` |
| 0x-prefixed | `0x0123456789ABCDEF0123456789ABCDEF` |

### RSSI Filtering

Only show devices with signal strength above a threshold:

```bash
python3 btrpa-scan.py --all --min-rssi -70
```

### RSSI Averaging

BLE RSSI is inherently noisy. Use a sliding window average for more stable distance estimates and to filter out spurious weak detections:

```bash
python3 btrpa-scan.py --all --rssi-window 5
```

When windowing is active, the display shows both raw and averaged RSSI (e.g. `RSSI: -65 dBm (avg: -62 dBm over 5 readings)`), and distance estimation uses the averaged value. The `--min-rssi` filter also applies to the averaged RSSI, preventing a single noisy spike from dropping a device.

### Active Scanning

Passive scanning (the default) only sees advertisements. Active scanning sends `SCAN_REQ` and gets `SCAN_RSP`, which can reveal additional service UUIDs and device names:

```bash
python3 btrpa-scan.py --all --active
```

> **Note:** On macOS, CoreBluetooth always scans actively regardless of this flag. On Linux/BlueZ, active scanning may require root or `CAP_NET_ADMIN`.

### Environment Presets

Distance estimation uses a path-loss exponent that varies by environment. The default (`free_space`, n=2.0) assumes no obstructions. For more realistic estimates indoors:

```bash
python3 btrpa-scan.py --all --environment indoor
```

| Preset | Path-Loss Exponent (n) | Use Case |
|--------|------------------------|----------|
| `free_space` | 2.0 | Open air, line of sight |
| `outdoor` | 2.2 | Parks, parking lots |
| `indoor` | 3.0 | Offices, homes, buildings |

Higher `n` values produce larger distance estimates for the same RSSI, reflecting signal attenuation from walls and obstacles.

### Proximity Alerts

Trigger an audible bell and visual alert when a device is estimated within a given distance. Requires that the target device advertise TX Power:

```bash
python3 btrpa-scan.py AA:BB:CC:DD:EE:FF --alert-within 5.0
```

Works in all modes including IRK resolution:

```bash
python3 btrpa-scan.py --irk <key> --alert-within 3.0
```

### Live TUI

Replace scrolling output with a live-updating terminal table, sorted by signal strength:

```bash
python3 btrpa-scan.py --all --tui
```

The TUI shows all detected devices in a compact table with address, name, RSSI, averaged RSSI, estimated distance, detection count, and last-seen time. Resolved IRK matches are shown in bold, and devices within the `--alert-within` threshold are highlighted.

Combine with other flags:

```bash
python3 btrpa-scan.py --irk <key> --tui --rssi-window 5 --environment indoor --alert-within 5.0
```

### Real-Time CSV Log

Stream each detection to a CSV file as it happens (useful for long-running scans where you want incremental data):

```bash
python3 btrpa-scan.py --all --log scan.csv
```

This can be combined with `--output` for a separate batch export:

```bash
python3 btrpa-scan.py --all --log live.csv --output json -o results.json
```

### Batch Export

Export all results at end of scan in CSV, JSON, or JSONL (JSON Lines) format:

```bash
python3 btrpa-scan.py --all --output json -o results.json -t 30
python3 btrpa-scan.py --all --output csv -t 30
python3 btrpa-scan.py --all --output jsonl -o results.jsonl -t 30
```

JSONL writes one JSON object per line, making it easy to pipe through `jq`:

```bash
python3 btrpa-scan.py --all --output jsonl -o results.jsonl -t 10
cat results.jsonl | jq .
```

### Multi-Adapter Scanning (Linux)

Scan with multiple Bluetooth adapters simultaneously for wider coverage:

```bash
python3 btrpa-scan.py --all --adapters hci0,hci1
```

Each adapter runs its own scanner instance sharing the same detection callback. All detections are merged into a single output.

### GPS Location Stamping

GPS is **on by default**. Each detection is tagged with the current GPS coordinates from gpsd. The scanner also tracks the **best GPS fix per device** — the coordinates from the detection with the strongest RSSI (closest proximity = most accurate location).

If gpsd is not running, the scanner prints a note and continues normally without GPS:

```bash
# With gpsd running — detections include lat/lon
python3 btrpa-scan.py --all --output json

# Without gpsd — works fine, GPS fields are empty
python3 btrpa-scan.py --all

# Explicitly disable GPS (skips connection attempt)
python3 btrpa-scan.py --all --no-gps
```

GPS coordinates appear in:
- **Console output** — "Best GPS" line per device
- **TUI settings bar** — current fix coordinates
- **Header** — GPS connection status
- **Summary tables** — "Best GPS" column per device
- **All exports** (CSV, JSON, JSONL, real-time log) — `latitude`, `longitude`, `gps_altitude` fields

### Quiet and Verbose Modes

Run in quiet mode (summary only, no per-device output — useful with `--output` or `--log`):

```bash
python3 btrpa-scan.py --all -q --output json -t 30
```

Run in verbose mode (show non-matching RPAs in IRK mode):

```bash
python3 btrpa-scan.py --irk 0123456789ABCDEF0123456789ABCDEF -v
```

## How RPA Resolution Works

Bluetooth Low Energy devices use Resolvable Private Addresses (RPAs) to prevent tracking. An RPA is a temporary MAC address that changes periodically, but can be resolved by anyone who possesses the device's Identity Resolving Key (IRK).

An RPA consists of:
- **prand** (3 bytes) - A random value with the top two bits set to `01`
- **hash** (3 bytes) - Computed as `AES-128-ECB(IRK, padding || prand)` truncated to 3 bytes

btrpa-scan implements the `ah()` function from the Bluetooth Core Specification (Vol 3, Part H, Section 2.2.2) to resolve these addresses in real time.

## Example Output

```
Mode: DISCOVER ALL - showing every broadcasting device
Scanning: passive
GPS: connected (37.774929, -122.419418)
Timeout: 30s  |  Press Ctrl+C to stop
------------------------------------------------------------

============================================================
  DEVICE #1  -  seen 1x
============================================================
  Address      : AA:BB:CC:DD:EE:FF
  Name         : MyDevice
  RSSI         : -45 dBm
  TX Power     : -59 dBm
  Est. Distance: ~0.4 m
  Manufacturer : 0x004C -> 0215abcdef
  Best GPS     : 37.774929, -122.419418
  Timestamp    : 14:32:07
============================================================

------------------------------------------------------------
Scan complete - 30.0s elapsed
  Total detections : 142
  Unique devices   : 12
  Results written to btrpa-scan-results.json
```

## Stopping a Scan

Press `Ctrl+C` at any time to gracefully stop the scan and display summary statistics.


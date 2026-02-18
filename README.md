# btrpa-scan

A Bluetooth Low Energy (BLE) scanner with advanced Resolvable Private Address (RPA) resolution. Discover nearby BLE devices, track a specific device by MAC address, or resolve privacy-randomized addresses using an Identity Resolving Key (IRK).

**Written by:** David Kennedy ([@HackingDave](https://twitter.com/HackingDave))
**Company:** [TrustedSec](https://www.trustedsec.com)

## Features

- **Discover All Devices** - Scan for all broadcasting BLE devices in range with signal strength, estimated distance, manufacturer data, and service UUIDs
- **Targeted Search** - Search for a specific device by MAC address and monitor every detection
- **IRK Resolution** - Resolve Resolvable Private Addresses against one or more Identity Resolving Keys to identify devices using randomized addresses for privacy
- **Multiple IRKs** - Load multiple IRKs from a file to resolve addresses for several devices in a single scan
- **RSSI Filtering** - Filter out weak signals with a minimum RSSI threshold
- **RSSI Averaging** - Sliding window average smooths noisy BLE RSSI readings for more stable distance estimates
- **Name Filtering** - Filter devices by name with case-insensitive substring matching
- **Active Scanning** - Send SCAN_REQ to get SCAN_RSP with additional service UUIDs and device names that passive scanning misses
- **Environment Presets** - Indoor, outdoor, and free-space path-loss models for more accurate distance estimation
- **Proximity Alerts** - Audible/visual alert when a device is estimated within a configurable distance
- **Web GUI** - Browser-based radar interface with animated sweep, distance visualization, GPS map, signal-strength device list with pin/unpin, and hover tooltips
- **Live TUI** - Curses-based live-updating table sorted by signal strength
- **Real-Time CSV Log** - Stream each detection to a CSV file as it happens
- **Batch Export** - Export results to CSV, JSON, or JSONL at end of scan (supports stdout with `-o -`)
- **GPS Location Stamping** - Tag each detection with GPS coordinates via gpsd; tracks per-device best location (strongest RSSI = closest proximity). On by default, degrades gracefully if gpsd is unavailable
- **Multi-Adapter** - Scan with multiple Bluetooth adapters simultaneously (Linux)
- **Verbose/Quiet Modes** - Verbose mode shows additional details (e.g. non-matching RPAs in IRK mode); quiet mode suppresses per-device output and shows only the summary

## Requirements

- Python 3.9+
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
| **macOS** | Uses CoreBluetooth. IRK mode leverages an undocumented API to retrieve real Bluetooth addresses instead of UUIDs. `--active` has no effect — CoreBluetooth always scans actively. |
| **Linux** | May require `root` or `CAP_NET_ADMIN` capability for scanning. |
| **Windows** | Native WinRT Bluetooth API — real MAC addresses available natively. TUI requires `pip install windows-curses`. |

## Installation

This project uses `pyproject.toml` ([PEP 621](https://peps.python.org/pep-0621/)), the modern Python packaging standard. It defines the project as an installable package with a registered CLI command — no need to run `.py` files directly.

### Quick Run (no install)

```bash
uvx btrpa-scan --all
```

### Run from GitHub (no install)

```bash
uvx --from git+https://github.com/hackingdave/btrpa-scan.git btrpa-scan --all
```

### Install as a Tool

```bash
uv tool install btrpa-scan
```

Or directly from GitHub:

```bash
uv tool install git+https://github.com/hackingdave/btrpa-scan.git
```

### Install via pip

```bash
pip install btrpa-scan
```

For GUI support (Flask-based radar interface):

```bash
pip install btrpa-scan[gui]
```

### From Source

```bash
git clone https://github.com/hackingdave/btrpa-scan.git
cd btrpa-scan
pip install .
```

## Usage

```
usage: btrpa-scan [-h] [-a] [--irk HEX] [--irk-file PATH] [-t TIMEOUT]
                     [--output {csv,json,jsonl}] [-o FILE] [--log FILE]
                     [-v | -q] [--min-rssi DBM] [--rssi-window N] [--active]
                     [--environment {free_space,indoor,outdoor}]
                     [--ref-rssi DBM] [--name-filter PATTERN]
                     [--alert-within METERS] [--tui] [--gui] [--gui-port PORT]
                     [--no-gps] [--adapters LIST] [mac]

BLE Scanner — discover all devices or hunt for a specific one

positional arguments:
  mac                   Target MAC address to search for (omit to scan all)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Scan for all broadcasting devices
  --irk HEX             Resolve RPAs using this Identity Resolving Key (32 hex chars)
  --irk-file PATH       Read IRK(s) from a file (one per line, hex format)
  -t, --timeout TIMEOUT Scan timeout in seconds (default: 30, or infinite for --irk)
  --output {csv,json,jsonl}
                        Batch output format written at end of scan
  -o, --output-file FILE
                        Output file path (default: btrpa-scan-results.<format>;
                        use - for stdout)
  --log FILE            Stream detections to a CSV file in real time
  -v, --verbose         Verbose mode — show additional details
  -q, --quiet           Quiet mode — suppress per-device output, show summary only
  --min-rssi DBM        Minimum RSSI threshold (e.g. -70) — ignore weaker signals
  --rssi-window N       RSSI sliding window size for averaging (default: 1 = no averaging)
  --active              Use active scanning (sends SCAN_REQ for additional data)
  --environment {free_space,indoor,outdoor}
                        Distance estimation path-loss model (default: free_space)
  --ref-rssi DBM        Calibrated RSSI at 1 metre for distance estimation
  --name-filter PATTERN Filter devices by name (case-insensitive substring match)
  --alert-within METERS Proximity alert when device is within this distance
  --tui                 Live-updating terminal table instead of scrolling output
  --gui                 Launch web-based radar interface in the browser
  --gui-port PORT       Port for GUI web server (default: 5000)
  --no-gps              Disable GPS location stamping (GPS is on by default via gpsd)
  --adapters LIST       Comma-separated Bluetooth adapter names (e.g. hci0,hci1)
```

### Mode 1: Discover All Devices

Scan for all broadcasting BLE devices (default 30-second timeout):

```bash
btrpa-scan --all
```

With a custom timeout:

```bash
btrpa-scan --all -t 60
```

### Mode 2: Targeted Search

Search for a specific device by MAC address:

```bash
btrpa-scan AA:BB:CC:DD:EE:FF
```

### Mode 3: IRK Resolution

Resolve Resolvable Private Addresses using an Identity Resolving Key. This mode runs indefinitely by default until stopped with `Ctrl+C`:

```bash
btrpa-scan --irk 0123456789ABCDEF0123456789ABCDEF
```

The IRK can be provided in several formats:

| Format | Example |
|--------|---------|
| Plain hex | `0123456789ABCDEF0123456789ABCDEF` |
| Colon-separated | `01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF` |
| Dash-separated | `01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF` |
| 0x-prefixed | `0x0123456789ABCDEF0123456789ABCDEF` |

#### IRK from a File

Load one or more IRKs from a file. Each line should contain one IRK in any supported hex format. Lines starting with `#` are treated as comments:

```bash
btrpa-scan --irk-file keys.txt
```

Example `keys.txt`:

```
# Alice's phone
0123456789ABCDEF0123456789ABCDEF
# Bob's watch
FEDCBA9876543210FEDCBA9876543210
```

When multiple IRKs are loaded, each detected RPA is checked against all keys. The summary shows total matches across all keys.

#### IRK from Environment Variable

Set the `BTRPA_IRK` environment variable to avoid passing the key on the command line:

```bash
export BTRPA_IRK=0123456789ABCDEF0123456789ABCDEF
btrpa-scan
```

Priority: `--irk` > `--irk-file` > `BTRPA_IRK`

### RSSI Filtering

Only show devices with signal strength above a threshold:

```bash
btrpa-scan --all --min-rssi -70
```

### RSSI Averaging

BLE RSSI is inherently noisy. Use a sliding window average for more stable distance estimates and to filter out spurious weak detections:

```bash
btrpa-scan --all --rssi-window 5
```

When windowing is active, the display shows both raw and averaged RSSI (e.g. `RSSI: -65 dBm (avg: -62 dBm over 5 readings)`), and distance estimation uses the averaged value. The `--min-rssi` filter also applies to the averaged RSSI, preventing a single noisy spike from dropping a device.

### Name Filtering

Filter devices by name using a case-insensitive substring match:

```bash
btrpa-scan --all --name-filter "AirPods"
```

Only devices whose advertised name contains the given pattern will be shown. Devices with no name are excluded when a name filter is active.

### Active Scanning

Passive scanning (the default) only sees advertisements. Active scanning sends `SCAN_REQ` and gets `SCAN_RSP`, which can reveal additional service UUIDs and device names:

```bash
btrpa-scan --all --active
```

> **Note:** On macOS, CoreBluetooth always scans actively regardless of this flag. On Linux/BlueZ, active scanning may require root or `CAP_NET_ADMIN`.

### Environment Presets

Distance estimation uses a path-loss exponent that varies by environment. The default (`free_space`, n=2.0) assumes no obstructions. For more realistic estimates indoors:

```bash
btrpa-scan --all --environment indoor
```

| Preset | Path-Loss Exponent (n) | Use Case |
|--------|------------------------|----------|
| `free_space` | 2.0 | Open air, line of sight |
| `outdoor` | 2.2 | Parks, parking lots |
| `indoor` | 3.0 | Offices, homes, buildings |

Higher `n` values produce larger distance estimates for the same RSSI, reflecting signal attenuation from walls and obstacles.

### Reference RSSI Calibration

By default btrpa-scan derives the expected RSSI at 1 metre from the advertised TX Power using an empirically validated 59 dB offset (the iBeacon standard). For even better accuracy you can supply a calibrated value measured in your own environment:

1. Place the target device exactly 1 metre from the scanner.
2. Run a short scan and note the average RSSI.
3. Pass that value with `--ref-rssi`:

```bash
btrpa-scan --all --ref-rssi -55
```

When `--ref-rssi` is set, TX Power is ignored entirely. This also enables distance estimates for devices that don't advertise TX Power.

### Proximity Alerts

Trigger an audible bell and visual alert when a device is estimated within a given distance. Requires that the target device advertise TX Power:

```bash
btrpa-scan AA:BB:CC:DD:EE:FF --alert-within 5.0
```

Works in all modes including IRK resolution:

```bash
btrpa-scan --irk <key> --alert-within 3.0
```

### Live TUI

Replace scrolling output with a live-updating terminal table, sorted by signal strength:

```bash
btrpa-scan --all --tui
```

The TUI shows all detected devices in a compact table with address, name, RSSI, averaged RSSI, estimated distance, detection count, and last-seen time. Resolved IRK matches are shown in bold, and devices within the `--alert-within` threshold are highlighted.

Combine with other flags:

```bash
btrpa-scan --irk <key> --tui --rssi-window 5 --environment indoor --alert-within 5.0
```

### Web GUI

Launch a browser-based radar interface with an animated sweep, real-time device tracking, and GPS map:

```bash
btrpa-scan --all --gui
```

The GUI features:

- **Radar display** — animated sweep line with concentric distance rings (1m, 5m, 10m, 20m). Devices appear as color-coded dots positioned by estimated distance (green = close, yellow = medium, red = far). Full-height layout with matrix data rain background and ghost MAC flicker effects
- **Device list** — right-side panel listing all detected devices, color-coded by signal strength. Click any device to pin it for tracking
- **Pinned devices** — left-side panel showing pinned MAC addresses with live RSSI and distance updates. Pin multiple devices simultaneously; click × to unpin
- **GPS map** — Leaflet.js map with OpenStreetMap tiles showing scanner position and device locations. Automatically hidden if no GPS is available
- **Hover tooltips** — hover over any device (radar dot, list entry, or pinned entry) to see full device details (address, name, RSSI, TX power, distance, GPS, manufacturer data, services)
- **Dark theme** — matrix-green hacker aesthetic designed for field work

GUI mode scans continuously by default (no 30-second timeout). Press `Ctrl+C` to stop. Use `-t` to set a specific scan duration:

```bash
# Scan for 60 seconds with indoor path-loss model
btrpa-scan --all --gui -t 60 --environment indoor

# Custom port
btrpa-scan --all --gui --gui-port 8080

# Combine with RSSI averaging and proximity alerts
btrpa-scan --all --gui --rssi-window 5 --alert-within 5.0
```

> **Note:** `--gui` requires Flask and flask-socketio (`pip install btrpa-scan[gui]`). Cannot be combined with `--tui` or `--quiet`.

### Real-Time CSV Log

Stream each detection to a CSV file as it happens (useful for long-running scans where you want incremental data):

```bash
btrpa-scan --all --log scan.csv
```

This can be combined with `--output` for a separate batch export:

```bash
btrpa-scan --all --log live.csv --output json -o results.json
```

### Batch Export

Export all results at end of scan in CSV, JSON, or JSONL (JSON Lines) format:

```bash
btrpa-scan --all --output json -o results.json -t 30
btrpa-scan --all --output csv -t 30
btrpa-scan --all --output jsonl -o results.jsonl -t 30
```

JSONL writes one JSON object per line, making it easy to pipe through `jq`:

```bash
btrpa-scan --all --output jsonl -o results.jsonl -t 10
cat results.jsonl | jq .
```

Write output to stdout for piping:

```bash
btrpa-scan --all --output json -o - -t 10 -q | jq .
```

### Multi-Adapter Scanning (Linux)

Scan with multiple Bluetooth adapters simultaneously for wider coverage:

```bash
btrpa-scan --all --adapters hci0,hci1
```

Each adapter runs its own scanner instance sharing the same detection callback. All detections are merged into a single output.

### GPS Location Stamping

GPS is **on by default**. Each detection is tagged with the current GPS coordinates from gpsd. The scanner also tracks the **best GPS fix per device** — the coordinates from the detection with the strongest RSSI (closest proximity = most accurate location).

If gpsd is not running, the scanner prints a note and continues normally without GPS:

```bash
# With gpsd running — detections include lat/lon
btrpa-scan --all --output json

# Without gpsd — works fine, GPS fields are empty
btrpa-scan --all

# Explicitly disable GPS (skips connection attempt)
btrpa-scan --all --no-gps
```

GPS coordinates appear in:
- **Console output** — "Best GPS" line per device
- **TUI settings bar** — current fix coordinates
- **GUI** — interactive map panel with device markers and scanner position
- **Header** — GPS connection status
- **Summary tables** — "Best GPS" column per device
- **All exports** (CSV, JSON, JSONL, real-time log) — `latitude`, `longitude`, `gps_altitude` fields

### Quiet and Verbose Modes

Run in quiet mode (summary only, no per-device output — useful with `--output` or `--log`):

```bash
btrpa-scan --all -q --output json -t 30
```

Run in verbose mode (show non-matching RPAs in IRK mode):

```bash
btrpa-scan --irk 0123456789ABCDEF0123456789ABCDEF -v
```

## How RPA Resolution Works

Bluetooth Low Energy devices use Resolvable Private Addresses (RPAs) to prevent tracking. An RPA is a temporary MAC address that changes periodically, but can be resolved by anyone who possesses the device's Identity Resolving Key (IRK).

An RPA consists of:
- **prand** (3 bytes) - A random value with the top two bits set to `01`
- **hash** (3 bytes) - Computed as `AES-128-ECB(IRK, padding || prand)` truncated to 3 bytes

btrpa-scan implements the `ah()` function from the Bluetooth Core Specification (Vol 3, Part H, Section 2.2.2) to resolve these addresses in real time.

> **Note on AES-ECB:** The use of AES in ECB mode for the `ah()` function is mandated by the Bluetooth Core Specification. Because only a single 16-byte block is ever encrypted, ECB's lack of diffusion across blocks is irrelevant — this is not a vulnerability.

## Security Considerations

- **IRK on the command line:** Command-line arguments are visible to other users on the system via `ps`. To avoid exposing the IRK, use `--irk-file` to read from a file, or set the `BTRPA_IRK` environment variable. Console output masks IRKs by default (showing only the first and last 4 hex characters).
- **GPS coordinates in exports:** All export formats (CSV, JSON, JSONL) and console output include GPS coordinates when available. If sharing scan results, be aware that your location may be disclosed. Use `--no-gps` to disable GPS entirely.
- **Output file paths:** The `--output-file` and `--log` options write to the specified path. Ensure the destination has appropriate permissions for your use case.

## Running Tests

```bash
pip install pytest
python -m pytest test_btrpa_scan.py -v
```

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

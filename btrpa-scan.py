#!/usr/bin/env python3
#
# btrpa-scan - Bluetooth Low Energy (BLE) Scanner with RPA Resolution
#
# Written by: David Kennedy (@HackingDave)
# Company:    TrustedSec
# Website:    https://www.trustedsec.com
#
# A BLE scanner that discovers broadcasting devices, searches for specific
# targets by MAC address, and resolves Resolvable Private Addresses (RPAs)
# using Identity Resolving Keys (IRKs) per the Bluetooth Core Specification.
#

"""Bluetooth LE scanner - scan all devices or search for a specific one."""

import argparse
import asyncio
import csv
import json
import os
import platform
import re
import signal
import socket
import webbrowser
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("Error: 'bleak' is not installed.")
    print("Install dependencies with:  pip install -r requirements.txt")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Error: 'cryptography' is not installed.")
    print("Install dependencies with:  pip install -r requirements.txt")
    sys.exit(1)

_HAS_CURSES = False
try:
    import curses
    _HAS_CURSES = True
except ImportError:
    pass

_HAS_FLASK = False
try:
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO
    _HAS_FLASK = True
except ImportError:
    pass

# Environment path loss exponents for distance estimation
_ENV_PATH_LOSS = {
    "free_space": 2.0,
    "outdoor": 2.2,
    "indoor": 3.0,
}

# Default reference-RSSI offset (dB) subtracted from TX Power to estimate
# the expected RSSI at the 1-metre reference distance.  The theoretical
# free-space path loss at 1 m for 2.4 GHz is ~41 dB, but real BLE devices
# add ~18 dB of antenna inefficiency, enclosure loss, and polarisation
# mismatch.  The iBeacon standard uses -59 dBm at 1 m for 0 dBm TX,
# which corresponds to an offset of 59.
_DEFAULT_REF_OFFSET = 59

# Polling / timing constants
_TUI_REFRESH_INTERVAL = 0.3       # seconds between TUI redraws
_SCAN_POLL_INTERVAL = 0.5         # seconds between poll cycles (continuous)
_TIMED_SCAN_POLL_INTERVAL = 0.1   # seconds between poll cycles (timed)
_GPS_RECONNECT_DELAY = 5          # seconds before GPS reconnect attempt
_GPS_SOCKET_TIMEOUT = 5           # seconds for GPS socket operations
_GPS_STARTUP_DELAY = 0.5          # seconds to wait for initial GPS connection

_FIELDNAMES = [
    "timestamp", "address", "name", "rssi", "avg_rssi", "tx_power",
    "est_distance", "latitude", "longitude", "gps_altitude",
    "manufacturer_data", "service_uuids", "resolved",
]

_BANNER = r"""
  _     _
 | |__ | |_ _ __ _ __   __ _       ___  ___ __ _ _ __
 | '_ \| __| '__| '_ \ / _` |_____/ __|/ __/ _` | '_ \
 | |_) | |_| |  | |_) | (_| |_____\__ \ (_| (_| | | | |
 |_.__/ \__|_|  | .__/ \__,_|     |___/\___\__,_|_| |_|
                |_|
   BLE Scanner with RPA Resolution
   by @HackingDave | TrustedSec
"""


def _timestamp() -> str:
    """Return an ISO 8601 timestamp with timezone offset."""
    return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def _mask_irk(irk_hex: str) -> str:
    """Mask an IRK hex string, showing only the first and last 4 characters."""
    if len(irk_hex) <= 8:
        return irk_hex
    return irk_hex[:4] + "..." + irk_hex[-4:]


class GpsdReader:
    """Lightweight gpsd client that reads GPS fixes over a TCP socket."""

    def __init__(self, host: str = "localhost", port: int = 2947):
        self._host = host
        self._port = port
        self._lock = threading.Lock()
        self._fix: Optional[dict] = None
        self._connected = False
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def fix(self) -> Optional[dict]:
        with self._lock:
            return dict(self._fix) if self._fix else None

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._connected

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self):
        while self._running:
            try:
                self._connect_and_read()
            except (OSError, ConnectionRefusedError, ConnectionResetError):
                pass
            with self._lock:
                self._connected = False
            if self._running:
                time.sleep(_GPS_RECONNECT_DELAY)

    def _connect_and_read(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_GPS_SOCKET_TIMEOUT)
        try:
            sock.connect((self._host, self._port))
            with self._lock:
                self._connected = True
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ""
            while self._running:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if msg.get("class") == "TPV":
                        lat = msg.get("lat")
                        lon = msg.get("lon")
                        if lat is not None and lon is not None:
                            with self._lock:
                                self._fix = {
                                    "lat": lat,
                                    "lon": lon,
                                    "alt": msg.get("alt"),
                                }
        finally:
            sock.close()


class BLEScanner:
    def __init__(self, target_mac: Optional[str], timeout: float,
                 irks: Optional[List[bytes]] = None,
                 output_format: Optional[str] = None,
                 output_file: Optional[str] = None,
                 verbose: bool = False,
                 quiet: bool = False,
                 min_rssi: Optional[int] = None,
                 rssi_window: int = 1,
                 active: bool = False,
                 environment: str = "free_space",
                 alert_within: Optional[float] = None,
                 log_file: Optional[str] = None,
                 tui: bool = False,
                 adapters: Optional[List[str]] = None,
                 gps: bool = True,
                 ref_rssi: Optional[int] = None,
                 name_filter: Optional[str] = None):
        self.target_mac = target_mac.upper() if target_mac else None
        self.targeted = target_mac is not None
        self.timeout = timeout
        self.seen_count = 0
        self.unique_devices: Dict[str, int] = {}
        self.running = True
        # IRK mode — supports one or more keys
        self.irks = irks or []
        self.irk_mode = len(self.irks) > 0
        self.resolved_devices: Dict[str, int] = {}
        self.rpa_count = 0
        self.non_rpa_warned: Set[str] = set()
        # Options
        self.verbose = verbose
        self.quiet = quiet
        self.min_rssi = min_rssi
        self.output_format = output_format
        self.output_file = output_file
        self.records: List[dict] = []
        # RSSI averaging
        self.rssi_window = max(1, rssi_window)
        self.rssi_history: Dict[str, deque] = {}
        # Scanning mode
        self.active = active
        # Environment for distance estimation
        self.environment = environment
        # Proximity alerts
        self.alert_within = alert_within
        # Real-time CSV log
        self.log_file = log_file
        self._log_writer = None
        self._log_fh = None
        # Only accumulate records in memory when batch output is requested.
        # For long-running scans without --output, this prevents unbounded
        # memory growth.  Real-time logging (--log) writes directly to disk.
        self._accumulate_records = (output_format is not None)
        # TUI mode
        self.tui = tui
        self.tui_devices: Dict[str, dict] = {}
        self._tui_screen = None
        self._tui_start = 0.0
        # Multi-adapter
        self.adapters = adapters
        # Reference RSSI calibration
        self.ref_rssi = ref_rssi
        # Name filter
        self.name_filter = name_filter
        # GPS
        self._gps = GpsdReader() if gps else None
        self.device_best_gps: Dict[str, dict] = {}
        # Thread safety for detection callback (multi-adapter)
        self._cb_lock = threading.Lock()

    def _avg_rssi(self, addr: str, rssi: int) -> int:
        """Update RSSI sliding window for a device and return the average."""
        if addr not in self.rssi_history:
            self.rssi_history[addr] = deque(maxlen=self.rssi_window)
        self.rssi_history[addr].append(rssi)
        return round(sum(self.rssi_history[addr]) / len(self.rssi_history[addr]))

    def _build_record(self, device: BLEDevice, adv: AdvertisementData,
                      resolved: Optional[bool] = None,
                      avg_rssi: Optional[int] = None) -> dict:
        """Build a record dict from device/adv data."""
        rssi = adv.rssi
        tx_power = adv.tx_power
        rssi_for_dist = avg_rssi if avg_rssi is not None else rssi
        dist = _estimate_distance(rssi_for_dist, tx_power, self.environment,
                                  ref_rssi=self.ref_rssi)

        mfr_data = ""
        if adv.manufacturer_data:
            parts = []
            for mfr_id, data in adv.manufacturer_data.items():
                parts.append(f"0x{mfr_id:04X}:{data.hex()}")
            mfr_data = "; ".join(parts)

        service_uuids = ", ".join(adv.service_uuids) if adv.service_uuids else ""

        return {
            "timestamp": _timestamp(),
            "address": device.address,
            "name": device.name or "Unknown",
            "rssi": rssi,
            "avg_rssi": avg_rssi if avg_rssi is not None else "",
            "tx_power": tx_power if tx_power is not None else "",
            "est_distance": round(dist, 2) if dist is not None else "",
            "latitude": "",
            "longitude": "",
            "gps_altitude": "",
            "manufacturer_data": mfr_data,
            "service_uuids": service_uuids,
            "resolved": resolved if resolved is not None else "",
        }

    def _record_device(self, device: BLEDevice, adv: AdvertisementData,
                       resolved: Optional[bool] = None,
                       avg_rssi: Optional[int] = None) -> dict:
        """Build a record, optionally append to self.records, write to live
        log, and update TUI state.  Returns the record dict."""
        record = self._build_record(device, adv, resolved=resolved, avg_rssi=avg_rssi)

        # Stamp GPS coordinates on this record
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                record["latitude"] = fix["lat"]
                record["longitude"] = fix["lon"]
                record["gps_altitude"] = fix["alt"] if fix["alt"] is not None else ""
                # Track per-device best GPS (strongest RSSI = closest proximity)
                addr = (device.address or "").upper()
                current_rssi = adv.rssi
                best = self.device_best_gps.get(addr)
                if best is None or current_rssi > best["rssi"]:
                    self.device_best_gps[addr] = {
                        "lat": fix["lat"],
                        "lon": fix["lon"],
                        "rssi": current_rssi,
                    }

        # Accumulate records only when batch output is needed
        if self._accumulate_records:
            self.records.append(record)

        # Real-time CSV logging
        if self._log_writer is not None:
            self._log_writer.writerow(record)
            self._log_fh.flush()

        # Update TUI device state
        if self.tui:
            addr = (device.address or "").upper()
            self.tui_devices[addr] = {
                "address": device.address,
                "name": device.name or "Unknown",
                "rssi": adv.rssi,
                "avg_rssi": avg_rssi,
                "est_distance": record["est_distance"],
                "times_seen": self.unique_devices.get(addr, 0),
                "last_seen": time.strftime("%H:%M:%S"),
                "resolved": resolved,
            }

        # Proximity alert
        if self.alert_within is not None and record["est_distance"] != "":
            if record["est_distance"] <= self.alert_within:
                if self.tui and self._tui_screen is not None:
                    curses.beep()
                elif not self.quiet:
                    print(f"\a  ** PROXIMITY ALERT ** {device.address} "
                          f"within ~{record['est_distance']:.1f}m "
                          f"(threshold: {self.alert_within}m)")

        return record

    def _print_device(self, device: BLEDevice, adv: AdvertisementData,
                      label: str, resolved: Optional[bool] = None,
                      avg_rssi: Optional[int] = None):
        # Always record for output / log / TUI
        record = self._record_device(device, adv, resolved=resolved, avg_rssi=avg_rssi)

        if self.quiet or self.tui:
            return

        rssi = adv.rssi
        dist = record["est_distance"]

        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
        addr_line = f"  Address      : {device.address}"
        if resolved is True:
            addr_line += "  << IRK MATCH >>"
        elif resolved is False:
            addr_line += "  (no match)"
        print(addr_line)
        print(f"  Name         : {device.name or 'Unknown'}")
        if avg_rssi is not None and self.rssi_window > 1:
            addr_key = (device.address or "").upper()
            n_samples = len(self.rssi_history.get(addr_key, []))
            print(f"  RSSI         : {rssi} dBm  (avg: {avg_rssi} dBm over {n_samples} readings)")
        else:
            print(f"  RSSI         : {rssi} dBm")
        tx_power = adv.tx_power
        print(f"  TX Power     : {tx_power if tx_power is not None else 'N/A'} dBm")
        if dist != "":
            print(f"  Est. Distance: ~{dist:.1f} m")
        if adv.local_name and adv.local_name != device.name:
            print(f"  Local Name   : {adv.local_name}")
        if adv.manufacturer_data:
            for mfr_id, data in adv.manufacturer_data.items():
                print(f"  Manufacturer : 0x{mfr_id:04X} -> {data.hex()}")
        if adv.service_uuids:
            print(f"  Services     : {', '.join(adv.service_uuids)}")
        if adv.service_data:
            for uuid, data in adv.service_data.items():
                print(f"  Service Data : {uuid} -> {data.hex()}")
        if adv.platform_data:
            for item in adv.platform_data:
                print(f"  Platform Data: {item}")
        addr_key = (device.address or "").upper()
        best_gps = self.device_best_gps.get(addr_key)
        if best_gps:
            print(f"  Best GPS     : {best_gps['lat']:.6f}, {best_gps['lon']:.6f}")
        print(f"  Timestamp    : {time.strftime('%H:%M:%S')}")
        print(f"{'='*60}")

    def detection_callback(self, device: BLEDevice, adv: AdvertisementData):
        with self._cb_lock:
            self._detection_callback_inner(device, adv)

    def _detection_callback_inner(self, device: BLEDevice,
                                  adv: AdvertisementData):
        addr = (device.address or "").upper()

        # Compute averaged RSSI when windowing is enabled
        avg_rssi = self._avg_rssi(addr, adv.rssi) if self.rssi_window > 1 else None
        effective_rssi = avg_rssi if avg_rssi is not None else adv.rssi

        # RSSI filtering — uses averaged RSSI when available
        if self.min_rssi is not None and effective_rssi < self.min_rssi:
            return

        # Name filtering (case-insensitive substring match)
        if self.name_filter is not None:
            name = device.name or ""
            if self.name_filter.lower() not in name.lower():
                return

        if self.irk_mode:
            self._irk_detection(device, adv, addr, avg_rssi=avg_rssi)
            return

        if self.targeted:
            if self.target_mac not in addr:
                return
            self.seen_count += 1
            self._print_device(device, adv,
                               f"TARGET FOUND  —  detection #{self.seen_count}",
                               avg_rssi=avg_rssi)
        else:
            times_seen = self.unique_devices.get(addr, 0) + 1
            self.unique_devices[addr] = times_seen
            self.seen_count += 1
            self._print_device(device, adv,
                               f"DEVICE #{len(self.unique_devices)}  —  seen {times_seen}x",
                               avg_rssi=avg_rssi)

    def _irk_detection(self, device: BLEDevice, adv: AdvertisementData,
                       addr: str, avg_rssi: Optional[int] = None):
        """Handle a detection in IRK resolution mode."""
        self.seen_count += 1

        is_uuid = len(addr.replace("-", "")) == 32 and ":" not in addr
        if is_uuid:
            if addr not in self.non_rpa_warned:
                self.non_rpa_warned.add(addr)
                if not self.quiet and not self.tui:
                    print(f"  [!] UUID address {addr} — cannot resolve (need real MAC)")
            return

        times_seen = self.unique_devices.get(addr, 0) + 1
        self.unique_devices[addr] = times_seen

        # Check address against all loaded IRKs
        resolved = False
        for irk in self.irks:
            if _resolve_rpa(irk, addr):
                resolved = True
                break

        if resolved:
            self.rpa_count += 1
            det_count = self.resolved_devices.get(addr, 0) + 1
            self.resolved_devices[addr] = det_count
            self._print_device(
                device, adv,
                f"IRK RESOLVED  —  match #{det_count} (addr seen {times_seen}x)",
                resolved=True, avg_rssi=avg_rssi,
            )
        else:
            if self.verbose:
                self._print_device(
                    device, adv,
                    f"IRK NO MATCH  —  addr seen {times_seen}x",
                    resolved=False, avg_rssi=avg_rssi,
                )

    # ------------------------------------------------------------------
    # TUI (curses)
    # ------------------------------------------------------------------

    def _redraw_tui(self, screen):
        """Redraw the TUI live table."""
        try:
            screen.erase()
            h, w = screen.getmaxyx()

            elapsed = time.time() - self._tui_start
            header = (f" btrpa-scan | Devices: {len(self.tui_devices)}"
                      f"  Detections: {self.seen_count}"
                      f"  Elapsed: {elapsed:.0f}s")
            if self.irk_mode:
                header += f"  IRK matches: {self.rpa_count}"
            screen.addnstr(0, 0, header.ljust(w - 1), w - 1,
                           curses.A_BOLD | curses.A_REVERSE)

            settings = f" {'active' if self.active else 'passive'}"
            if self.environment != "free_space":
                settings += f" | env: {self.environment}"
            if self.rssi_window > 1:
                settings += f" | rssi-avg: {self.rssi_window}"
            if self.min_rssi is not None:
                settings += f" | min-rssi: {self.min_rssi}"
            if self.alert_within is not None:
                settings += f" | alert: <{self.alert_within}m"
            if self._gps is not None:
                fix = self._gps.fix
                if fix is not None:
                    settings += f" | GPS: {fix['lat']:.5f},{fix['lon']:.5f}"
                elif self._gps.connected:
                    settings += " | GPS: no fix"
                else:
                    settings += " | GPS: offline"
            screen.addnstr(1, 0, settings, w - 1, curses.A_DIM)

            col_fmt = " {:<19s} {:<16s} {:>5s} {:>5s} {:>7s} {:>5s} {:>8s}"
            col_hdr = col_fmt.format(
                "Address", "Name", "RSSI", "Avg", "Dist", "Seen", "Last")
            screen.addnstr(3, 0, col_hdr, w - 1, curses.A_UNDERLINE)

            sorted_devs = sorted(
                self.tui_devices.values(),
                key=lambda d: d["rssi"], reverse=True,
            )

            row = 4
            for dev in sorted_devs:
                if row >= h - 1:
                    remaining = len(sorted_devs) - (row - 4)
                    screen.addnstr(
                        h - 1, 0,
                        f" ... {remaining} more (resize terminal)", w - 1)
                    break
                avg_str = str(dev["avg_rssi"]) if dev["avg_rssi"] is not None else ""
                dist_str = (f"~{dev['est_distance']:.1f}m"
                            if isinstance(dev["est_distance"], (int, float))
                            else "")
                line = col_fmt.format(
                    (dev["address"] or "")[:18],
                    dev["name"][:15],
                    str(dev["rssi"]), avg_str, dist_str,
                    f"{dev['times_seen']}x",
                    dev["last_seen"],
                )
                attr = curses.A_NORMAL
                if dev.get("resolved") is True:
                    attr = curses.A_BOLD
                if (self.alert_within is not None
                        and isinstance(dev["est_distance"], (int, float))
                        and dev["est_distance"] <= self.alert_within):
                    attr |= curses.A_STANDOUT
                screen.addnstr(row, 0, line, w - 1, attr)
                row += 1

            footer = " Press Ctrl+C to stop"
            if self.log_file:
                footer += f"  |  Logging to {self.log_file}"
            screen.addnstr(h - 1, 0, footer, w - 1, curses.A_DIM)

            screen.refresh()
        except curses.error:
            pass

    # ------------------------------------------------------------------
    # Main scan flow
    # ------------------------------------------------------------------

    async def scan(self):
        # Install signal handlers inside the async context for clean
        # shutdown without the signal-handler / KeyboardInterrupt race.
        loop = asyncio.get_running_loop()
        if platform.system() != "Windows":
            loop.add_signal_handler(signal.SIGINT, self.stop)
            loop.add_signal_handler(signal.SIGTERM, self.stop)

        # Start GPS reader
        if self._gps is not None:
            self._gps.start()
            await asyncio.sleep(_GPS_STARTUP_DELAY)

        # Open real-time CSV log
        if self.log_file:
            self._log_fh = open(self.log_file, "w", newline="")
            self._log_writer = csv.DictWriter(self._log_fh,
                                              fieldnames=_FIELDNAMES)
            self._log_writer.writeheader()
            self._log_fh.flush()

        # TUI setup
        if self.tui:
            self._tui_screen = curses.initscr()
            curses.noecho()
            curses.cbreak()
            curses.curs_set(0)
            if curses.has_colors():
                curses.start_color()
                curses.use_default_colors()

        try:
            elapsed = await self._scan_loop()
        finally:
            # TUI cleanup
            if self._tui_screen is not None:
                curses.curs_set(1)
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                self._tui_screen = None

            # Stop GPS reader
            if self._gps is not None:
                self._gps.stop()

            # Close log file
            if self._log_fh is not None:
                self._log_fh.close()
                self._log_fh = None
                self._log_writer = None

        # Summary and output (printed after TUI is torn down)
        self._print_summary(elapsed)
        self._write_output()

    async def _scan_loop(self) -> float:
        """Run the BLE scanner and return elapsed seconds."""
        if not self.quiet and not self.tui:
            self._print_header()

        scanner_kwargs: dict = {"detection_callback": self.detection_callback}
        if self.active:
            scanner_kwargs["scanning_mode"] = "active"
        if self.irk_mode and platform.system() == "Darwin":
            # Undocumented CoreBluetooth API to retrieve real BD_ADDR
            # instead of CoreBluetooth UUIDs.  May break in future
            # Bleak releases.
            scanner_kwargs["cb"] = {"use_bdaddr": True}

        # Multi-adapter support
        scanners = []
        if self.adapters:
            for adapter in self.adapters:
                kw = {**scanner_kwargs, "adapter": adapter}
                scanners.append(BleakScanner(**kw))
        else:
            scanners.append(BleakScanner(**scanner_kwargs))

        for s in scanners:
            await s.start()

        start = time.time()
        self._tui_start = start
        try:
            if self.timeout == float('inf'):
                while self.running:
                    if self._tui_screen is not None:
                        self._redraw_tui(self._tui_screen)
                    await asyncio.sleep(
                        _TUI_REFRESH_INTERVAL if self.tui
                        else _SCAN_POLL_INTERVAL)
            else:
                while self.running and (time.time() - start) < self.timeout:
                    if self._tui_screen is not None:
                        self._redraw_tui(self._tui_screen)
                    await asyncio.sleep(_TIMED_SCAN_POLL_INTERVAL)
        except asyncio.CancelledError:
            pass
        finally:
            for s in scanners:
                await s.stop()

        return time.time() - start

    def _print_header(self):
        """Print scan configuration banner."""
        print(_BANNER)
        if self.irk_mode:
            n_irks = len(self.irks)
            if n_irks == 1:
                print("Mode: IRK RESOLUTION — resolving RPAs against provided IRK")
                print(f"  IRK: {_mask_irk(self.irks[0].hex())}")
            else:
                print(f"Mode: IRK RESOLUTION — resolving RPAs against {n_irks} IRKs")
                for i, irk in enumerate(self.irks, 1):
                    print(f"  IRK #{i}: {_mask_irk(irk.hex())}")
            _os = platform.system()
            if _os == "Darwin":
                print("  Note: using undocumented macOS API to retrieve real BT addresses")
            elif _os == "Linux":
                print("  Note: Linux/BlueZ — may require root or CAP_NET_ADMIN")
            elif _os == "Windows":
                print("  Note: Windows/WinRT — real MAC addresses available natively")
        elif self.targeted:
            print(f"Mode: TARGETED — searching for {self.target_mac}")
        else:
            print("Mode: DISCOVER ALL — showing every broadcasting device")
        scan_mode = "active" if self.active else "passive"
        print(f"Scanning: {scan_mode}", end="")
        if self.rssi_window > 1:
            print(f"  |  RSSI averaging: window of {self.rssi_window}")
        else:
            print()
        if self.active and platform.system() == "Darwin":
            print("  Note: CoreBluetooth always scans actively regardless of this flag")
        if self.environment != "free_space":
            print(f"Environment: {self.environment} "
                  f"(n={_ENV_PATH_LOSS[self.environment]})")
        if self.min_rssi is not None:
            print(f"Min RSSI: {self.min_rssi} dBm")
        if self.name_filter is not None:
            print(f"Name filter: \"{self.name_filter}\"")
        if self.alert_within is not None:
            print(f"Proximity alert: within {self.alert_within}m")
        if self.log_file:
            print(f"Live log: {self.log_file}")
        if self.adapters:
            print(f"Adapters: {', '.join(self.adapters)}")
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                print(f"GPS: connected ({fix['lat']:.6f}, {fix['lon']:.6f})")
            elif self._gps.connected:
                print("GPS: waiting for fix")
            else:
                print("GPS: gpsd not available — continuing without GPS")
        elif self._gps is None:
            print("GPS: disabled")
        if self.timeout == float('inf'):
            print("Running continuously  |  Press Ctrl+C to stop")
        else:
            print(f"Timeout: {self.timeout}s  |  Press Ctrl+C to stop")
        print(f"{'—'*60}")

    def _print_summary(self, elapsed: float):
        """Print scan summary statistics."""
        print(f"\n{'—'*60}")
        print(f"Scan complete — {elapsed:.1f}s elapsed")
        print(f"  Total detections : {self.seen_count}")
        if self.irk_mode:
            print(f"  Unique addresses : {len(self.unique_devices)}")
            print(f"  IRK matches      : {self.rpa_count} detections "
                  f"across {len(self.resolved_devices)} address(es)")
            if self.resolved_devices:
                has_gps = any(a in self.device_best_gps for a in self.resolved_devices)
                print(f"\n  Resolved addresses:")
                if has_gps:
                    print(f"  {'Address':<20} {'Detections':>11}  {'Best GPS'}")
                    print(f"  {'—'*20} {'—'*11}  {'—'*24}")
                else:
                    print(f"  {'Address':<20} {'Detections':>11}")
                    print(f"  {'—'*20} {'—'*11}")
                for addr, count in sorted(self.resolved_devices.items(),
                                          key=lambda x: x[1], reverse=True):
                    line = f"  {addr:<20} {count:>10}x"
                    if has_gps:
                        bg = self.device_best_gps.get(addr)
                        gps_str = f"  {bg['lat']:.6f}, {bg['lon']:.6f}" if bg else ""
                        line += gps_str
                    print(line)
            if not self.resolved_devices:
                print("\n  No addresses resolved — the device may not be "
                      "broadcasting,")
                print("  or the IRK may be incorrect.")
        elif not self.targeted:
            print(f"  Unique devices   : {len(self.unique_devices)}")
            if self.unique_devices:
                has_gps = any(a in self.device_best_gps for a in self.unique_devices)
                if has_gps:
                    print(f"\n  {'Address':<40} {'Seen':>6}  {'Best GPS'}")
                    print(f"  {'—'*40} {'—'*6}  {'—'*24}")
                else:
                    print(f"\n  {'Address':<40} {'Seen':>6}")
                    print(f"  {'—'*40} {'—'*6}")
                for addr, count in sorted(self.unique_devices.items(),
                                          key=lambda x: x[1], reverse=True):
                    line = f"  {addr:<40} {count:>5}x"
                    if has_gps:
                        bg = self.device_best_gps.get(addr)
                        gps_str = f"  {bg['lat']:.6f}, {bg['lon']:.6f}" if bg else ""
                        line += gps_str
                    print(line)

    def _write_output(self):
        """Write batch output file (json / jsonl / csv)."""
        if not self.output_format or not self.records:
            if self.log_file:
                print(f"  Live log written to {self.log_file}")
            return

        filename = self.output_file or f"btrpa-scan-results.{self.output_format}"

        # Support writing to stdout with --output-file -
        if filename == "-":
            if self.output_format == "json":
                sys.stdout.write(json.dumps(self.records, indent=2) + "\n")
            elif self.output_format == "jsonl":
                for record in self.records:
                    sys.stdout.write(json.dumps(record) + "\n")
            elif self.output_format == "csv":
                writer = csv.DictWriter(sys.stdout, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(self.records)
            return

        if self.output_format == "json":
            with open(filename, "w") as f:
                json.dump(self.records, f, indent=2)
        elif self.output_format == "jsonl":
            with open(filename, "w") as f:
                for record in self.records:
                    f.write(json.dumps(record) + "\n")
        elif self.output_format == "csv":
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(self.records)
        print(f"  Results written to {filename}")
        if self.log_file:
            print(f"  Live log written to {self.log_file}")

    def stop(self):
        if not self.tui and self.running:
            print("\nStopping scan...")
        self.running = False


def _estimate_distance(rssi: int, tx_power: Optional[int],
                       env: str = "free_space",
                       ref_rssi: Optional[int] = None) -> Optional[float]:
    """Estimate distance in meters using the log-distance path loss model.

    When *ref_rssi* is provided it is used directly as the expected RSSI at
    the 1-metre reference distance (measured_power), ignoring *tx_power*.
    Otherwise we derive measured_power from *tx_power* by subtracting
    ``_DEFAULT_REF_OFFSET`` (59 dB) — the empirically validated offset used
    by the iBeacon standard that accounts for free-space path loss plus
    typical BLE antenna/enclosure losses.
    """
    if rssi == 0:
        return None
    if ref_rssi is not None:
        measured_power = ref_rssi
    elif tx_power is not None:
        measured_power = tx_power - _DEFAULT_REF_OFFSET
    else:
        return None
    n = _ENV_PATH_LOSS.get(env, 2.0)
    return 10 ** ((measured_power - rssi) / (10 * n))


def _bt_ah(irk: bytes, prand: bytes) -> bytes:
    """Bluetooth Core Spec ah() function (Vol 3, Part H, Section 2.2.2).

    AES-128-ECB(IRK, padding || prand) -> return last 3 bytes.

    Note: ECB mode is mandated by the Bluetooth Core Specification for this
    single-block operation.  It is not a vulnerability — only one 16-byte
    block is ever encrypted, so ECB's lack of diffusion is irrelevant.
    """
    plaintext = b'\x00' * 13 + prand  # 16 bytes: 13 zero-pad + 3-byte prand
    cipher = Cipher(algorithms.AES(irk), modes.ECB())
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct[-3:]  # last 3 bytes = hash


def _is_rpa(addr_bytes: bytes) -> bool:
    """Check if a 6-byte address is a Resolvable Private Address.

    RPA has top two bits of the most-significant byte set to 01.
    """
    return len(addr_bytes) == 6 and (addr_bytes[0] >> 6) == 0b01


def _resolve_rpa(irk: bytes, address: str) -> bool:
    """Resolve a MAC address string against an IRK.

    MAC format: AA:BB:CC:DD:EE:FF
    prand = first 3 octets (AA:BB:CC), hash = last 3 octets (DD:EE:FF).
    Returns True if ah(IRK, prand) == hash.
    """
    parts = address.replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    try:
        addr_bytes = bytes(int(b, 16) for b in parts)
    except ValueError:
        return False
    if not _is_rpa(addr_bytes):
        return False
    prand = addr_bytes[:3]
    expected_hash = addr_bytes[3:]
    return _bt_ah(irk, prand) == expected_hash


def _parse_irk(irk_string: str) -> bytes:
    """Parse an IRK from hex string (plain, colon-separated, or 0x-prefixed).

    Returns 16 bytes or raises ValueError.
    """
    s = irk_string.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = s.replace(":", "").replace("-", "")
    if len(s) != 32:
        raise ValueError(
            f"IRK must be exactly 16 bytes (32 hex chars), got {len(s)} hex chars")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"IRK contains invalid hex characters: {irk_string}")


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def main():
    parser = argparse.ArgumentParser(
        description="BLE Scanner — discover all devices or hunt for a specific one"
    )
    parser.add_argument(
        "mac", nargs="?", default=None,
        help="Target MAC address to search for (omit to scan all)"
    )
    parser.add_argument(
        "-a", "--all", action="store_true",
        help="Scan for all broadcasting devices"
    )
    parser.add_argument(
        "--irk", type=str, default=None, metavar="HEX",
        help="Resolve RPAs using this Identity Resolving Key (32 hex chars)"
    )
    parser.add_argument(
        "--irk-file", type=str, default=None, metavar="PATH",
        help="Read IRK(s) from a file (one per line, hex format; "
             "lines starting with # are ignored)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=None,
        help="Scan timeout in seconds (default: 30, or infinite for --irk)"
    )

    # Output / logging
    parser.add_argument(
        "--output", choices=["csv", "json", "jsonl"], default=None,
        help="Batch output format written at end of scan"
    )
    parser.add_argument(
        "-o", "--output-file", type=str, default=None, metavar="FILE",
        help="Output file path (default: btrpa-scan-results.<format>; "
             "use - for stdout)"
    )
    parser.add_argument(
        "--log", type=str, default=None, metavar="FILE",
        help="Stream detections to a CSV file in real time"
    )

    # Verbosity
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose mode — show additional details"
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true",
        help="Quiet mode — suppress per-device output, show summary only"
    )

    # Signal / detection tuning
    parser.add_argument(
        "--min-rssi", type=int, default=None, metavar="DBM",
        help="Minimum RSSI threshold (e.g. -70) — ignore weaker signals"
    )
    parser.add_argument(
        "--rssi-window", type=int, default=1, metavar="N",
        help="RSSI sliding window size for averaging (e.g. 5-10). "
             "Smooths noisy readings for stable distance estimates "
             "(default: 1 = no averaging)"
    )
    parser.add_argument(
        "--active", action="store_true",
        help="Use active scanning — sends SCAN_REQ to get SCAN_RSP with "
             "additional service UUIDs and names (default: passive)"
    )
    parser.add_argument(
        "--environment", choices=["free_space", "indoor", "outdoor"],
        default="free_space",
        help="Environment preset for distance estimation path-loss exponent: "
             "free_space (n=2.0), outdoor (n=2.2), indoor (n=3.0). "
             "Default: free_space"
    )
    parser.add_argument(
        "--ref-rssi", type=int, default=None, metavar="DBM",
        help="Calibrated RSSI (dBm) measured at 1 metre from the target "
             "device. When set, this value is used directly for distance "
             "estimation instead of deriving it from TX Power. "
             "Also enables distance estimates for devices that don't "
             "advertise TX Power"
    )

    # Filtering
    parser.add_argument(
        "--name-filter", type=str, default=None, metavar="PATTERN",
        help="Filter devices by name (case-insensitive substring match)"
    )

    # Proximity alerts
    parser.add_argument(
        "--alert-within", type=float, default=None, metavar="METERS",
        help="Trigger an audible/visual alert when a device is estimated "
             "within this distance (requires TX Power in advertisements)"
    )

    # TUI
    parser.add_argument(
        "--tui", action="store_true",
        help="Live-updating terminal table instead of scrolling output"
    )

    # GPS
    parser.add_argument(
        "--no-gps", action="store_true",
        help="Disable GPS location stamping (GPS is on by default via gpsd)"
    )

    # Multi-adapter (Linux)
    parser.add_argument(
        "--adapters", type=str, default=None, metavar="LIST",
        help="Comma-separated Bluetooth adapter names to scan with "
             "(e.g. hci0,hci1 — Linux only)"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    if args.output_file and not args.output:
        parser.error("--output-file (-o) requires --output to specify "
                     "the format (csv, json, or jsonl)")

    if args.mac and not _MAC_RE.match(args.mac):
        parser.error(
            f"Invalid MAC address '{args.mac}'. "
            "Expected format: XX:XX:XX:XX:XX:XX (6 colon-separated hex octets)")

    # Determine if any IRK source was provided
    has_irk = bool(args.irk or args.irk_file or os.environ.get("BTRPA_IRK"))

    if has_irk and args.all:
        parser.error("Cannot use IRK with --all")
    if has_irk and args.mac:
        parser.error("Cannot use IRK with a specific MAC address")
    if args.mac and args.all:
        parser.error("Cannot use --all with a specific MAC address")
    if not args.mac and not args.all and not has_irk:
        print(_BANNER)
        parser.print_help()
        sys.exit(0)

    if args.rssi_window < 1:
        parser.error("--rssi-window must be at least 1")

    if args.tui and not _HAS_CURSES:
        parser.error("--tui requires the 'curses' module "
                     "(install 'windows-curses' on Windows)")

    if args.tui and args.quiet:
        parser.error("Cannot use --tui with --quiet")

    if args.irk and args.irk_file:
        parser.error("Cannot use --irk and --irk-file together")

    # Parse IRKs (from --irk, --irk-file, or BTRPA_IRK env var)
    irks: List[bytes] = []
    if args.irk:
        try:
            irks.append(_parse_irk(args.irk))
        except ValueError as e:
            parser.error(str(e))
    elif args.irk_file:
        try:
            with open(args.irk_file) as f:
                for line_num, raw_line in enumerate(f, 1):
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    try:
                        irks.append(_parse_irk(stripped))
                    except ValueError as e:
                        parser.error(f"IRK file line {line_num}: {e}")
        except OSError as e:
            parser.error(f"Cannot read IRK file: {e}")
        if not irks:
            parser.error("IRK file contains no valid keys")
    elif os.environ.get("BTRPA_IRK"):
        try:
            irks.append(_parse_irk(os.environ["BTRPA_IRK"]))
        except ValueError as e:
            parser.error(f"BTRPA_IRK environment variable: {e}")

    # Default timeout
    if args.timeout is not None:
        timeout = args.timeout
    elif irks:
        timeout = float('inf')
    else:
        timeout = 30.0

    # Parse adapters
    adapters = None
    if args.adapters:
        adapters = [a.strip() for a in args.adapters.split(",") if a.strip()]
        if not adapters:
            parser.error("--adapters requires at least one adapter name")

    target = args.mac if not args.all and not irks else None
    scanner = BLEScanner(
        target, timeout, irks=irks,
        output_format=args.output,
        output_file=args.output_file,
        verbose=args.verbose,
        quiet=args.quiet,
        min_rssi=args.min_rssi,
        rssi_window=args.rssi_window,
        active=args.active,
        environment=args.environment,
        alert_within=args.alert_within,
        log_file=args.log,
        tui=args.tui,
        adapters=adapters,
        gps=not args.no_gps,
        ref_rssi=args.ref_rssi,
        name_filter=args.name_filter,
    )

    # On Windows, asyncio doesn't support loop.add_signal_handler, so
    # fall back to the older signal.signal approach.
    if platform.system() == "Windows":
        signal.signal(signal.SIGINT, lambda *_: scanner.stop())

    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

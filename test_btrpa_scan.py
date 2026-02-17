#!/usr/bin/env python3
"""Unit tests for btrpa-scan core functions.

Run with:  python -m pytest test_btrpa_scan.py -v
"""

import importlib
import re
import struct
from collections import deque

import pytest

# The module has a hyphen in its name, so we use importlib to import it.
btrpa = importlib.import_module("btrpa-scan")


# ------------------------------------------------------------------
# _parse_irk
# ------------------------------------------------------------------

class TestParseIrk:
    """Tests for _parse_irk — hex string → 16 bytes."""

    def test_plain_hex(self):
        raw = "0123456789abcdef0123456789abcdef"
        assert btrpa._parse_irk(raw) == bytes.fromhex(raw)

    def test_uppercase(self):
        raw = "0123456789ABCDEF0123456789ABCDEF"
        assert btrpa._parse_irk(raw) == bytes.fromhex(raw)

    def test_0x_prefix(self):
        raw = "0x0123456789abcdef0123456789abcdef"
        assert btrpa._parse_irk(raw) == bytes.fromhex(raw[2:])

    def test_colon_separated(self):
        raw = "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF"
        expected = bytes.fromhex(raw.replace(":", ""))
        assert btrpa._parse_irk(raw) == expected

    def test_dash_separated(self):
        raw = "01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF"
        expected = bytes.fromhex(raw.replace("-", ""))
        assert btrpa._parse_irk(raw) == expected

    def test_with_whitespace(self):
        raw = "  0123456789abcdef0123456789abcdef  "
        assert btrpa._parse_irk(raw) == bytes.fromhex(raw.strip())

    def test_too_short(self):
        with pytest.raises(ValueError, match="32 hex chars"):
            btrpa._parse_irk("0123456789abcdef")

    def test_too_long(self):
        with pytest.raises(ValueError, match="32 hex chars"):
            btrpa._parse_irk("0123456789abcdef0123456789abcdef00")

    def test_invalid_hex(self):
        with pytest.raises(ValueError, match="invalid hex"):
            btrpa._parse_irk("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            btrpa._parse_irk("")


# ------------------------------------------------------------------
# _is_rpa
# ------------------------------------------------------------------

class TestIsRpa:
    """Tests for _is_rpa — checks the top two bits of the first byte."""

    def test_valid_rpa_01(self):
        # Top two bits = 01 → 0b01xx_xxxx = 0x40..0x7F
        addr = bytes([0x40, 0x11, 0x22, 0x33, 0x44, 0x55])
        assert btrpa._is_rpa(addr) is True

    def test_valid_rpa_max(self):
        addr = bytes([0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        assert btrpa._is_rpa(addr) is True

    def test_not_rpa_00(self):
        # Top two bits = 00
        addr = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        assert btrpa._is_rpa(addr) is False

    def test_not_rpa_10(self):
        # Top two bits = 10
        addr = bytes([0x80, 0x11, 0x22, 0x33, 0x44, 0x55])
        assert btrpa._is_rpa(addr) is False

    def test_not_rpa_11(self):
        # Top two bits = 11
        addr = bytes([0xC0, 0x11, 0x22, 0x33, 0x44, 0x55])
        assert btrpa._is_rpa(addr) is False

    def test_wrong_length(self):
        assert btrpa._is_rpa(bytes([0x40, 0x11, 0x22])) is False
        assert btrpa._is_rpa(b"") is False


# ------------------------------------------------------------------
# _bt_ah  and  _resolve_rpa
# ------------------------------------------------------------------

class TestBtAh:
    """Tests for the Bluetooth ah() function and RPA resolution."""

    def _make_rpa(self, irk: bytes, prand: bytes) -> str:
        """Construct a valid RPA string from an IRK and a 3-byte prand."""
        hash_bytes = btrpa._bt_ah(irk, prand)
        addr_bytes = prand + hash_bytes
        return ":".join(f"{b:02X}" for b in addr_bytes)

    def test_ah_output_length(self):
        irk = bytes(range(16))
        prand = bytes([0x40, 0x11, 0x22])
        result = btrpa._bt_ah(irk, prand)
        assert len(result) == 3

    def test_resolve_rpa_match(self):
        irk = bytes.fromhex("0123456789abcdef0123456789abcdef")
        # prand with top two bits = 01
        prand = bytes([0x55, 0xAA, 0x33])
        rpa = self._make_rpa(irk, prand)
        assert btrpa._resolve_rpa(irk, rpa) is True

    def test_resolve_rpa_no_match_wrong_irk(self):
        irk = bytes.fromhex("0123456789abcdef0123456789abcdef")
        wrong_irk = bytes.fromhex("fedcba9876543210fedcba9876543210")
        prand = bytes([0x55, 0xAA, 0x33])
        rpa = self._make_rpa(irk, prand)
        assert btrpa._resolve_rpa(wrong_irk, rpa) is False

    def test_resolve_rpa_non_rpa_address(self):
        irk = bytes(16)
        # Top two bits = 00 → not an RPA
        assert btrpa._resolve_rpa(irk, "00:11:22:33:44:55") is False

    def test_resolve_rpa_invalid_format(self):
        irk = bytes(16)
        assert btrpa._resolve_rpa(irk, "not-a-mac") is False
        assert btrpa._resolve_rpa(irk, "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ") is False
        assert btrpa._resolve_rpa(irk, "") is False

    def test_resolve_rpa_dash_separator(self):
        irk = bytes.fromhex("0123456789abcdef0123456789abcdef")
        prand = bytes([0x55, 0xAA, 0x33])
        rpa_colon = self._make_rpa(irk, prand)
        rpa_dash = rpa_colon.replace(":", "-")
        assert btrpa._resolve_rpa(irk, rpa_dash) is True

    def test_ah_deterministic(self):
        irk = bytes.fromhex("abcdef0123456789abcdef0123456789")
        prand = bytes([0x60, 0x00, 0x01])
        r1 = btrpa._bt_ah(irk, prand)
        r2 = btrpa._bt_ah(irk, prand)
        assert r1 == r2


# ------------------------------------------------------------------
# _estimate_distance
# ------------------------------------------------------------------

class TestEstimateDistance:
    """Tests for the log-distance path loss model."""

    def test_rssi_zero_returns_none(self):
        assert btrpa._estimate_distance(0, -10) is None

    def test_no_tx_power_no_ref_returns_none(self):
        assert btrpa._estimate_distance(-60, None) is None

    def test_basic_free_space(self):
        # At measured_power, distance should be ~1 m
        tx_power = 0
        measured_power = tx_power - btrpa._DEFAULT_REF_OFFSET  # -59
        dist = btrpa._estimate_distance(measured_power, tx_power, "free_space")
        assert dist is not None
        assert abs(dist - 1.0) < 0.01

    def test_ref_rssi_overrides_tx_power(self):
        # ref_rssi should be used directly, tx_power ignored
        dist = btrpa._estimate_distance(-59, tx_power=99, ref_rssi=-59)
        assert dist is not None
        assert abs(dist - 1.0) < 0.01

    def test_ref_rssi_without_tx_power(self):
        # Should work even when tx_power is None
        dist = btrpa._estimate_distance(-59, tx_power=None, ref_rssi=-59)
        assert dist is not None
        assert abs(dist - 1.0) < 0.01

    def test_weaker_rssi_gives_larger_distance(self):
        d1 = btrpa._estimate_distance(-50, tx_power=0)
        d2 = btrpa._estimate_distance(-70, tx_power=0)
        assert d1 is not None and d2 is not None
        assert d2 > d1

    def test_indoor_gives_shorter_distance_than_free_space(self):
        # Higher path-loss exponent → distance estimate is smaller for same RSSI
        d_free = btrpa._estimate_distance(-70, tx_power=0, env="free_space")
        d_indoor = btrpa._estimate_distance(-70, tx_power=0, env="indoor")
        assert d_free is not None and d_indoor is not None
        assert d_indoor < d_free

    def test_unknown_env_defaults_to_2(self):
        d1 = btrpa._estimate_distance(-60, tx_power=0, env="free_space")
        d2 = btrpa._estimate_distance(-60, tx_power=0, env="nonexistent")
        # Both use n=2.0
        assert d1 is not None and d2 is not None
        assert abs(d1 - d2) < 0.001


# ------------------------------------------------------------------
# _timestamp
# ------------------------------------------------------------------

class TestTimestamp:
    """Tests for the ISO 8601 timestamp helper."""

    def test_format(self):
        ts = btrpa._timestamp()
        # Should match ISO 8601 with timezone offset
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}", ts)

    def test_not_empty(self):
        assert len(btrpa._timestamp()) > 0


# ------------------------------------------------------------------
# _mask_irk
# ------------------------------------------------------------------

class TestMaskIrk:
    """Tests for _mask_irk — redacts the middle of an IRK hex string."""

    def test_normal_32_char(self):
        irk_hex = "0123456789abcdef0123456789abcdef"
        masked = btrpa._mask_irk(irk_hex)
        assert masked == "0123...cdef"
        # Full key should not be present
        assert irk_hex not in masked

    def test_short_string_not_masked(self):
        short = "abcd1234"
        assert btrpa._mask_irk(short) == short

    def test_very_short_string(self):
        assert btrpa._mask_irk("ab") == "ab"


# ------------------------------------------------------------------
# BLEScanner._avg_rssi (via instance)
# ------------------------------------------------------------------

class TestAvgRssi:
    """Tests for the RSSI sliding window average."""

    def _make_scanner(self, window: int = 5):
        return btrpa.BLEScanner(
            target_mac=None, timeout=10, rssi_window=window, gps=False)

    def test_single_reading(self):
        s = self._make_scanner(window=3)
        assert s._avg_rssi("AA:BB", -60) == -60

    def test_average_of_multiple(self):
        s = self._make_scanner(window=3)
        s._avg_rssi("AA:BB", -60)
        s._avg_rssi("AA:BB", -66)
        avg = s._avg_rssi("AA:BB", -63)
        assert avg == round((-60 + -66 + -63) / 3)

    def test_window_evicts_old(self):
        s = self._make_scanner(window=2)
        s._avg_rssi("AA:BB", -100)
        s._avg_rssi("AA:BB", -50)
        avg = s._avg_rssi("AA:BB", -60)
        # Window of 2: only -50 and -60 should remain
        assert avg == round((-50 + -60) / 2)

    def test_separate_devices(self):
        s = self._make_scanner(window=3)
        s._avg_rssi("DEV1", -40)
        s._avg_rssi("DEV2", -80)
        # Each device has its own history
        assert s._avg_rssi("DEV1", -40) == -40
        assert s._avg_rssi("DEV2", -80) == -80

    def test_window_minimum_1(self):
        s = btrpa.BLEScanner(
            target_mac=None, timeout=10, rssi_window=0, gps=False)
        # rssi_window is clamped to 1
        assert s.rssi_window == 1


# ------------------------------------------------------------------
# GUI parameter support
# ------------------------------------------------------------------

class TestGuiParameter:
    """Tests for GUI parameter on BLEScanner."""

    def test_gui_defaults_false(self):
        s = btrpa.BLEScanner(target_mac=None, timeout=10, gps=False)
        assert s.gui is False

    def test_gui_enabled(self):
        s = btrpa.BLEScanner(target_mac=None, timeout=10, gps=False, gui=True)
        assert s.gui is True

    def test_gui_port_default(self):
        s = btrpa.BLEScanner(target_mac=None, timeout=10, gps=False, gui=True)
        assert s.gui_port == 5000

    def test_gui_port_custom(self):
        s = btrpa.BLEScanner(target_mac=None, timeout=10, gps=False, gui=True, gui_port=8080)
        assert s.gui_port == 8080

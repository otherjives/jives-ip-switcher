"""
Tests for discovery.py — adapter enumeration helpers, profile storage, history.
Uses TemporaryDirectory for file-mutating tests (retrospective lesson #6).
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from discovery import (
    IpProfile, HistoryEntry,
    mask_to_prefix, prefix_to_mask,
    validate_ip, validate_mask,
    load_profiles, save_profiles, add_profile, delete_profile,
    update_profile_used, load_history, add_history, clear_history,
    _get_app_data_dir,
)


# ─── IP/mask validation ─────────────────────────────────────────────────────

class TestIpValidation:
    def test_valid_ip(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("255.255.255.255") is True
        assert validate_ip("0.0.0.0") is True

    def test_invalid_ip(self):
        assert validate_ip("192.168.1.999") is False
        assert validate_ip("192.168.1") is False
        assert validate_ip("abc") is False
        assert validate_ip("") is False
        assert validate_ip("192.168.1.1.1") is False

    def test_valid_mask(self):
        assert validate_mask("255.255.255.0") is True
        assert validate_mask("255.255.0.0") is True
        assert validate_mask("255.0.0.0") is True
        assert validate_mask("255.255.255.252") is True

    def test_invalid_mask(self):
        assert validate_mask("255.255.255.1") is False  # non-contiguous
        assert validate_mask("192.168.1.0") is False    # not a mask
        assert validate_mask("") is False
        assert validate_mask("255.255.255") is False


# ─── Mask/prefix conversion ──────────────────────────────────────────────────

class TestMaskConversion:
    def test_mask_to_prefix(self):
        assert mask_to_prefix("255.255.255.0") == 24
        assert mask_to_prefix("255.255.0.0") == 16
        assert mask_to_prefix("255.0.0.0") == 8
        assert mask_to_prefix("255.255.255.252") == 30
        assert mask_to_prefix("") == 0

    def test_prefix_to_mask(self):
        assert prefix_to_mask(24) == "255.255.255.0"
        assert prefix_to_mask(16) == "255.255.0.0"
        assert prefix_to_mask(8) == "255.0.0.0"
        assert prefix_to_mask(30) == "255.255.255.252"
        assert prefix_to_mask(32) == "255.255.255.255"

    def test_roundtrip(self):
        for p in [8, 16, 24, 30, 32]:
            mask = prefix_to_mask(p)
            assert mask_to_prefix(mask) == p


# ─── Profile storage (uses temp dir) ─────────────────────────────────────────

@pytest.fixture
def temp_app_data(monkeypatch):
    """Redirect app data dir to a TemporaryDirectory."""
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setattr(
            "discovery._get_app_data_dir",
            lambda: Path(td)
        )
        # Also patch the import in operations if needed
        yield Path(td)


class TestProfileStorage:
    def test_save_and_load(self, temp_app_data):
        profiles = [
            IpProfile(name="Office", ip="192.168.1.100", subnet_mask="255.255.255.0"),
            IpProfile(name="Site A", ip="10.0.0.50", subnet_mask="255.0.0.0", gateway="10.0.0.1"),
        ]
        save_profiles(profiles)
        loaded = load_profiles()
        assert len(loaded) == 2
        assert loaded[0].name == "Office"
        assert loaded[0].ip == "192.168.1.100"
        assert loaded[1].name == "Site A"
        assert loaded[1].gateway == "10.0.0.1"

    def test_add_profile(self, temp_app_data):
        p = IpProfile(name="Test1", ip="192.168.1.5", subnet_mask="255.255.255.0")
        add_profile(p)
        loaded = load_profiles()
        assert len(loaded) == 1
        assert loaded[0].name == "Test1"

    def test_add_replaces_same_name(self, temp_app_data):
        p1 = IpProfile(name="Test", ip="192.168.1.5", subnet_mask="255.255.255.0")
        add_profile(p1)
        p2 = IpProfile(name="Test", ip="10.0.0.5", subnet_mask="255.0.0.0")
        add_profile(p2)
        loaded = load_profiles()
        assert len(loaded) == 1
        assert loaded[0].ip == "10.0.0.5"

    def test_delete_profile(self, temp_app_data):
        add_profile(IpProfile(name="Keep", ip="192.168.1.1"))
        add_profile(IpProfile(name="Delete", ip="10.0.0.1"))
        delete_profile("Delete")
        loaded = load_profiles()
        assert len(loaded) == 1
        assert loaded[0].name == "Keep"

    def test_load_empty(self, temp_app_data):
        loaded = load_profiles()
        assert loaded == []

    def test_load_corrupt(self, temp_app_data):
        # Write a corrupt JSON file
        path = temp_app_data / "ip_profiles.json"
        path.write_text("not valid json{{", encoding="utf-8")
        loaded = load_profiles()
        assert loaded == []


class TestHistory:
    def test_add_and_load(self, temp_app_data):
        entry = HistoryEntry(
            timestamp=datetime.now().isoformat(),
            adapter="Ethernet",
            old_dhcp=True, old_ip="", old_mask="", old_gateway="",
            new_dhcp=False, new_ip="192.168.1.100",
            new_mask="255.255.255.0", new_gateway="192.168.1.1",
        )
        add_history(entry)
        loaded = load_history()
        assert len(loaded) == 1
        assert loaded[0].adapter == "Ethernet"
        assert loaded[0].new_ip == "192.168.1.100"

    def test_most_recent_first(self, temp_app_data):
        for i in range(5):
            entry = HistoryEntry(
                timestamp=f"2026-01-0{i+1}T00:00:00",
                adapter="Eth",
                old_dhcp=False, old_ip="", old_mask="", old_gateway="",
                new_dhcp=False, new_ip=f"192.168.1.{i}",
                new_mask="255.255.255.0", new_gateway="",
            )
            add_history(entry)
        loaded = load_history()
        assert loaded[0].new_ip == "192.168.1.4"  # most recent first

    def test_history_cap(self, temp_app_data):
        for i in range(600):
            entry = HistoryEntry(
                timestamp=f"2026-01-01T00:00:{i:02d}",
                adapter="Eth",
                old_dhcp=False, old_ip="", old_mask="", old_gateway="",
                new_dhcp=False, new_ip=f"10.0.0.{i % 256}",
                new_mask="255.255.255.0", new_gateway="",
            )
            add_history(entry)
        loaded = load_history()
        # File should be capped at 500, but load_history returns up to limit=100
        assert len(loaded) <= 100

    def test_clear_history(self, temp_app_data):
        add_history(HistoryEntry(
            timestamp="2026-01-01T00:00:00", adapter="Eth",
            old_dhcp=False, old_ip="", old_mask="", old_gateway="",
            new_dhcp=True, new_ip="", new_mask="", new_gateway="",
        ))
        clear_history()
        assert load_history() == []

    def test_load_empty(self, temp_app_data):
        assert load_history() == []


class TestIpProfileDataclass:
    def test_defaults(self):
        p = IpProfile(name="Test")
        assert p.dhcp is False
        assert p.ip == ""
        assert p.subnet_mask == "255.255.255.0"
        assert p.gateway == ""
        assert p.location == ""
        assert p.created != ""

    def test_dhcp_profile(self):
        p = IpProfile(name="DHCP", dhcp=True)
        assert p.dhcp is True
        assert p.ip == ""
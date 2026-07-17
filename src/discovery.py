"""
jivesIpSwitcher — by jives
Discovery module: adapter enumeration, config reading, profile storage, history.

Layer 1 of 3 (model / discovery). No file mutations here — that's operations.py.
"""

import json
import subprocess
import re
import os
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


# ─── Data classes ────────────────────────────────────────────────────────────

@dataclass
class AdapterInfo:
    """A network adapter and its current IPv4 configuration."""
    name: str                 # Windows interface alias, e.g. "Ethernet"
    description: str          # Friendly description from netsh
    index: int                # Interface index (for netsh commands)
    is_up: bool               # Administrative state
    dhcp_enabled: bool
    ip_address: str           # Current IPv4, "" if none
    subnet_mask: str          # "255.255.255.0" or ""
    gateway: str              # "192.168.1.1" or ""
    dns_servers: list         # ["8.8.8.8", "8.8.4.4"] or []
    mac_address: str          # "AA-BB-CC-DD-EE-FF" or ""
    is_physical: bool         # True if not loopback/tunnel/virtual


@dataclass
class IpProfile:
    """A saved IP configuration that can be applied to any adapter."""
    name: str
    dhcp: bool = False
    ip: str = ""
    subnet_mask: str = "255.255.255.0"
    gateway: str = ""
    dns_primary: str = ""
    dns_secondary: str = ""
    location: str = ""          # Optional tag: "Office", "Site A", etc.
    adapter_hint: str = ""      # Preferred adapter name (informational)
    notes: str = ""
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    last_used: str = ""


@dataclass
class HistoryEntry:
    """A record of a configuration change applied to an adapter."""
    timestamp: str
    adapter: str
    old_dhcp: bool
    old_ip: str
    old_mask: str
    old_gateway: str
    new_dhcp: bool
    new_ip: str
    new_mask: str
    new_gateway: str
    profile_name: str = "manual"


# ─── Adapter enumeration ────────────────────────────────────────────────────

def _run_netsh(args: list, timeout: int = 10) -> str:
    """Run a netsh command and return stdout. Raises on non-zero exit."""
    result = subprocess.run(
        ["netsh"] + args,
        capture_output=True, text=True, timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if result.returncode != 0:
        raise RuntimeError(f"netsh failed: {result.stderr.strip()}")
    return result.stdout


def _run_ipconfig(timeout: int = 10) -> str:
    """Run ipconfig /all and return stdout."""
    result = subprocess.run(
        ["ipconfig", "/all"],
        capture_output=True, text=True, timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    return result.stdout


def enumerate_adapters() -> list[AdapterInfo]:
    """
    Enumerate all physical network adapters with current IPv4 config.
    Uses netsh interface ipv4 show config + ipconfig /all for MAC addresses.
    Filters out loopback, tunnel, and virtual adapters.
    """
    adapters: list[AdapterInfo] = []

    # Parse adapter list from netsh
    try:
        raw = _run_netsh(["interface", "ipv4", "show", "interfaces"])
    except RuntimeError:
        raw = ""

    # netsh "show interfaces" gives: Index  Metric  MTU   State  Name
    # We parse the table rows
    interface_rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Index") or line.startswith("---") or line.startswith("Admin"):
            continue
        parts = line.split(None, 4)
        if len(parts) >= 5:
            try:
                idx = int(parts[0])
            except ValueError:
                continue
            state = parts[3]
            name = parts[4].strip()
            interface_rows.append((idx, name, state == "connected"))

    # Get detailed config per interface
    try:
        config_raw = _run_netsh(["interface", "ipv4", "show", "config"])
    except RuntimeError:
        config_raw = ""

    # Parse per-adapter config blocks from "show config"
    # Format:
    # Configuration for interface "Ethernet"
    #     DHCP enabled:                         Yes
    #     IP Address:                            192.168.1.100
    #     Subnet Prefix:                         192.168.1.0/24 (mask 255.255.255.0)
    #     Default Gateway:                       192.168.1.1
    #     Gateway Metric:                        0
    #     Interface Metric:                      10
    #     DNS servers configured through DHCP:   192.168.1.1
    config_map: dict[str, dict] = {}
    current_name = None
    for line in config_raw.splitlines():
        m = re.match(r'^Configuration for interface "(.+)"', line)
        if m:
            current_name = m.group(1)
            config_map[current_name] = {
                "dhcp": False, "ip": "", "mask": "",
                "gateway": "", "dns": [],
            }
            continue
        if current_name is None:
            continue
        c = config_map[current_name]
        stripped = line.strip()
        if "DHCP enabled:" in stripped:
            c["dhcp"] = "yes" in stripped.lower()
        elif "IP Address:" in stripped:
            c["ip"] = stripped.split(":", 1)[1].strip()
        elif "Subnet Prefix:" in stripped:
            # 192.168.1.0/24 (mask 255.255.255.0)
            mm = re.search(r'mask\s+([\d.]+)', stripped)
            if mm:
                c["mask"] = mm.group(1)
        elif "Default Gateway:" in stripped:
            gw = stripped.split(":", 1)[1].strip()
            if gw and gw != "None":
                c["gateway"] = gw
        elif "DNS servers configured through" in stripped or "Statically Configured DNS Servers:" in stripped:
            pass  # DNS handled below
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', stripped):
            # Continuation DNS line or gateway continuation
            if c["gateway"] and stripped == c["gateway"]:
                pass
            else:
                c["dns"].append(stripped)

    # Get MAC addresses from ipconfig /all
    mac_map: dict[str, str] = {}
    try:
        ipconfig_raw = _run_ipconfig()
    except Exception:
        ipconfig_raw = ""

    current_adapter_name = None
    for line in ipconfig_raw.splitlines():
        # Adapter names appear as a line ending with ":"
        # e.g. "Ethernet adapter Ethernet:"
        m = re.match(r'^(.+?)\s+adapter\s+(.+):$', line)
        if m:
            current_adapter_name = m.group(2)
            continue
        if current_adapter_name and "Physical Address" in line:
            mac = line.split(":", 1)[1].strip()
            if mac and mac != "(00-00-00-00-00-00)":
                mac_map[current_adapter_name] = mac

    # Virtual/loopback filter keywords
    skip_keywords = ["loopback", "tunnel", "isatap", "teredo", "virtual",
                     "vpn", "ppp", "ras", "6to4", "virtualbox", "vmware",
                     "hyper-v", "bluetooth", "wi-fi direct"]

    for idx, name, is_up in interface_rows:
        cfg = config_map.get(name, {})
        mac = mac_map.get(name, "")

        is_physical = not any(kw in name.lower() for kw in skip_keywords)

        adapters.append(AdapterInfo(
            name=name,
            description=name,
            index=idx,
            is_up=is_up,
            dhcp_enabled=cfg.get("dhcp", False),
            ip_address=cfg.get("ip", ""),
            subnet_mask=cfg.get("mask", ""),
            gateway=cfg.get("gateway", ""),
            dns_servers=cfg.get("dns", []),
            mac_address=mac,
            is_physical=is_physical,
        ))

    # If netsh interfaces list was empty, fall back to config-only parse
    if not interface_rows and config_map:
        for name, cfg in config_map.items():
            is_physical = not any(kw in name.lower() for kw in skip_keywords)
            adapters.append(AdapterInfo(
                name=name,
                description=name,
                index=0,
                is_up=True,
                dhcp_enabled=cfg.get("dhcp", False),
                ip_address=cfg.get("ip", ""),
                subnet_mask=cfg.get("mask", ""),
                gateway=cfg.get("gateway", ""),
                dns_servers=cfg.get("dns", []),
                mac_address=mac_map.get(name, ""),
                is_physical=is_physical,
            ))

    return adapters


def get_adapter_by_name(name: str) -> Optional[AdapterInfo]:
    """Get a single adapter by its interface alias name."""
    for a in enumerate_adapters():
        if a.name == name:
            return a
    return None


def mask_to_prefix(mask: str) -> int:
    """Convert subnet mask like 255.255.255.0 to /24 prefix length."""
    if not mask:
        return 0
    octets = mask.split(".")
    if len(octets) != 4:
        return 0
    binary = "".join(bin(int(o))[2:].zfill(8) for o in octets)
    return binary.count("1")


def prefix_to_mask(prefix: int) -> str:
    """Convert /24 to 255.255.255.0."""
    bits = "1" * prefix + "0" * (32 - prefix)
    octets = [bits[i:i+8] for i in range(0, 32, 8)]
    return ".".join(str(int(o, 2)) for o in octets)


def validate_ip(ip: str) -> bool:
    """Basic IPv4 validation."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def validate_mask(mask: str) -> bool:
    """Validate a subnet mask is a valid contiguous mask."""
    if not validate_ip(mask):
        return False
    prefix = mask_to_prefix(mask)
    bits = "1" * prefix + "0" * (32 - prefix)
    expected = ".".join(str(int(bits[i:i+8], 2)) for i in range(0, 32, 8))
    return mask == expected


# ─── Profile storage ────────────────────────────────────────────────────────

PROFILES_FILE = "ip_profiles.json"
HISTORY_FILE = "ip_history.json"


def _get_app_data_dir() -> Path:
    """Get the app data directory. Uses %APPDATA% on Windows, falls back to home."""
    base = os.environ.get("APPDATA") or os.environ.get("USERPROFILE") or str(Path.home())
    return Path(base) / "jivesIpSwitcher"


def load_profiles() -> list[IpProfile]:
    """Load all saved IP profiles from JSON storage."""
    path = _get_app_data_dir() / PROFILES_FILE
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [IpProfile(**p) for p in data]
    except (json.JSONDecodeError, TypeError):
        return []


def save_profiles(profiles: list[IpProfile]) -> None:
    """Save profiles to JSON storage."""
    d = _get_app_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / PROFILES_FILE
    path.write_text(
        json.dumps([asdict(p) for p in profiles], indent=2),
        encoding="utf-8",
    )


def add_profile(profile: IpProfile) -> list[IpProfile]:
    """Add or replace a profile by name, return updated list."""
    profiles = load_profiles()
    profiles = [p for p in profiles if p.name != profile.name]
    profiles.append(profile)
    save_profiles(profiles)
    return profiles


def delete_profile(name: str) -> list[IpProfile]:
    """Delete a profile by name, return updated list."""
    profiles = [p for p in load_profiles() if p.name != name]
    save_profiles(profiles)
    return profiles


def update_profile_used(name: str) -> None:
    """Update the last_used timestamp on a profile."""
    profiles = load_profiles()
    for p in profiles:
        if p.name == name:
            p.last_used = datetime.now().isoformat()
            break
    save_profiles(profiles)


# ─── History ─────────────────────────────────────────────────────────────────

def load_history(limit: int = 100) -> list[HistoryEntry]:
    """Load config change history, most recent first."""
    path = _get_app_data_dir() / HISTORY_FILE
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = [HistoryEntry(**e) for e in data]
        entries.reverse()  # most recent first
        return entries[:limit]
    except (json.JSONDecodeError, TypeError):
        return []


def add_history(entry: HistoryEntry) -> None:
    """Add a history entry."""
    d = _get_app_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / HISTORY_FILE
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
    existing.append(asdict(entry))
    # Cap at 500 entries
    if len(existing) > 500:
        existing = existing[-500:]
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def clear_history() -> None:
    """Clear all history."""
    d = _get_app_data_dir()
    path = d / HISTORY_FILE
    if path.exists():
        path.unlink()
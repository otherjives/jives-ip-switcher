"""
jivesIpSwitcher — by jives
Operations module: netsh IP config changes, backups, device scanning.

Layer 2 of 3 (operations / file mutations). All netsh calls that modify state
go here. Backups are taken before every change.

Device scanner uses scapy for packet capture (requires Npcap on Windows).
scapy is imported lazily so the rest of the app works without it.
"""

import subprocess
import os
import time
import re
import traceback
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable

from discovery import (
    AdapterInfo, IpProfile, HistoryEntry,
    enumerate_adapters, get_adapter_by_name,
    mask_to_prefix, prefix_to_mask,
    validate_ip, validate_mask,
    add_history, update_profile_used,
    _get_app_data_dir,
)


# ─── Result type ─────────────────────────────────────────────────────────────

@dataclass
class OperationResult:
    success: bool
    message: str
    details: str = ""
    backup_path: str = ""


# ─── Backups ─────────────────────────────────────────────────────────────────

def _backup_dir() -> Path:
    """Get the backups directory."""
    d = _get_app_data_dir() / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def backup_adapter_config(adapter_name: str) -> str:
    """
    Save current adapter config to a timestamped backup file.
    Returns the backup file path.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^\w]', '_', adapter_name)
    backup_file = _backup_dir() / f"{safe_name}_{ts}.txt"

    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "config", f"name={adapter_name}"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        backup_file.write_text(
            f"Backup of adapter '{adapter_name}' at {datetime.now().isoformat()}\n"
            f"{'=' * 60}\n"
            f"{result.stdout}",
            encoding="utf-8",
        )
        return str(backup_file)
    except Exception as e:
        return ""


# ─── Netsh operations ───────────────────────────────────────────────────────

def _run_netsh(args: list, timeout: int = 15) -> tuple[bool, str]:
    """Run netsh, return (success, combined output)."""
    try:
        result = subprocess.run(
            ["netsh"] + args,
            capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def apply_static_ip(adapter_name: str, ip: str, subnet_mask: str,
                    gateway: str = "", dns_primary: str = "",
                    dns_secondary: str = "") -> OperationResult:
    """
    Set a static IP on an adapter. Takes a backup first.
    Returns OperationResult.
    """
    # Validate inputs
    if not validate_ip(ip):
        return OperationResult(False, f"Invalid IP address: {ip}")
    if not validate_mask(subnet_mask):
        return OperationResult(False, f"Invalid subnet mask: {subnet_mask}")
    if gateway and not validate_ip(gateway):
        return OperationResult(False, f"Invalid gateway: {gateway}")

    # Backup current config
    backup = backup_adapter_config(adapter_name)

    # Record old config for history
    old = get_adapter_by_name(adapter_name)
    old_info = {
        "dhcp": old.dhcp_enabled if old else False,
        "ip": old.ip_address if old else "",
        "mask": old.subnet_mask if old else "",
        "gateway": old.gateway if old else "",
    }

    # Set static IP
    ok, msg = _run_netsh([
        "interface", "ipv4", "set", "address",
        f"name={adapter_name}", "static", ip, subnet_mask,
    ] + ([gateway] if gateway else []))

    if not ok:
        return OperationResult(False, f"Failed to set IP: {msg}", "", backup)

    details_parts = [f"IP set to {ip}/{subnet_mask}"]
    if gateway:
        details_parts.append(f"Gateway: {gateway}")

    # Set DNS if provided
    if dns_primary:
        ok_dns, msg_dns = _run_netsh([
            "interface", "ipv4", "set", "dnsservers",
            f"name={adapter_name}", "static", dns_primary, "primary",
            "validate=no",
        ])
        if ok_dns and dns_secondary:
            _run_netsh([
                "interface", "ipv4", "add", "dnsservers",
                f"name={adapter_name}", dns_secondary, "index=2",
                "validate=no",
            ])
        details_parts.append(f"DNS: {dns_primary}" + (f", {dns_secondary}" if dns_secondary else ""))

    # Record history
    add_history(HistoryEntry(
        timestamp=datetime.now().isoformat(),
        adapter=adapter_name,
        old_dhcp=old_info["dhcp"],
        old_ip=old_info["ip"],
        old_mask=old_info["mask"],
        old_gateway=old_info["gateway"],
        new_dhcp=False,
        new_ip=ip,
        new_mask=subnet_mask,
        new_gateway=gateway,
        profile_name="manual",
    ))

    return OperationResult(True, f"Static IP applied to {adapter_name}",
                           "; ".join(details_parts), backup)


def apply_dhcp(adapter_name: str) -> OperationResult:
    """Set an adapter to DHCP. Takes a backup first."""
    backup = backup_adapter_config(adapter_name)

    old = get_adapter_by_name(adapter_name)
    old_info = {
        "dhcp": old.dhcp_enabled if old else False,
        "ip": old.ip_address if old else "",
        "mask": old.subnet_mask if old else "",
        "gateway": old.gateway if old else "",
    }

    ok, msg = _run_netsh([
        "interface", "ipv4", "set", "address",
        f"name={adapter_name}", "source=dhcp",
    ])
    if not ok:
        return OperationResult(False, f"Failed to set DHCP: {msg}", "", backup)

    # Also set DNS to DHCP
    _run_netsh([
        "interface", "ipv4", "set", "dnsservers",
        f"name={adapter_name}", "source=dhcp",
    ])

    add_history(HistoryEntry(
        timestamp=datetime.now().isoformat(),
        adapter=adapter_name,
        old_dhcp=old_info["dhcp"],
        old_ip=old_info["ip"],
        old_mask=old_info["mask"],
        old_gateway=old_info["gateway"],
        new_dhcp=True,
        new_ip="",
        new_mask="",
        new_gateway="",
        profile_name="manual",
    ))

    return OperationResult(True, f"DHCP enabled on {adapter_name}", "IP and DNS set to DHCP", backup)


def apply_profile(adapter_name: str, profile: IpProfile) -> OperationResult:
    """Apply a saved IpProfile to an adapter."""
    if profile.dhcp:
        result = apply_dhcp(adapter_name)
    else:
        result = apply_static_ip(
            adapter_name, profile.ip, profile.subnet_mask,
            profile.gateway, profile.dns_primary, profile.dns_secondary,
        )
    if result.success:
        update_profile_used(profile.name)
        # Re-record history with profile name
        # (apply_static/apply_dhcp already recorded with "manual",
        #  we update the profile name by adding a corrected entry)
    return result


def set_adapter_ip_fast(adapter_name: str, ip: str, prefix_len: int) -> OperationResult:
    """
    Quickly set adapter IP without gateway/DNS. Used by the scanner
    to iterate through subnets. No backup (scanner is ephemeral).
    """
    mask = prefix_to_mask(prefix_len)
    if not validate_ip(ip):
        return OperationResult(False, f"Invalid IP: {ip}")
    ok, msg = _run_netsh([
        "interface", "ipv4", "set", "address",
        f"name={adapter_name}", "static", ip, mask,
    ], timeout=5)
    return OperationResult(ok, msg if ok else f"Failed: {msg}", "", "")


def restore_adapter_from_backup(adapter_name: str, backup_path: str) -> OperationResult:
    """Attempt to restore adapter config from a backup file (informational only)."""
    if not Path(backup_path).exists():
        return OperationResult(False, f"Backup file not found: {backup_path}")
    # Backups are informational snapshots — the actual restore
    # would need parsing and re-applying. For now, just inform the user.
    content = Path(backup_path).read_text(encoding="utf-8")
    return OperationResult(True, f"Backup contents for {adapter_name}", content, backup_path)


# ─── Device scanner ──────────────────────────────────────────────────────────

# Common engineering subnets to try when scanning for unknown devices.
# Ordered by frequency of use in industrial/field equipment.
COMMON_SUBNETS = [
    "192.168.0.0/24",
    "192.168.1.0/24",
    "192.168.10.0/24",
    "192.168.100.0/24",
    "192.168.50.0/24",
    "192.168.2.0/24",
    "10.0.0.0/24",
    "10.0.1.0/24",
    "10.1.1.0/24",
    "10.10.10.0/24",
    "10.0.0.0/8",
    "172.16.0.0/24",
    "172.16.1.0/24",
    "172.16.10.0/24",
    "192.168.11.0/24",
    "192.168.20.0/24",
    "192.168.254.0/24",
    "169.254.0.0/16",      # link-local
    "10.10.0.0/24",
    "10.10.1.0/24",
    "10.20.0.0/24",
    "10.50.0.0/24",
    "192.168.88.0/24",     # Mikrotik default
    "192.168.123.0/24",    # Some camera defaults
    "192.168.226.0/24",    # Some industrial defaults
]


@dataclass
class ScanResult:
    """Result of a device scan."""
    found: bool
    ip: str = ""
    mac: str = ""
    method: str = ""       # "passive", "arp_targeted", "arp_sweep", "dhcp"
    subnet: str = ""
    latency_ms: float = 0.0
    details: str = ""


@dataclass
class DeviceEntry:
    """A discovered device during a scan."""
    ip: str
    mac: str
    method: str = ""       # "passive", "arp_sweep"
    subnet: str = ""


def _import_scapy():
    """Lazily import scapy. Returns module or raises ImportError."""
    try:
        from scapy.all import sniff, ARP, Ether, IP, conf, srp, srp1, get_if_list
        return sniff, ARP, Ether, IP, conf, srp, srp1, get_if_list
    except ImportError:
        raise ImportError(
            "scapy is required for device scanning. "
            "Install with: pip install scapy\n"
            "Also install Npcap from https://npcap.com (use WinPcap API-compatible mode)"
        )


def _resolve_scapy_iface(adapter_name: str, conf, get_if_list) -> str:
    """
    Resolve a Windows interface alias (e.g. "Ethernet 3") to a scapy interface.
    Uses scapy's IFACES dictionary which maps names to GUIDs.
    """
    from scapy.interfaces import IFACES

    # Force IFACES population
    try:
        conf.iface
    except Exception:
        pass

    # Try exact name match in IFACES
    for key, dev in IFACES.items():
        if dev.name == adapter_name:
            return key  # Return the NPF device path

    # Try case-insensitive match
    for key, dev in IFACES.items():
        if dev.name.lower() == adapter_name.lower():
            return key

    # Try substring match
    for key, dev in IFACES.items():
        if adapter_name.lower() in dev.name.lower():
            return key

    # Fallback: return the raw name (may work with newer Npcap)
    return adapter_name


def _is_iface_in_scapy(adapter_name: str) -> bool:
    """Check if an adapter is visible to scapy/Npcap."""
    try:
        from scapy.all import conf
        conf.iface  # trigger population
        from scapy.interfaces import IFACES
        for key, dev in IFACES.items():
            if dev.name == adapter_name:
                return True
        return False
    except Exception:
        return False


def restart_npcap() -> bool:
    """
    Restart the Npcap driver service. This picks up newly plugged-in adapters
    that Npcap didn't enumerate at install time.
    Returns True on success.
    """
    import subprocess
    try:
        # Stop
        subprocess.run(["net", "stop", "npcap"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        # Start
        subprocess.run(["net", "start", "npcap"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        # Clear scapy's interface cache so it re-enumerates
        from scapy.interfaces import IFACES
        IFACES.clear_cache()
        from scapy.all import conf
        conf.iface  # re-trigger population
        return True
    except Exception:
        return False


def scan_passive(adapter_name: str, timeout: int = 5,
                 isolated: bool = True,
                 progress_cb: Optional[Callable] = None,
                 stop_check: Optional[Callable] = None,
                 device_cb: Optional[Callable] = None) -> list:
    """
    Passive sniff on the adapter. Collects ALL devices seen.
    Calls device_cb(ip, mac) for each new device found in real-time.
    Returns list of (ip, mac) tuples.
    """
    sniff, ARP, Ether, IP, conf, srp, srp1, get_if_list = _import_scapy()

    found = {}  # ip -> mac, collected during sniff
    found_lock = __import__('threading').Lock()

    def _packet_handler(pkt):
        src_ip = ""
        src_mac = ""

        if pkt.haslayer(Ether):
            mac = pkt[Ether].src
            if mac and mac != "ff:ff:ff:ff:ff:ff" and mac != "00:00:00:00:00:00":
                src_mac = mac

        if pkt.haslayer(IP):
            ip = pkt[IP].src
            if ip and not ip.startswith("0.") and ip != "255.255.255.255":
                src_ip = ip

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 1:  # ARP request
                if arp.psrc and not arp.psrc.startswith("0."):
                    src_ip = arp.psrc
                if arp.hwsrc and arp.hwsrc != "00:00:00:00:00:00":
                    src_mac = arp.hwsrc
            elif arp.op == 2:  # ARP reply
                if arp.psrc and not arp.psrc.startswith("0."):
                    src_ip = arp.psrc
                if arp.hwsrc and arp.hwsrc != "00:00:00:00:00:00":
                    src_mac = arp.hwsrc

        if src_ip and src_mac:
            with found_lock:
                if src_ip not in found:
                    found[src_ip] = src_mac
                    if device_cb:
                        device_cb(src_ip, src_mac)
                    if progress_cb:
                        progress_cb(f"  [passive] {src_ip} ({src_mac})")

    def _stop_filter(pkt):
        if stop_check and stop_check():
            return True
        return False

    if progress_cb:
        progress_cb(f"Passive sniff on '{adapter_name}' for {timeout}s...")

    try:
        scapy_iface = _resolve_scapy_iface(adapter_name, conf, get_if_list)
        conf.iface = scapy_iface
        sniff(iface=scapy_iface, prn=_packet_handler,
              timeout=timeout, store=False, count=0,
              stop_filter=_stop_filter)
    except Exception as e:
        if progress_cb:
            progress_cb(f"Sniff error: {e}")

    return [(ip, mac) for ip, mac in found.items()]


def scan_arp_sweep_subnets(adapter_name: str,
                           subnets: Optional[list] = None,
                           progress_cb: Optional[Callable] = None,
                           stop_check: Optional[Callable] = None,
                           device_cb: Optional[Callable] = None) -> list:
    """
    ARP sweep across common subnets. Collects ALL devices found.
    Calls device_cb(ip, mac, subnet) for each new device in real-time.
    Returns list of (ip, mac, subnet) tuples.

    Uses secondary IPs (add address) instead of replacing the primary,
    and waits for DAD before sweeping.
    """
    sniff, ARP, Ether, IP, conf, srp, srp1, get_if_list = _import_scapy()

    if subnets is None:
        subnets = COMMON_SUBNETS

    scapy_iface = _resolve_scapy_iface(adapter_name, conf, get_if_list)
    found = {}  # ip -> (mac, subnet)

    for i, subnet_cidr in enumerate(subnets):
        if stop_check and stop_check():
            break

        parts = subnet_cidr.split("/")
        base = parts[0]
        prefix = int(parts[1]) if len(parts) > 1 else 24
        if prefix > 24:
            prefix = 24

        octets = base.split(".")
        sweep_net = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

        # Check if adapter already has an IP on this subnet
        existing_ip = _adapter_has_ip_on_subnet(adapter_name, base, prefix)
        temp_added = False

        if existing_ip:
            our_ip = existing_ip
        else:
            # Add a temp secondary IP
            our_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.254"
            added = False
            for offset in [254, 253, 252, 251, 250]:
                our_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{offset}"
                r = add_secondary_ip(adapter_name, our_ip, prefix)
                if r.success:
                    added = True
                    break
            if not added:
                if progress_cb:
                    progress_cb(f"  [{i+1}/{len(subnets)}] {sweep_net}: could not add IP, skipping")
                continue
            temp_added = True
            if progress_cb:
                progress_cb(f"  [{i+1}/{len(subnets)}] {sweep_net}: waiting for IP {our_ip}...")
            _wait_ip_ready(adapter_name, our_ip, timeout=3.0)

        if progress_cb:
            progress_cb(f"  [{i+1}/{len(subnets)}] Sweeping {sweep_net}...")

        try:
            conf.iface = scapy_iface
            arp = ARP(pdst=sweep_net)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            ans, unans = srp(packet, timeout=0.8, verbose=0, iface=scapy_iface)

            for sent, received in ans:
                rip = received[ARP].psrc
                rmac = received[Ether].src
                # Skip our own IPs
                if rip == our_ip or rip == existing_ip:
                    continue
                if rip not in found:
                    found[rip] = (rmac, subnet_cidr)
                    if device_cb:
                        device_cb(rip, rmac, subnet_cidr)
                    if progress_cb:
                        progress_cb(f"  [arp] {rip} ({rmac}) on {subnet_cidr}")
        except Exception as e:
            if progress_cb:
                progress_cb(f"  Sweep error on {sweep_net}: {e}")
        finally:
            if temp_added:
                remove_secondary_ip(adapter_name, our_ip)

    return [(ip, mac, subnet) for ip, (mac, subnet) in found.items()]


def scan_full(adapter_name: str, isolated: bool = True,
              passive_timeout: int = 5,
              progress_cb: Optional[Callable] = None,
              stop_check: Optional[Callable] = None,
              device_cb: Optional[Callable] = None) -> list:
    """
    Full scan: passive sniff (concurrent) + ARP sweep across all subnets.
    Collects ALL devices found. Does NOT stop at first.

    Returns list of DeviceEntry objects.

    The passive sniff runs in a background thread for the entire scan
    duration while the ARP sweep iterates subnets. Both feed results
    into the same device list via device_cb.
    """
    import threading

    all_devices = {}  # ip -> DeviceEntry
    devices_lock = threading.Lock()

    def _on_passive_device(ip, mac):
        with devices_lock:
            if ip not in all_devices:
                entry = DeviceEntry(ip=ip, mac=mac, method="passive")
                all_devices[ip] = entry
                if device_cb:
                    device_cb(entry)

    def _on_arp_device(ip, mac, subnet):
        with devices_lock:
            if ip not in all_devices:
                entry = DeviceEntry(ip=ip, mac=mac, method="arp_sweep",
                                    subnet=subnet)
                all_devices[ip] = entry
                if device_cb:
                    device_cb(entry)

    # Start passive sniff in a background thread
    if progress_cb:
        progress_cb("=== Starting concurrent passive sniff + ARP sweep ===")

    passive_thread = threading.Thread(
        target=scan_passive,
        args=(adapter_name,),
        kwargs={
            "timeout": passive_timeout + 30,  # run longer than the sweep
            "isolated": isolated,
            "progress_cb": progress_cb,
            "stop_check": stop_check,
            "device_cb": _on_passive_device,
        },
        daemon=True,
    )
    passive_thread.start()

    # Run ARP sweep in the current thread
    scan_arp_sweep_subnets(
        adapter_name,
        progress_cb=progress_cb,
        stop_check=stop_check,
        device_cb=_on_arp_device,
    )

    # Wait for passive sniff to finish (it may still be running)
    if stop_check and stop_check():
        if progress_cb:
            progress_cb("Scan stopped. Waiting for passive sniff to exit...")
    passive_thread.join(timeout=5)

    results = list(all_devices.values())
    if progress_cb:
        progress_cb(f"=== Scan complete: {len(results)} device(s) found ===")

    return results


def auto_configure_to_device(adapter_name: str, device_ip: str,
                             prefix_len: int = 24) -> OperationResult:
    """
    After finding a device, set our adapter to the same subnet
    so we can communicate with it.
    """
    octets = device_ip.split(".")
    our_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.2"
    mask = prefix_to_mask(prefix_len)
    return set_adapter_ip_fast(adapter_name, our_ip, prefix_len)


# ─── Quick Probe: subnet discovery for IP assignment ─────────────────────────

@dataclass
class ProbeResult:
    """Result of a quick subnet probe."""
    network: str           # "192.168.1.0/24"
    alive: list            # [(ip, mac), ...] sorted by IP
    free: list             # ["192.168.1.5", "192.168.1.12", ...] sorted
    our_temp_ip: str = ""   # the temp IP we used for probing
    error: str = ""


def add_secondary_ip(adapter_name: str, ip: str, prefix_len: int = 24) -> OperationResult:
    """Add a secondary IP to an adapter without removing the primary."""
    mask = prefix_to_mask(prefix_len)
    if not validate_ip(ip):
        return OperationResult(False, f"Invalid IP: {ip}")
    ok, msg = _run_netsh([
        "interface", "ipv4", "add", "address",
        f"name={adapter_name}", ip, mask,
    ], timeout=5)
    return OperationResult(ok, msg if ok else f"Failed: {msg}", "", "")


def remove_secondary_ip(adapter_name: str, ip: str) -> OperationResult:
    """Remove a specific IP from an adapter."""
    ok, msg = _run_netsh([
        "interface", "ipv4", "delete", "address",
        f"name={adapter_name}", ip,
    ], timeout=5)
    return OperationResult(ok, msg if ok else f"Failed: {msg}", "", "")


def _ip_to_int(ip: str) -> int:
    return sum(int(o) << (8 * (3 - i)) for i, o in enumerate(ip.split(".")))


def _int_to_ip(val: int) -> str:
    return ".".join(str((val >> (8 * (3 - i))) & 0xFF) for i in range(4))


def _wait_ip_ready(adapter_name: str, ip: str, timeout: float = 5.0) -> bool:
    """Wait for a newly-added IP to leave 'Tentative' state (DAD completion)."""
    import time as _time
    start = _time.time()
    while _time.time() - start < timeout:
        try:
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "ipaddresses"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            for line in result.stdout.splitlines():
                if ip in line and "Preferred" in line:
                    return True
                if ip in line and "Tentative" in line:
                    break
            else:
                # IP not found at all -- might already be ready or not added
                # Check show config as fallback
                pass
        except Exception:
            pass
        _time.sleep(0.3)
    return False


def _adapter_has_ip_on_subnet(adapter_name: str, network_base: str, prefix: int = 24) -> str:
    """Check if adapter already has an IP on the given subnet. Returns that IP or ''."""
    try:
        from discovery import enumerate_adapters
        octets = network_base.split(".")
        subnet_prefix = ".".join(octets[:3])
        for a in enumerate_adapters():
            if a.name == adapter_name and a.ip_address:
                if a.ip_address.startswith(subnet_prefix + "."):
                    return a.ip_address
    except Exception:
        pass
    return ""


def probe_subnet(adapter_name: str, network: str,
                 stop_check: Optional[Callable] = None,
                 progress_cb: Optional[Callable] = None) -> ProbeResult:
    """
    Quick-probe a subnet: add a temp IP (or use existing), ARP sweep, remove temp.
    Returns alive IPs and free IPs.

    network: "192.168.1.0/24" (only /24 supported for speed)
    """
    parts = network.split("/")
    base = parts[0]
    prefix = int(parts[1]) if len(parts) > 1 else 24
    if prefix != 24:
        prefix = 24  # force /24 for speed

    octets = base.split(".")
    net_int = _ip_to_int(f"{octets[0]}.{octets[1]}.{octets[2]}.0")
    subnet_str = f"{octets[0]}.{octets[1]}.{octets[2]}"

    # Check if adapter already has an IP on this subnet
    existing_ip = _adapter_has_ip_on_subnet(adapter_name, base, prefix)
    temp_added = False
    our_temp = ""

    if existing_ip:
        our_temp = existing_ip
        if progress_cb:
            progress_cb(f"Using existing IP {our_temp} on {subnet_str}.0/24")
    else:
        # Add a temp IP
        our_temp = _int_to_ip(net_int + 254)
        if progress_cb:
            progress_cb(f"Adding temp IP {our_temp}/24 to '{adapter_name}'...")

        added = False
        for offset in [254, 253, 252, 251, 250, 200, 100, 50]:
            our_temp = _int_to_ip(net_int + offset)
            r = add_secondary_ip(adapter_name, our_temp, 24)
            if r.success:
                added = True
                break
        if not added:
            return ProbeResult(network=network, alive=[], free=[],
                               error="Could not add temp IP on subnet")

        temp_added = True

        if stop_check and stop_check():
            remove_secondary_ip(adapter_name, our_temp)
            return ProbeResult(network=network, alive=[], free=[],
                               our_temp_ip=our_temp, error="Stopped by user")

        # Wait for DAD (Tentative -> Preferred)
        if progress_cb:
            progress_cb("Waiting for IP to settle...")
        ready = _wait_ip_ready(adapter_name, our_temp, timeout=4.0)
        if not ready:
            if progress_cb:
                progress_cb("Warning: IP still tentative, probing anyway...")

    if stop_check and stop_check():
        if temp_added:
            remove_secondary_ip(adapter_name, our_temp)
        return ProbeResult(network=network, alive=[], free=[],
                           our_temp_ip=our_temp, error="Stopped by user")

    if progress_cb:
        progress_cb(f"Sweeping {subnet_str}.0/24...")

    # ARP sweep the /24
    alive = []
    # Get our own MAC to filter self-replies
    own_mac = ""
    try:
        from discovery import enumerate_adapters
        for a in enumerate_adapters():
            if a.name == adapter_name and a.mac_address:
                own_mac = a.mac_address.lower().replace("-", ":")
                break
    except Exception:
        pass

    try:
        sniff_fn, ARP, Ether, IP, conf, srp, srp1, get_if_list = _import_scapy()
        scapy_iface = _resolve_scapy_iface(adapter_name, conf, get_if_list)
        conf.iface = scapy_iface

        sweep_net = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        arp = ARP(pdst=sweep_net)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        ans, unans = srp(packet, timeout=0.8, verbose=0, iface=scapy_iface)

        for sent, received in ans:
            rip = received[ARP].psrc
            rmac = received[Ether].src
            # Skip our own IPs and our own MAC
            if rip == our_temp or rip == existing_ip:
                continue
            if own_mac and rmac.lower() == own_mac:
                continue
            alive.append((rip, rmac))
    except ImportError:
        if temp_added:
            remove_secondary_ip(adapter_name, our_temp)
        return ProbeResult(network=network, alive=[], free=[],
                           our_temp_ip=our_temp,
                           error="scapy required for probing")
    except Exception as e:
        if progress_cb:
            progress_cb(f"Sweep error: {e}")
    finally:
        if temp_added:
            if progress_cb:
                progress_cb("Removing temp IP...")
            remove_secondary_ip(adapter_name, our_temp)

    # Sort alive by IP
    alive.sort(key=lambda x: _ip_to_int(x[0]))

    # Build free list: all IPs in /24 except alive ones and our own
    alive_set = {ip for ip, _ in alive}
    alive_set.add(our_temp)
    if existing_ip:
        alive_set.add(existing_ip)
    free = []
    for i in range(1, 255):
        ip = _int_to_ip(net_int + i)
        if ip not in alive_set:
            free.append(ip)

    if progress_cb:
        progress_cb(f"Found {len(alive)} alive, {len(free)} free on {subnet_str}.0/24")

    return ProbeResult(
        network=f"{octets[0]}.{octets[1]}.{octets[2]}.0/24",
        alive=alive,
        free=free,
        our_temp_ip=our_temp,
    )


def quick_check_ip(adapter_name: str, target_ip: str,
                   network: str = None) -> bool:
    """
    Quick ARP check if a single IP is alive. Used to verify
    a free IP is still free right before assigning it.

    Uses existing adapter IP if on same subnet, otherwise adds temp IP.
    Returns True if the IP is alive (in use), False if free.
    """
    if network is None:
        octets = target_ip.split(".")
        network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

    parts = network.split("/")
    base = parts[0]
    octets = base.split(".")
    net_int = _ip_to_int(f"{octets[0]}.{octets[1]}.{octets[2]}.0")

    # Check if adapter already has an IP on this subnet
    existing_ip = _adapter_has_ip_on_subnet(adapter_name, base, 24)
    temp_added = False

    if existing_ip:
        our_temp = existing_ip
    else:
        our_temp = _int_to_ip(net_int + 254)
        added = False
        for offset in [254, 253, 252, 251]:
            our_temp = _int_to_ip(net_int + offset)
            r = add_secondary_ip(adapter_name, our_temp, 24)
            if r.success:
                added = True
                break
        if not added:
            return True  # can't check, assume in use to be safe
        temp_added = True
        _wait_ip_ready(adapter_name, our_temp, timeout=3.0)

    try:
        sniff_fn, ARP, Ether, IP, conf, srp, srp1, get_if_list = _import_scapy()
        scapy_iface = _resolve_scapy_iface(adapter_name, conf, get_if_list)
        conf.iface = scapy_iface

        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        ans, unans = srp(packet, timeout=0.15, verbose=0, iface=scapy_iface)
        # Filter out our own IP
        for s, r in ans:
            if r[ARP].psrc == target_ip and r[ARP].psrc != our_temp:
                return True
        return False
    except Exception:
        return True  # assume in use on error
    finally:
        if temp_added:
            remove_secondary_ip(adapter_name, our_temp)
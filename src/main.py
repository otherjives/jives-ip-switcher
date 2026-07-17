"""
jivesIpSwitcher — by jives
Main GUI Application

Two tabs:
1. IP Config — set/store/restore IP configurations on network adapters
2. Device Scanner — find unknown devices by passive sniff + ARP sweep

Architecture: discovery (model) → operations (mutations) → main (GUI)
See workbenchSetupTool-RETROSPECTIVE.md for patterns followed.
"""

import sys
import os
import traceback
from pathlib import Path
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QComboBox, QCheckBox, QTreeWidget, QTreeWidgetItem,
    QProgressBar, QTextEdit, QGroupBox, QLineEdit, QSpinBox,
    QTabWidget, QHeaderView, QSplitter, QMessageBox, QInputDialog,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QButtonGroup, QRadioButton,
)
from PySide6.QtGui import QFont, QColor, QAction, QKeyEvent

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─── IP Octet Spinbox ────────────────────────────────────────────────────────

class IpOctetSpinBox(QSpinBox):
    """
    QSpinBox for a single IP octet (0-255).
    - Typing '.' moves focus to the next octet (auto-advance).
    - Focus-in selects all text ready for overtype.
    """
    octet_changed = Signal()  # emitted when value changes (for gateway auto-calc)

    def __init__(self, next_spin=None, parent=None):
        super().__init__(parent)
        self.setRange(0, 255)
        self._next_spin = next_spin
        # Select all on focus so typing replaces content
        self.lineEdit().setSelection(0, len(self.text()))

    def set_next_spin(self, spin):
        self._next_spin = spin

    def focusInEvent(self, event):
        super().focusInEvent(event)
        # Select all text when receiving focus (ready for typing)
        self.lineEdit().selectAll()

    def keyPressEvent(self, event: QKeyEvent):
        # '.' or period on main keyboard → advance to next octet
        if event.text() == ".":
            if self._next_spin is not None:
                self._next_spin.setFocus()
                self._next_spin.lineEdit().selectAll()
            return  # consume the event, don't insert '.'
        super().keyPressEvent(event)

from discovery import (
    enumerate_adapters, get_adapter_by_name,
    IpProfile, HistoryEntry,
    load_profiles, save_profiles, add_profile, delete_profile,
    update_profile_used, load_history, clear_history,
    mask_to_prefix, prefix_to_mask, validate_ip, validate_mask,
)
from operations import (
    apply_static_ip, apply_dhcp, apply_profile,
    OperationResult, ScanResult, ProbeResult, DeviceEntry,
    scan_full, auto_configure_to_device,
    set_adapter_ip_fast,
    _is_iface_in_scapy, restart_npcap,
    probe_subnet, quick_check_ip,
)


# ─── Theme ──────────────────────────────────────────────────────────────────

DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Segoe UI", "Arial";
    font-size: 9pt;
}
QGroupBox {
    border: 1px solid #3a3a5c;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: bold;
    color: #7b68ee;
}
QGroupBox::title {
    left: 8px;
    padding: 0 4px;
}
QPushButton {
    background-color: #2a2a4e;
    border: 1px solid #7b68ee;
    border-radius: 3px;
    padding: 5px 14px;
    color: #e0e0e0;
    min-height: 22px;
}
QPushButton:hover {
    background-color: #7b68ee;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #5b48ce;
}
QPushButton:disabled {
    background-color: #2a2a3e;
    border-color: #3a3a5c;
    color: #666;
}
QComboBox, QSpinBox, QLineEdit {
    background-color: #2a2a4e;
    border: 1px solid #3a3a5c;
    border-radius: 3px;
    padding: 3px 6px;
    color: #e0e0e0;
    min-height: 22px;
}
QComboBox:hover, QSpinBox:hover, QLineEdit:hover {
    border-color: #7b68ee;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #2a2a4e;
    border: 1px solid #3a3a5c;
    selection-background-color: #7b68ee;
}
QTreeWidget, QListWidget, QTableWidget {
    background-color: #2a2a4e;
    border: 1px solid #3a3a5c;
    border-radius: 3px;
    alternate-background-color: #252544;
}
QTreeWidget::item, QListWidget::item, QTableWidget::item {
    padding: 2px;
    min-height: 18px;
}
QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
    background-color: #7b68ee;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #2a2a4e;
    border: none;
    padding: 4px;
    font-weight: bold;
    color: #7b68ee;
}
QProgressBar {
    background-color: #2a2a4e;
    border: 1px solid #3a3a5c;
    border-radius: 3px;
    text-align: center;
    height: 20px;
}
QProgressBar::chunk {
    background-color: #7b68ee;
    border-radius: 2px;
}
QTextEdit {
    background-color: #1e1e38;
    border: 1px solid #3a3a5c;
    border-radius: 3px;
    font-family: "Consolas", "Courier New";
    font-size: 9pt;
}
QTabWidget::pane {
    border: 1px solid #3a3a5c;
    border-radius: 3px;
}
QTabWidget::tab-bar {
    alignment: left;
}
QTabBar::tab {
    background-color: #2a2a4e;
    border: 1px solid #3a3a5c;
    border-bottom: none;
    padding: 6px 16px;
    color: #999;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #7b68ee;
    color: #ffffff;
    border-color: #7b68ee;
}
QTabBar::tab:hover:!selected {
    background-color: #3a3a5c;
}
QCheckBox {
    spacing: 6px;
    color: #e0e0e0;
}
QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #7b68ee;
    border-radius: 2px;
    background-color: #2a2a4e;
}
QCheckBox::indicator:checked {
    background-color: #7b68ee;
}
QLabel {
    color: #e0e0e0;
}
QSplitter::handle {
    background-color: #3a3a5c;
    width: 3px;
    height: 3px;
}
QScrollBar:vertical {
    border: none;
    background: #1a1a2e;
    width: 10px;
}
QScrollBar::handle:vertical {
    background: #3a3a5c;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #7b68ee;
}
QScrollBar::add-line, QScrollBar::sub-line {
    height: 0;
}
"""


# ─── IP Config Worker ───────────────────────────────────────────────────────

class ConfigWorker(QThread):
    """Worker for applying IP configurations in a background thread."""
    progress = Signal(str)
    finished_ops = Signal(bool, str, str)  # success, message, details

    def __init__(self, adapter_name: str, mode: str, profile: IpProfile = None,
                 ip: str = "", mask: str = "", gateway: str = "",
                 dns1: str = "", dns2: str = ""):
        super().__init__()
        self.adapter_name = adapter_name
        self.mode = mode  # "static", "dhcp", "profile"
        self.profile = profile
        self.ip = ip
        self.mask = mask
        self.gateway = gateway
        self.dns1 = dns1
        self.dns2 = dns2

    def run(self):
        try:
            if self.mode == "dhcp":
                self.progress.emit("Setting DHCP...")
                r = apply_dhcp(self.adapter_name)
            elif self.mode == "profile":
                self.progress.emit(f"Applying profile '{self.profile.name}'...")
                r = apply_profile(self.adapter_name, self.profile)
            else:
                self.progress.emit("Setting static IP...")
                r = apply_static_ip(
                    self.adapter_name, self.ip, self.mask,
                    self.gateway, self.dns1, self.dns2,
                )
            self.finished_ops.emit(r.success, r.message, r.details)
        except Exception as e:
            self.finished_ops.emit(False, f"Error: {e}", traceback.format_exc())


# ─── Scanner Worker ──────────────────────────────────────────────────────────

class ScannerWorker(QThread):
    """Worker for device scanning in a background thread."""
    progress = Signal(str)
    device_found = Signal(object)  # DeviceEntry
    finished_scan = Signal()

    def __init__(self, adapter_name: str, isolated: bool, passive_timeout: int = 5):
        super().__init__()
        self.adapter_name = adapter_name
        self.isolated = isolated
        self.passive_timeout = passive_timeout
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            def cb(msg):
                if not self._stop:
                    self.progress.emit(msg)

            def on_device(entry: DeviceEntry):
                if not self._stop:
                    self.device_found.emit(entry)

            if self._stop:
                self.finished_scan.emit()
                return

            # Check if the adapter is visible to scapy/Npcap
            if not _is_iface_in_scapy(self.adapter_name):
                self.progress.emit(
                    f"Adapter '{self.adapter_name}' not found in Npcap. "
                    "Restarting Npcap driver to pick up new adapters..."
                )
                if restart_npcap():
                    self.progress.emit("Npcap restarted. Re-checking adapter...")
                    if not _is_iface_in_scapy(self.adapter_name):
                        self.progress.emit(
                            f"Adapter '{self.adapter_name}' still not found after Npcap restart. "
                            "Try: reinstall Npcap with 'Install Npcap on all adapters' option, "
                            "or unplug/replug the USB adapter."
                        )
                        self.finished_scan.emit()
                        return
                else:
                    self.progress.emit(
                        "Failed to restart Npcap. Try running as Administrator."
                    )
                    self.finished_scan.emit()
                    return

            scan_full(
                self.adapter_name,
                isolated=self.isolated,
                passive_timeout=self.passive_timeout,
                progress_cb=cb,
                stop_check=lambda: self._stop,
                device_cb=on_device,
            )
        except ImportError as e:
            self.progress.emit(str(e))
        except Exception as e:
            self.progress.emit(f"Scan error: {e}\n{traceback.format_exc()}")
        finally:
            self.finished_scan.emit()


# ─── Probe Worker ────────────────────────────────────────────────────────────

class ProbeWorker(QThread):
    """Worker for subnet probing in a background thread."""
    progress = Signal(str)
    probe_result = Signal(object)  # ProbeResult
    finished_probe = Signal()

    def __init__(self, adapter_name: str, network: str):
        super().__init__()
        self.adapter_name = adapter_name
        self.network = network
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            # Check scapy visibility
            if not _is_iface_in_scapy(self.adapter_name):
                self.progress.emit(
                    f"Adapter '{self.adapter_name}' not in Npcap. Restarting..."
                )
                if restart_npcap():
                    if not _is_iface_in_scapy(self.adapter_name):
                        self.progress.emit("Adapter still not found after Npcap restart.")
                        self.finished_probe.emit()
                        return
                else:
                    self.progress.emit("Failed to restart Npcap. Run as admin.")
                    self.finished_probe.emit()
                    return

            result = probe_subnet(
                self.adapter_name, self.network,
                stop_check=lambda: self._stop,
                progress_cb=lambda msg: self.progress.emit(msg),
            )
            if not self._stop:
                self.probe_result.emit(result)
        except Exception as e:
            self.progress.emit(f"Probe error: {e}\n{traceback.format_exc()}")
        finally:
            self.finished_probe.emit()


class QuickCheckWorker(QThread):
    """Worker for quick single-IP check before assigning."""
    result = Signal(bool, str)  # (is_alive, ip)
    finished_check = Signal()

    def __init__(self, adapter_name: str, target_ip: str):
        super().__init__()
        self.adapter_name = adapter_name
        self.target_ip = target_ip

    def run(self):
        try:
            alive = quick_check_ip(self.adapter_name, self.target_ip)
            self.result.emit(alive, self.target_ip)
        except Exception as e:
            self.result.emit(True, self.target_ip)  # assume in use on error
        finally:
            self.finished_check.emit()


# ─── IP Config Tab ───────────────────────────────────────────────────────────

class IpConfigTab(QWidget):
    """Tab for setting/storing/restoring IP configurations."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._refresh_adapters()
        self._refresh_profiles()
        self._refresh_history()
        # Auto-focus first IP octet after the event loop starts
        from PySide6.QtCore import QTimer
        QTimer.singleShot(100, lambda: (
            self.ip_spin[0].setFocus(),
            self.ip_spin[0].lineEdit().selectAll(),
        ))

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── Top: Adapter selection + current config ──
        top_group = QGroupBox("Adapter & Current Config")
        top_layout = QGridLayout(top_group)

        top_layout.addWidget(QLabel("Adapter:"), 0, 0)
        self.adapter_combo = QComboBox()
        self.adapter_combo.setMinimumWidth(200)
        self.adapter_combo.currentIndexChanged.connect(self._update_current_config)
        top_layout.addWidget(self.adapter_combo, 0, 1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_adapters)
        top_layout.addWidget(refresh_btn, 0, 2)

        # Show inactive adapters checkbox (hidden by default)
        self.show_inactive_check = QCheckBox("Show inactive adapters")
        self.show_inactive_check.setChecked(False)
        self.show_inactive_check.stateChanged.connect(self._refresh_adapters)
        top_layout.addWidget(self.show_inactive_check, 0, 3)

        # Current config display
        self.current_config_label = QLabel("Select an adapter to see current config")
        self.current_config_label.setStyleSheet("color: #999; padding: 4px;")
        top_layout.addWidget(self.current_config_label, 1, 0, 1, 3)

        layout.addWidget(top_group)

        # ── Middle: Splitter with config inputs (left) and profiles/history (right) ──
        splitter = QSplitter(Qt.Horizontal)

        # Left: Config inputs
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout(config_group)

        # No radio buttons -- fields always unlocked, DHCP is a button action

        # IP address (4 IpOctetSpinBoxes with auto-advance on '.')
        ip_grid = QGridLayout()
        ip_grid.addWidget(QLabel("IP Address:"), 0, 0)
        self.ip_spin = [IpOctetSpinBox() for _ in range(4)]
        for i, spin in enumerate(self.ip_spin):
            ip_grid.addWidget(spin, 0, 1 + i * 2)
            if i < 3:
                spin.set_next_spin(self.ip_spin[i + 1])
                dot = QLabel(".")
                dot.setAlignment(Qt.AlignCenter)
                ip_grid.addWidget(dot, 0, 2 + i * 2)

        ip_grid.addWidget(QLabel("Subnet:"), 1, 0)
        self.prefix_spin = QSpinBox()
        self.prefix_spin.setRange(1, 32)
        self.prefix_spin.setValue(24)
        self.prefix_spin.valueChanged.connect(self._on_prefix_changed)
        ip_grid.addWidget(self.prefix_spin, 1, 1)
        self.subnet_hint_label = QLabel("/24 = 255.255.255.0")
        ip_grid.addWidget(self.subnet_hint_label, 1, 2, 1, 5)

        ip_grid.addWidget(QLabel("Gateway:"), 2, 0)
        self.gw_spin = [IpOctetSpinBox() for _ in range(4)]
        for i, spin in enumerate(self.gw_spin):
            ip_grid.addWidget(spin, 2, 1 + i * 2)
            if i < 3:
                spin.set_next_spin(self.gw_spin[i + 1])
                dot = QLabel(".")
                dot.setAlignment(Qt.AlignCenter)
                ip_grid.addWidget(dot, 2, 2 + i * 2)

        # Gateway auto-calc checkbox inline with label (row 2, col 8)
        self.gw_auto_check = QCheckBox("auto")
        self.gw_auto_check.setChecked(True)
        self.gw_auto_check.setToolTip("Auto-calculate gateway as network address + 1")
        ip_grid.addWidget(self.gw_auto_check, 2, 8)

        ip_grid.addWidget(QLabel("DNS 1:"), 3, 0)
        self.dns1_spin = [IpOctetSpinBox() for _ in range(4)]
        # Default: Cloudflare DNS (1.1.1.1)
        for i, val in enumerate([1, 1, 1, 1]):
            self.dns1_spin[i].setValue(val)
        for i, spin in enumerate(self.dns1_spin):
            ip_grid.addWidget(spin, 3, 1 + i * 2)
            if i < 3:
                spin.set_next_spin(self.dns1_spin[i + 1])
                dot = QLabel(".")
                dot.setAlignment(Qt.AlignCenter)
                ip_grid.addWidget(dot, 3, 2 + i * 2)

        ip_grid.addWidget(QLabel("DNS 2:"), 4, 0)
        self.dns2_spin = [IpOctetSpinBox() for _ in range(4)]
        # Default: Google DNS (8.8.8.8)
        for i, val in enumerate([8, 8, 8, 8]):
            self.dns2_spin[i].setValue(val)
        for i, spin in enumerate(self.dns2_spin):
            ip_grid.addWidget(spin, 4, 1 + i * 2)
            if i < 3:
                spin.set_next_spin(self.dns2_spin[i + 1])
                dot = QLabel(".")
                dot.setAlignment(Qt.AlignCenter)
                ip_grid.addWidget(dot, 4, 2 + i * 2)

        # Wire IP octet changes to gateway auto-calc
        for spin in self.ip_spin:
            spin.valueChanged.connect(self._maybe_calc_gateway)
        # Last IP octet Tab-out also triggers via prefix change

        config_layout.addLayout(ip_grid)

        # Location + profile name
        name_grid = QGridLayout()
        name_grid.addWidget(QLabel("Location:"), 0, 0)
        self.location_edit = QLineEdit()
        self.location_edit.setPlaceholderText("e.g. Office, Site A, Field")
        name_grid.addWidget(self.location_edit, 0, 1)

        name_grid.addWidget(QLabel("Profile Name:"), 1, 0)
        self.profile_name_edit = QLineEdit()
        self.profile_name_edit.setPlaceholderText("Name this config to save it")
        name_grid.addWidget(self.profile_name_edit, 1, 1)

        config_layout.addLayout(name_grid)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.apply_btn = QPushButton("Apply Static")
        self.apply_btn.clicked.connect(self._apply_config)
        btn_layout.addWidget(self.apply_btn)

        self.dhcp_btn = QPushButton("Release to DHCP")
        self.dhcp_btn.clicked.connect(self._apply_dhcp)
        btn_layout.addWidget(self.dhcp_btn)

        self.save_btn = QPushButton("Save Profile")
        self.save_btn.clicked.connect(self._save_profile)
        btn_layout.addWidget(self.save_btn)

        self.probe_btn = QPushButton("Probe Subnet")
        self.probe_btn.clicked.connect(self._start_probe)
        btn_layout.addWidget(self.probe_btn)

        config_layout.addLayout(btn_layout)

        # Probe results table (hidden until probe runs)
        self.probe_group = QGroupBox("Probe Results")
        probe_layout = QVBoxLayout(self.probe_group)
        self.probe_table = QTableWidget(0, 3)
        self.probe_table.setHorizontalHeaderLabels(["IP", "MAC", "Status"])
        self.probe_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.probe_table.setMaximumHeight(120)
        probe_layout.addWidget(self.probe_table)

        probe_btn_layout = QHBoxLayout()
        self.probe_use_btn = QPushButton("Use Selected IP")
        self.probe_use_btn.clicked.connect(self._use_probed_ip)
        probe_btn_layout.addWidget(self.probe_use_btn)
        probe_btn_layout.addStretch()
        probe_layout.addLayout(probe_btn_layout)

        self.probe_group.setVisible(False)
        config_layout.addWidget(self.probe_group)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        config_layout.addWidget(self.progress_bar)

        splitter.addWidget(config_group)

        # Right: Profiles + History
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # Profiles
        profiles_group = QGroupBox("Saved Profiles")
        profiles_layout = QVBoxLayout(profiles_group)
        self.profiles_list = QListWidget()
        self.profiles_list.setMaximumHeight(150)
        profiles_layout.addWidget(self.profiles_list)

        profile_btn_layout = QHBoxLayout()
        self.load_profile_btn = QPushButton("Load")
        self.load_profile_btn.clicked.connect(self._load_profile)
        profile_btn_layout.addWidget(self.load_profile_btn)

        self.delete_profile_btn = QPushButton("Delete")
        self.delete_profile_btn.clicked.connect(self._delete_profile)
        profile_btn_layout.addWidget(self.delete_profile_btn)
        profiles_layout.addLayout(profile_btn_layout)

        right_layout.addWidget(profiles_group)

        # History
        history_group = QGroupBox("History")
        history_layout = QVBoxLayout(history_group)
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(
            ["Time", "Adapter", "Old IP", "New IP", "Profile", "Notes"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        history_layout.addWidget(self.history_table)

        clear_hist_btn = QPushButton("Clear History")
        clear_hist_btn.clicked.connect(self._clear_history)
        history_layout.addWidget(clear_hist_btn)

        right_layout.addWidget(history_group)

        splitter.addWidget(right_widget)
        splitter.setSizes([400, 350])

        layout.addWidget(splitter, 1)

    def _on_mode_changed(self):
        # Fields are always unlocked -- no more DHCP/static toggle
        if self.gw_auto_check.isChecked():
            self._maybe_calc_gateway()

    def _on_prefix_changed(self, val):
        """Update subnet hint label and recalculate gateway."""
        mask = prefix_to_mask(val)
        self.subnet_hint_label.setText(f"/{val} = {mask}")
        self._maybe_calc_gateway()

    def _maybe_calc_gateway(self):
        """If gateway auto-calc is enabled, set gateway = network address + 1."""
        if not self.gw_auto_check.isChecked():
            return
        ip = self._get_ip_string(self.ip_spin)
        if not validate_ip(ip):
            return
        prefix = self.prefix_spin.value()
        # Calculate network address
        ip_int = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(ip.split(".")))
        mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net_int = ip_int & mask_int
        gw_int = net_int + 1
        gw = ".".join(str((gw_int >> (8 * (3 - i))) & 0xFF) for i in range(4))
        octets = gw.split(".")
        for i, spin in enumerate(self.gw_spin):
            if i < len(octets):
                spin.setValue(int(octets[i]))

    def _refresh_adapters(self):
        self.adapter_combo.clear()
        try:
            adapters = enumerate_adapters()
            show_inactive = self.show_inactive_check.isChecked()
            physical = [a for a in adapters if a.is_physical]
            if not physical:
                physical = adapters
            # Filter out inactive adapters unless "show inactive" is checked
            if not show_inactive:
                physical = [a for a in physical if a.is_up]
            for a in physical:
                label = f"{a.name}"
                if a.ip_address:
                    label += f"  ({a.ip_address})"
                if a.dhcp_enabled:
                    label += " [DHCP]"
                if not a.is_up:
                    label += " [inactive]"
                self.adapter_combo.addItem(label, a.name)
            self._update_current_config()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to enumerate adapters:\n{e}")

    def _update_current_config(self):
        name = self.adapter_combo.currentData()
        if not name:
            self.current_config_label.setText("No adapter selected")
            return
        try:
            adapters = enumerate_adapters()
            for a in adapters:
                if a.name == name:
                    parts = []
                    parts.append(f"MAC: {a.mac_address}" if a.mac_address else "MAC: unknown")
                    if a.dhcp_enabled:
                        parts.append("Mode: DHCP")
                    else:
                        parts.append("Mode: Static")
                    if a.ip_address:
                        parts.append(f"IP: {a.ip_address}/{a.subnet_mask}")
                    if a.gateway:
                        parts.append(f"GW: {a.gateway}")
                    if a.dns_servers:
                        parts.append(f"DNS: {', '.join(a.dns_servers)}")
                    self.current_config_label.setText("  |  ".join(parts))
                    # Temporarily disable gateway auto-calc while populating
                    auto_was = self.gw_auto_check.isChecked()
                    self.gw_auto_check.setChecked(False)
                    # Populate spinboxes with current values
                    if a.ip_address:
                        octets = a.ip_address.split(".")
                        for i, spin in enumerate(self.ip_spin):
                            if i < len(octets):
                                spin.setValue(int(octets[i]))
                    if a.subnet_mask:
                        self.prefix_spin.setValue(mask_to_prefix(a.subnet_mask))
                    if a.gateway:
                        octets = a.gateway.split(".")
                        for i, spin in enumerate(self.gw_spin):
                            if i < len(octets):
                                spin.setValue(int(octets[i]))
                    if a.dns_servers:
                        for idx, dns in enumerate(a.dns_servers[:2]):
                            octets = dns.split(".")
                            target = self.dns1_spin if idx == 0 else self.dns2_spin
                            for i, spin in enumerate(target):
                                if i < len(octets):
                                    spin.setValue(int(octets[i]))
                    # Restore auto-calc state
                    self.gw_auto_check.setChecked(auto_was)
                    self._on_mode_changed()
                    return
            self.current_config_label.setText("Adapter not found")
        except Exception as e:
            self.current_config_label.setText(f"Error: {e}")

    def _get_ip_string(self, spins) -> str:
        return ".".join(str(s.value()) for s in spins)

    def _apply_config(self):
        name = self.adapter_combo.currentData()
        if not name:
            QMessageBox.warning(self, "No Adapter", "Select an adapter first.")
            return

        self.apply_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.dhcp_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        ip = self._get_ip_string(self.ip_spin)
        mask = prefix_to_mask(self.prefix_spin.value())
        gw = self._get_ip_string(self.gw_spin)
        dns1 = self._get_ip_string(self.dns1_spin)
        dns2 = self._get_ip_string(self.dns2_spin)
        # Strip 0.0.0.0 values
        if gw == "0.0.0.0": gw = ""
        if dns1 == "0.0.0.0": dns1 = ""
        if dns2 == "0.0.0.0": dns2 = ""
        self._worker = ConfigWorker(name, "static", ip=ip, mask=mask,
                                    gateway=gw, dns1=dns1, dns2=dns2)

        self._worker.progress.connect(
            lambda msg: self.progress_bar.setFormat(msg)
        )
        self._worker.finished_ops.connect(self._on_apply_done)
        self._worker.start()

    def _on_apply_done(self, success, message, details):
        self.progress_bar.setVisible(False)
        self.apply_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
        self.dhcp_btn.setEnabled(True)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Failed", f"{message}\n\n{details}")
        self._refresh_adapters()
        self._refresh_history()

    def _apply_dhcp(self):
        """Release the selected adapter to DHCP."""
        name = self.adapter_combo.currentData()
        if not name:
            QMessageBox.warning(self, "No Adapter", "Select an adapter first.")
            return

        self.apply_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.dhcp_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        self._worker = ConfigWorker(name, "dhcp")
        self._worker.progress.connect(
            lambda msg: self.progress_bar.setFormat(msg)
        )
        self._worker.finished_ops.connect(self._on_apply_done)
        self._worker.start()

    def _start_probe(self):
        """Start a subnet probe: add temp IP, ARP sweep, show results."""
        name = self.adapter_combo.currentData()
        if not name:
            QMessageBox.warning(self, "No Adapter", "Select an adapter first.")
            return

        # Build network from current IP fields
        ip = self._get_ip_string(self.ip_spin)
        prefix = self.prefix_spin.value()
        network = f"{'.'.join(ip.split('.')[:3])}.0/{prefix}"

        self.probe_btn.setEnabled(False)
        self.probe_group.setVisible(True)
        self.probe_table.setRowCount(0)
        self.probe_table.setRowCount(1)
        self.probe_table.setItem(0, 0, QTableWidgetItem("Probing..."))
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat(f"Probing {network}")

        self._probe_worker = ProbeWorker(name, network)
        self._probe_worker.progress.connect(
            lambda msg: self.progress_bar.setFormat(msg)
        )
        self._probe_worker.probe_result.connect(self._on_probe_result)
        self._probe_worker.finished_probe.connect(self._on_probe_finished)
        self._probe_worker.start()

    def _on_probe_result(self, result: ProbeResult):
        if result.error:
            self.probe_table.setItem(0, 0, QTableWidgetItem(f"Error: {result.error}"))
            return

        # Populate table: alive IPs first, then first few free IPs
        self.probe_table.setRowCount(0)
        for ip, mac in result.alive:
            row = self.probe_table.rowCount()
            self.probe_table.insertRow(row)
            self.probe_table.setItem(row, 0, QTableWidgetItem(ip))
            self.probe_table.setItem(row, 1, QTableWidgetItem(mac))
            self.probe_table.setItem(row, 2, QTableWidgetItem("IN USE"))

        for ip in result.free[:50]:  # show up to 50 free IPs
            row = self.probe_table.rowCount()
            self.probe_table.insertRow(row)
            self.probe_table.setItem(row, 0, QTableWidgetItem(ip))
            self.probe_table.setItem(row, 1, QTableWidgetItem(""))
            self.probe_table.setItem(row, 2, QTableWidgetItem("free"))

        self._probe_result = result

    def _on_probe_finished(self):
        self.probe_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

    def _use_probed_ip(self):
        """Use the selected IP from probe results. Quick-checks it first."""
        row = self.probe_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select an IP from the results.")
            return

        ip = self.probe_table.item(row, 0).text()
        status = self.probe_table.item(row, 2).text()

        if status == "IN USE":
            reply = QMessageBox.question(self, "IP In Use",
                f"{ip} is currently in use. Use it anyway?")
            if reply != QMessageBox.Yes:
                return

        name = self.adapter_combo.currentData()
        if not name:
            return

        # Quick re-check if still free
        self.probe_use_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat(f"Checking {ip}...")

        self._check_worker = QuickCheckWorker(name, ip)
        self._check_worker.result.connect(lambda alive, checked_ip: self._on_check_done(alive, checked_ip))
        self._check_worker.finished_check.connect(lambda: self.progress_bar.setVisible(False))
        self._check_worker.start()

    def _on_check_done(self, alive: bool, ip: str):
        self.probe_use_btn.setEnabled(True)
        if alive:
            reply = QMessageBox.question(self, "IP Taken",
                f"{ip} is now in use! Pick another or use it anyway?")
            if reply != QMessageBox.Yes:
                return

        # Populate the IP fields with this address
        octets = ip.split(".")
        for i, spin in enumerate(self.ip_spin):
            if i < len(octets):
                spin.setValue(int(octets[i]))
        self._maybe_calc_gateway()

    def _save_profile(self):
        name = self.profile_name_edit.text().strip()
        if not name:
            name, ok = QInputDialog.getText(self, "Profile Name", "Enter a name:")
            if not ok or not name:
                return

        # Always save as static profile (fields always populated now)
        profile = IpProfile(
            name=name,
            dhcp=False,
            ip=self._get_ip_string(self.ip_spin),
            subnet_mask=prefix_to_mask(self.prefix_spin.value()),
            gateway=self._get_ip_string(self.gw_spin),
            dns_primary=self._get_ip_string(self.dns1_spin),
            dns_secondary=self._get_ip_string(self.dns2_spin),
            location=self.location_edit.text(),
        )

        add_profile(profile)
        self._refresh_profiles()
        QMessageBox.information(self, "Saved", f"Profile '{name}' saved.")

    def _refresh_profiles(self):
        self.profiles_list.clear()
        for p in load_profiles():
            label = f"{p.name}"
            if p.location:
                label += f"  [{p.location}]"
            if p.dhcp:
                label += "  (DHCP)"
            else:
                label += f"  ({p.ip})"
            self.profiles_list.addItem(QListWidgetItem(label))

    def _load_profile(self):
        row = self.profiles_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a profile to load.")
            return
        profiles = load_profiles()
        if row >= len(profiles):
            return
        p = profiles[row]

        self.profile_name_edit.setText(p.name)
        self.location_edit.setText(p.location)

        # Load values into fields (always static now)
        auto_was = self.gw_auto_check.isChecked()
        self.gw_auto_check.setChecked(False)
        if p.ip:
            octets = p.ip.split(".")
            for i, spin in enumerate(self.ip_spin):
                if i < len(octets):
                    spin.setValue(int(octets[i]))
        if p.subnet_mask:
            self.prefix_spin.setValue(mask_to_prefix(p.subnet_mask))
        if p.gateway:
            octets = p.gateway.split(".")
            for i, spin in enumerate(self.gw_spin):
                if i < len(octets):
                    spin.setValue(int(octets[i]))
        if p.dns_primary:
            octets = p.dns_primary.split(".")
            for i, spin in enumerate(self.dns1_spin):
                if i < len(octets):
                    spin.setValue(int(octets[i]))
        if p.dns_secondary:
            octets = p.dns_secondary.split(".")
            for i, spin in enumerate(self.dns2_spin):
                if i < len(octets):
                    spin.setValue(int(octets[i]))
        # Restore auto-calc state
        self.gw_auto_check.setChecked(auto_was)

        self._on_mode_changed()

    def _delete_profile(self):
        row = self.profiles_list.currentRow()
        if row < 0:
            return
        profiles = load_profiles()
        if row >= len(profiles):
            return
        name = profiles[row].name
        reply = QMessageBox.question(self, "Confirm", f"Delete profile '{name}'?")
        if reply == QMessageBox.Yes:
            delete_profile(name)
            self._refresh_profiles()

    def _refresh_history(self):
        entries = load_history()
        self.history_table.setRowCount(len(entries))
        for i, e in enumerate(entries):
            ts = e.timestamp[:19].replace("T", " ")
            self.history_table.setItem(i, 0, QTableWidgetItem(ts))
            self.history_table.setItem(i, 1, QTableWidgetItem(e.adapter))
            old = "DHCP" if e.old_dhcp else f"{e.old_ip}/{e.old_mask}"
            new = "DHCP" if e.new_dhcp else f"{e.new_ip}/{e.new_mask}"
            self.history_table.setItem(i, 2, QTableWidgetItem(old))
            self.history_table.setItem(i, 3, QTableWidgetItem(new))
            self.history_table.setItem(i, 4, QTableWidgetItem(e.profile_name))
            self.history_table.setItem(i, 5, QTableWidgetItem(""))

    def _clear_history(self):
        reply = QMessageBox.question(self, "Confirm", "Clear all history?")
        if reply == QMessageBox.Yes:
            clear_history()
            self._refresh_history()

    def on_show(self):
        """Called when this tab becomes active."""
        self._refresh_adapters()
        self._refresh_profiles()
        self._refresh_history()
        # Auto-focus first IP octet ready for typing
        self.ip_spin[0].setFocus()
        self.ip_spin[0].lineEdit().selectAll()


# ─── Device Scanner Tab ──────────────────────────────────────────────────────

class ScannerTab(QWidget):
    """Tab for finding unknown devices on a direct connection."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scanner_worker = None
        self._build_ui()
        self._refresh_adapters()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Top: Adapter selection + options
        top_group = QGroupBox("Scanner Setup")
        top_layout = QGridLayout(top_group)

        top_layout.addWidget(QLabel("Adapter:"), 0, 0)
        self.scanner_adapter_combo = QComboBox()
        self.scanner_adapter_combo.setMinimumWidth(200)
        top_layout.addWidget(self.scanner_adapter_combo, 0, 1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_adapters)
        top_layout.addWidget(refresh_btn, 0, 2)

        # Show inactive adapters checkbox
        self.show_inactive_check = QCheckBox("Show inactive adapters")
        self.show_inactive_check.setChecked(False)
        self.show_inactive_check.stateChanged.connect(self._refresh_adapters)
        top_layout.addWidget(self.show_inactive_check, 0, 3)

        self.isolated_check = QCheckBox("Isolated adapter (direct connection to device)")
        self.isolated_check.setChecked(True)
        self.isolated_check.setToolTip(
            "When checked, assumes any traffic on this adapter is from the\n"
            "device you are directly plugged into. Enables faster detection."
        )
        top_layout.addWidget(self.isolated_check, 1, 0, 1, 3)

        top_layout.addWidget(QLabel("Passive sniff timeout (s):"), 2, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(5)
        top_layout.addWidget(self.timeout_spin, 2, 1)

        layout.addWidget(top_group)

        # Middle: Action buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self._start_scan)
        btn_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        btn_layout.addWidget(self.stop_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Bottom: Splitter with results table + log
        splitter = QSplitter(Qt.Vertical)

        # Results table
        results_group = QGroupBox("Discovered Devices")
        results_layout = QVBoxLayout(results_group)
        self.scan_results_table = QTableWidget(0, 4)
        self.scan_results_table.setHorizontalHeaderLabels(["IP", "MAC", "Method", "Subnet"])
        self.scan_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.scan_results_table)

        results_btn_layout = QHBoxLayout()
        self.auto_config_btn = QPushButton("Auto-Configure to Selected")
        self.auto_config_btn.setEnabled(False)
        self.auto_config_btn.clicked.connect(self._auto_configure)
        results_btn_layout.addWidget(self.auto_config_btn)
        results_btn_layout.addStretch()
        results_layout.addLayout(results_btn_layout)

        splitter.addWidget(results_group)

        # Log panel
        log_group = QGroupBox("Scan Log")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        splitter.addWidget(log_group)

        splitter.setSizes([200, 200])
        layout.addWidget(splitter, 1)

    def _refresh_adapters(self):
        self.scanner_adapter_combo.clear()
        try:
            adapters = enumerate_adapters()
            show_inactive = self.show_inactive_check.isChecked()
            physical = [a for a in adapters if a.is_physical]
            if not physical:
                physical = adapters
            # Filter out inactive adapters unless "show inactive" is checked
            if not show_inactive:
                physical = [a for a in physical if a.is_up]
            for a in physical:
                label = f"{a.name}"
                if a.mac_address:
                    label += f"  [{a.mac_address}]"
                if a.ip_address:
                    label += f"  ({a.ip_address})"
                if not a.is_up:
                    label += " [inactive]"
                self.scanner_adapter_combo.addItem(label, a.name)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to enumerate adapters:\n{e}")

    def _start_scan(self):
        name = self.scanner_adapter_combo.currentData()
        if not name:
            QMessageBox.warning(self, "No Adapter", "Select an adapter first.")
            return

        self.log_text.clear()
        self.scan_results_table.setRowCount(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.auto_config_btn.setEnabled(False)

        self._scanner_worker = ScannerWorker(
            name, self.isolated_check.isChecked(),
            self.timeout_spin.value(),
        )
        self._scanner_worker.progress.connect(self._log)
        self._scanner_worker.device_found.connect(self._on_device_found)
        self._scanner_worker.finished_scan.connect(self._on_scan_finished)
        self._scanner_worker.start()

    def _stop_scan(self):
        if self._scanner_worker:
            self._scanner_worker.stop()
        self.stop_btn.setEnabled(False)

    def _log(self, msg):
        self.log_text.append(msg)

    def _on_device_found(self, entry: DeviceEntry):
        """Add a discovered device to the results table in real-time."""
        row = self.scan_results_table.rowCount()
        self.scan_results_table.insertRow(row)
        self.scan_results_table.setItem(row, 0, QTableWidgetItem(entry.ip))
        self.scan_results_table.setItem(row, 1, QTableWidgetItem(entry.mac))
        self.scan_results_table.setItem(row, 2, QTableWidgetItem(entry.method))
        self.scan_results_table.setItem(row, 3, QTableWidgetItem(entry.subnet))
        self.auto_config_btn.setEnabled(True)

    def _on_scan_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _auto_configure(self):
        row = self.scan_results_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a device from the results.")
            return

        ip = self.scan_results_table.item(row, 0).text()
        name = self.scanner_adapter_combo.currentData()
        if not name:
            return

        reply = QMessageBox.question(
            self, "Auto-Configure",
            f"Set adapter '{name}' to {ip.rsplit('.', 1)[0]}.2/24\n"
            f"to communicate with device at {ip}?"
        )
        if reply == QMessageBox.Yes:
            r = auto_configure_to_device(name, ip, 24)
            if r.success:
                QMessageBox.information(self, "Done",
                    f"Adapter configured. You can now reach {ip}")
                self._refresh_adapters()
            else:
                QMessageBox.critical(self, "Failed", r.message)

    def on_show(self):
        self._refresh_adapters()


# ─── Main Window ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("jives IP Switcher — by jives")
        self.setMinimumSize(800, 600)
        self.resize(900, 650)

        # Central tab widget
        tabs = QTabWidget()
        self.ip_config_tab = IpConfigTab()
        self.scanner_tab = ScannerTab()
        tabs.addTab(self.ip_config_tab, "IP Config")
        tabs.addTab(self.scanner_tab, "Device Scanner")
        tabs.currentChanged.connect(self._on_tab_changed)
        self.setCentralWidget(tabs)

        # Menu bar
        self._build_menu()

    def _build_menu(self):
        menubar = self.menuBar()
        menubar.setStyleSheet("background-color: #1a1a2e; color: #e0e0e0;")

        file_menu = menubar.addMenu("File")

        refresh_action = QAction("Refresh All", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self._refresh_all)
        file_menu.addAction(refresh_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _on_tab_changed(self, index):
        if index == 0:
            self.ip_config_tab.on_show()
        else:
            self.scanner_tab.on_show()

    def _refresh_all(self):
        self.ip_config_tab.on_show()
        self.scanner_tab.on_show()

    def _show_about(self):
        QMessageBox.about(self, "About",
            "jives IP Switcher — by jives\n\n"
            "Set and store IP configurations on network adapters.\n"
            "Scan for unknown devices on direct connections.\n\n"
            "Device scanner requires scapy + Npcap.\n"
            "Run as Administrator for IP changes to work.")


def is_admin() -> bool:
    """Check if running with elevated privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """
    Relaunch the current process with UAC elevation via ShellExecute "runas".
    Returns True if the elevated process was launched successfully.
    Works with both `python main.py` and PyInstaller single-file EXE.
    """
    try:
        import ctypes
        # sys.executable is either python.exe or the frozen EXE
        # When frozen, we ARE the exe. When running from source, we need
        # python.exe + script path.
        if getattr(sys, "frozen", False):
            # PyInstaller EXE -- just relaunch the exe
            params = ""
            executable = sys.executable
        else:
            # Running from source -- relaunch python with the script
            script = os.path.abspath(__file__)
            params = f'"{script}"'
            executable = sys.executable

        # ShellExecuteW returns hInstance > 32 on success
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1  # SW_SHOWNORMAL
        )
        return result > 32
    except Exception as e:
        print(f"Failed to elevate: {e}")
        return False


def main():
    # Auto-elevate: if not admin, relaunch with UAC prompt
    if not is_admin():
        if relaunch_as_admin():
            return  # elevated process launched, we exit
        # UAC declined or failed -- show a minimal GUI with a message
        app = QApplication(sys.argv)
        app.setStyleSheet(DARK_STYLESHEET)
        QMessageBox.critical(
            None, "Administrator Required",
            "jives IP Switcher needs Administrator privileges to change\n"
            "network adapter IP configurations.\n\n"
            "Please right-click the EXE and select 'Run as administrator',\n"
            "or approve the UAC prompt when it appears."
        )
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("jivesIpSwitcher")
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
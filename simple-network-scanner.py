#!/usr/bin/env python3

import csv
from datetime import datetime
import ipaddress
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import tkinter as tk
import xml.etree.ElementTree as ET
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any


class NmapGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Simple Network Scanner")
        self.root.geometry("1100x720")
        self.root.minsize(850, 540)

        self.process: subprocess.Popen[str] | None = None
        self.output_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.current_xml_path: str | None = None
        self.current_temp_dir: str | None = None
        self.last_completed_scan_type = "Device Discovery"

        self.scan_started_at: float | None = None
        self.activity_job: str | None = None
        self.activity_frame = 0
        self.active_target = ""
        self.latest_nmap_status = ""

        self.target_var = tk.StringVar()
        self.interface_var = tk.StringVar(
            value="Detecting local network..."
        )
        self.scan_type_var = tk.StringVar(
            value="Device Discovery"
        )
        self.scan_description_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.result_count_var = tk.StringVar(
            value="0 devices found"
        )
        self.dark_mode_var = tk.BooleanVar(value=False)
        self.style = ttk.Style(self.root)

        self.scan_options = {
            "Device Discovery": ["-sn"],
            "Device Discovery w/MAC": ["-sn"],
            "Quick Port Scan": ["-T4", "-F"],
            "Standard Port Scan": ["-T4"],
        }

        self.scan_descriptions = {
            "Device Discovery": (
                "Finds active devices. Does not request administrator access."
            ),
            "Device Discovery w/MAC": (
                "Finds devices plus local MAC addresses and vendors. Requires administrator access."
            ),
            "Quick Port Scan": (
                "Checks the most common ports for a fast overview."
            ),
            "Standard Port Scan": (
                "Checks Nmap's default 1,000 commonly used ports."
            ),
        }

        self.build_interface()
        self.update_scan_description()
        self.update_device_columns(self.scan_type_var.get())
        self.apply_theme()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application,
        )

        self.root.after(
            100,
            self.process_output_queue,
        )

        self.root.after(
            250,
            self.detect_local_network,
        )

    def build_interface(self) -> None:
        main_frame = ttk.Frame(
            self.root,
            padding=12,
        )
        main_frame.pack(
            fill=tk.BOTH,
            expand=True,
        )

        self.build_target_section(main_frame)
        self.build_scan_section(main_frame)
        self.build_results_section(main_frame)
        self.build_status_section(main_frame)

        self.root.bind(
            "<Control-c>",
            lambda _event: self.copy_selected_ip(),
        )

        self.target_entry.focus()

    def build_target_section(
        self,
        parent: ttk.Frame,
    ) -> None:
        target_frame = ttk.LabelFrame(
            parent,
            text="Network or Device",
            padding=10,
        )
        target_frame.pack(fill=tk.X)

        ttk.Label(
            target_frame,
            text="Target:",
        ).grid(
            row=0,
            column=0,
            sticky=tk.W,
            padx=(0, 8),
        )

        self.target_entry = ttk.Entry(
            target_frame,
            textvariable=self.target_var,
        )
        self.target_entry.grid(
            row=0,
            column=1,
            sticky=tk.EW,
        )

        self.target_entry.bind(
            "<Return>",
            lambda _event: self.start_scan(),
        )

        self.detect_button = ttk.Button(
            target_frame,
            text="Detect Network",
            command=self.detect_local_network,
        )
        self.detect_button.grid(
            row=0,
            column=2,
            padx=(8, 0),
        )

        ttk.Label(
            target_frame,
            textvariable=self.interface_var,
        ).grid(
            row=1,
            column=1,
            columnspan=2,
            sticky=tk.W,
            pady=(6, 0),
        )

        target_frame.columnconfigure(
            1,
            weight=1,
        )

    def build_scan_section(
        self,
        parent: ttk.Frame,
    ) -> None:
        controls_frame = ttk.LabelFrame(
            parent,
            text="Scan",
            padding=10,
        )
        controls_frame.pack(
            fill=tk.X,
            pady=(10, 0),
        )

        ttk.Label(
            controls_frame,
            text="Scan type:",
        ).grid(
            row=0,
            column=0,
            sticky=tk.W,
            padx=(0, 8),
        )

        self.scan_type_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.scan_type_var,
            values=list(self.scan_options.keys()),
            state="readonly",
            width=25,
        )
        self.scan_type_combo.grid(
            row=0,
            column=1,
            sticky=tk.W,
        )

        self.scan_type_combo.bind(
            "<<ComboboxSelected>>",
            self.on_scan_type_changed,
        )

        description_label = ttk.Label(
            controls_frame,
            textvariable=self.scan_description_var,
            anchor=tk.W,
            justify=tk.LEFT,
        )
        description_label.grid(
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W,
            pady=(8, 0),
        )

        button_frame = ttk.Frame(
            controls_frame
        )
        button_frame.grid(
            row=0,
            column=3,
            sticky=tk.E,
        )

        self.scan_button = ttk.Button(
            button_frame,
            text="Start",
            command=self.start_scan,
        )
        self.scan_button.pack(
            side=tk.LEFT
        )

        self.stop_button = ttk.Button(
            button_frame,
            text="Stop",
            command=self.stop_scan,
            state=tk.DISABLED,
        )
        self.stop_button.pack(
            side=tk.LEFT,
            padx=(8, 0),
        )

        self.copy_button = ttk.Button(
            button_frame,
            text="Copy IP",
            command=self.copy_selected_ip,
        )
        self.copy_button.pack(
            side=tk.LEFT,
            padx=(8, 0),
        )

        ttk.Button(
            button_frame,
            text="Clear",
            command=self.clear_results,
        ).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )

        ttk.Button(
            button_frame,
            text="Save",
            command=self.save_results,
        ).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )

        controls_frame.columnconfigure(
            2,
            weight=1,
        )

    def build_results_section(
        self,
        parent: ttk.Frame,
    ) -> None:
        self.notebook = ttk.Notebook(
            parent
        )
        self.notebook.pack(
            fill=tk.BOTH,
            expand=True,
            pady=(10, 0),
        )

        self.devices_tab = ttk.Frame(
            self.notebook,
            padding=8,
        )

        self.ports_tab = ttk.Frame(
            self.notebook,
            padding=8,
        )

        self.raw_output_tab = ttk.Frame(
            self.notebook,
            padding=8,
        )

        self.notebook.add(
            self.devices_tab,
            text="Devices",
        )

        self.notebook.add(
            self.ports_tab,
            text="Ports",
        )

        self.notebook.add(
            self.raw_output_tab,
            text="Raw Output",
        )

        self.build_devices_table()
        self.build_ports_table()
        self.build_raw_output()

    def build_status_section(
        self,
        parent: ttk.Frame,
    ) -> None:
        status_frame = ttk.Frame(
            parent
        )
        status_frame.pack(
            fill=tk.X,
            pady=(8, 0),
        )

        ttk.Label(
            status_frame,
            textvariable=self.status_var,
        ).pack(
            side=tk.LEFT
        )

        ttk.Label(
            status_frame,
            textvariable=self.result_count_var,
        ).pack(
            side=tk.LEFT,
            padx=(20, 0),
        )

        self.dark_mode_toggle = ttk.Checkbutton(
            status_frame,
            text="Dark Mode",
            variable=self.dark_mode_var,
            command=self.apply_theme,
        )
        self.dark_mode_toggle.pack(side=tk.RIGHT)

    def apply_theme(self) -> None:
        dark = self.dark_mode_var.get()

        # The clam theme allows the application colors to be controlled
        # consistently across common Linux desktop environments.
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        if dark:
            colors = {
                "background": "#202124",
                "panel": "#292a2d",
                "field": "#303134",
                "text": "#e8eaed",
                "muted": "#bdc1c6",
                "border": "#5f6368",
                "selected": "#4c6f91",
                "selected_text": "#ffffff",
            }
        else:
            colors = {
                "background": "#f3f3f3",
                "panel": "#f3f3f3",
                "field": "#ffffff",
                "text": "#202124",
                "muted": "#5f6368",
                "border": "#b8b8b8",
                "selected": "#3478c7",
                "selected_text": "#ffffff",
            }

        self.root.configure(background=colors["background"])

        self.style.configure(
            ".",
            background=colors["background"],
            foreground=colors["text"],
            fieldbackground=colors["field"],
            bordercolor=colors["border"],
            lightcolor=colors["border"],
            darkcolor=colors["border"],
            troughcolor=colors["panel"],
        )
        self.style.configure(
            "TFrame",
            background=colors["background"],
        )
        self.style.configure(
            "TLabel",
            background=colors["background"],
            foreground=colors["text"],
        )
        self.style.configure(
            "TLabelframe",
            background=colors["background"],
            bordercolor=colors["border"],
        )
        self.style.configure(
            "TLabelframe.Label",
            background=colors["background"],
            foreground=colors["text"],
        )
        self.style.configure(
            "TButton",
            background=colors["panel"],
            foreground=colors["text"],
            bordercolor=colors["border"],
        )
        self.style.map(
            "TButton",
            background=[
                ("active", colors["selected"]),
                ("pressed", colors["selected"]),
                ("disabled", colors["panel"]),
            ],
            foreground=[
                ("active", colors["selected_text"]),
                ("pressed", colors["selected_text"]),
                ("disabled", colors["muted"]),
            ],
        )
        self.style.configure(
            "TCheckbutton",
            background=colors["background"],
            foreground=colors["text"],
        )
        self.style.map(
            "TCheckbutton",
            background=[("active", colors["background"])],
            foreground=[("active", colors["text"])],
        )
        self.style.configure(
            "TEntry",
            fieldbackground=colors["field"],
            foreground=colors["text"],
            insertcolor=colors["text"],
            bordercolor=colors["border"],
        )
        self.style.configure(
            "TCombobox",
            fieldbackground=colors["field"],
            background=colors["panel"],
            foreground=colors["text"],
            arrowcolor=colors["text"],
            bordercolor=colors["border"],
        )
        self.style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", colors["field"]),
                ("disabled", colors["panel"]),
            ],
            foreground=[
                ("readonly", colors["text"]),
                ("disabled", colors["muted"]),
            ],
            selectbackground=[("readonly", colors["field"])],
            selectforeground=[("readonly", colors["text"])],
        )
        self.style.configure(
            "TNotebook",
            background=colors["background"],
            bordercolor=colors["border"],
        )
        self.style.configure(
            "TNotebook.Tab",
            background=colors["panel"],
            foreground=colors["text"],
            bordercolor=colors["border"],
        )
        self.style.map(
            "TNotebook.Tab",
            background=[
                ("selected", colors["field"]),
                ("active", colors["selected"]),
            ],
            foreground=[
                ("selected", colors["text"]),
                ("active", colors["selected_text"]),
            ],
        )
        self.style.configure(
            "Treeview",
            background=colors["field"],
            fieldbackground=colors["field"],
            foreground=colors["text"],
            bordercolor=colors["border"],
        )
        self.style.map(
            "Treeview",
            background=[("selected", colors["selected"])],
            foreground=[("selected", colors["selected_text"])],
        )
        self.style.configure(
            "Treeview.Heading",
            background=colors["panel"],
            foreground=colors["text"],
            bordercolor=colors["border"],
        )
        self.style.map(
            "Treeview.Heading",
            background=[("active", colors["selected"])],
            foreground=[("active", colors["selected_text"])],
        )
        self.style.configure(
            "Vertical.TScrollbar",
            background=colors["panel"],
            troughcolor=colors["background"],
            bordercolor=colors["border"],
            arrowcolor=colors["text"],
        )

        # Tk text widgets are not controlled by ttk.Style.
        if hasattr(self, "raw_output_text"):
            self.raw_output_text.configure(
                background=colors["field"],
                foreground=colors["text"],
                insertbackground=colors["text"],
                selectbackground=colors["selected"],
                selectforeground=colors["selected_text"],
            )

        # These options control the pop-down list used by ttk.Combobox.
        self.root.option_add("*TCombobox*Listbox.background", colors["field"])
        self.root.option_add("*TCombobox*Listbox.foreground", colors["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", colors["selected"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", colors["selected_text"])

    def build_devices_table(self) -> None:
        table_frame = ttk.Frame(
            self.devices_tab
        )
        table_frame.pack(
            fill=tk.BOTH,
            expand=True,
        )

        columns = (
            "ip_address",
            "hostname",
            "mac_address",
            "vendor",
            "status",
            "latency",
        )

        self.device_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "ip_address": "IP Address",
            "hostname": "Hostname",
            "mac_address": "MAC Address",
            "vendor": "Vendor",
            "status": "Status",
            "latency": "Latency",
        }

        for column, heading in headings.items():
            self.device_tree.heading(
                column,
                text=heading,
                command=lambda selected_column=column:
                self.sort_device_column(
                    selected_column,
                    False,
                ),
            )

        self.device_tree.column(
            "ip_address",
            width=125,
            minwidth=110,
            anchor=tk.W,
            stretch=False,
        )

        self.device_tree.column(
            "hostname",
            width=220,
            minwidth=140,
            anchor=tk.W,
            stretch=True,
        )

        self.device_tree.column(
            "mac_address",
            width=145,
            minwidth=130,
            anchor=tk.W,
            stretch=False,
        )

        self.device_tree.column(
            "vendor",
            width=210,
            minwidth=130,
            anchor=tk.W,
            stretch=True,
        )

        self.device_tree.column(
            "status",
            width=70,
            minwidth=60,
            anchor=tk.CENTER,
            stretch=False,
        )

        self.device_tree.column(
            "latency",
            width=100,
            minwidth=85,
            anchor=tk.E,
            stretch=False,
        )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient=tk.VERTICAL,
            command=self.device_tree.yview,
        )

        self.device_tree.configure(
            yscrollcommand=vertical_scrollbar.set,
        )

        self.device_tree.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        table_frame.rowconfigure(
            0,
            weight=1,
        )

        table_frame.columnconfigure(
            0,
            weight=1,
        )

        self.device_tree.bind(
            "<Double-1>",
            self.on_device_double_click,
        )

        ttk.Label(
            self.devices_tab,
            text=(
                "Single-click to select a device. "
                "Double-click to copy its IP address."
            ),
        ).pack(
            anchor=tk.W,
            pady=(6, 0),
        )

    def build_ports_table(self) -> None:
        table_frame = ttk.Frame(
            self.ports_tab
        )
        table_frame.pack(
            fill=tk.BOTH,
            expand=True,
        )

        columns = (
            "ip_address",
            "hostname",
            "port",
            "protocol",
            "state",
            "service",
        )

        self.port_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "ip_address": "IP Address",
            "hostname": "Hostname",
            "port": "Port",
            "protocol": "Protocol",
            "state": "State",
            "service": "Service",
        }

        for column, heading in headings.items():
            self.port_tree.heading(
                column,
                text=heading,
                command=lambda selected_column=column:
                self.sort_port_column(
                    selected_column,
                    False,
                ),
            )

        self.port_tree.column(
            "ip_address",
            width=125,
            minwidth=110,
            anchor=tk.W,
            stretch=False,
        )

        self.port_tree.column(
            "hostname",
            width=210,
            minwidth=145,
            anchor=tk.W,
            stretch=True,
        )

        self.port_tree.column(
            "port",
            width=65,
            minwidth=50,
            anchor=tk.E,
            stretch=False,
        )

        self.port_tree.column(
            "protocol",
            width=75,
            minwidth=60,
            anchor=tk.CENTER,
            stretch=False,
        )

        self.port_tree.column(
            "state",
            width=70,
            minwidth=55,
            anchor=tk.CENTER,
            stretch=False,
        )

        self.port_tree.column(
            "service",
            width=260,
            minwidth=120,
            anchor=tk.W,
            stretch=True,
        )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient=tk.VERTICAL,
            command=self.port_tree.yview,
        )

        self.port_tree.configure(
            yscrollcommand=vertical_scrollbar.set,
        )

        self.port_tree.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        table_frame.rowconfigure(
            0,
            weight=1,
        )

        table_frame.columnconfigure(
            0,
            weight=1,
        )

        self.port_tree.bind(
            "<Double-1>",
            self.on_port_double_click,
        )

        ttk.Label(
            self.ports_tab,
            text=(
                "Each row represents an open port. "
                "Double-click a row to copy its IP address."
            ),
        ).pack(
            anchor=tk.W,
            pady=(6, 0),
        )

    def build_raw_output(self) -> None:
        self.raw_output_text = scrolledtext.ScrolledText(
            self.raw_output_tab,
            wrap=tk.NONE,
            font=("Monospace", 10),
        )

        self.raw_output_text.pack(
            fill=tk.BOTH,
            expand=True,
        )

    def update_scan_description(self) -> None:
        scan_type = self.scan_type_var.get()

        self.scan_description_var.set(
            self.scan_descriptions.get(
                scan_type,
                "",
            )
        )

    @staticmethod
    def is_device_discovery(scan_type: str) -> bool:
        return scan_type in {
            "Device Discovery",
            "Device Discovery w/MAC",
        }

    def update_device_columns(
        self,
        scan_type: str,
    ) -> None:
        if scan_type == "Device Discovery w/MAC":
            self.device_tree.configure(
                displaycolumns=(
                    "ip_address",
                    "hostname",
                    "mac_address",
                    "vendor",
                    "status",
                    "latency",
                )
            )

            # Use compact, fixed widths so all six columns remain visible.
            self.device_tree.column(
                "ip_address",
                width=120,
                minwidth=105,
                stretch=False,
            )
            self.device_tree.column(
                "hostname",
                width=245,
                minwidth=150,
                stretch=False,
            )
            self.device_tree.column(
                "mac_address",
                width=145,
                minwidth=130,
                stretch=False,
            )
            self.device_tree.column(
                "vendor",
                width=280,
                minwidth=150,
                stretch=True,
            )
            self.device_tree.column(
                "status",
                width=65,
                minwidth=55,
                stretch=False,
            )
            self.device_tree.column(
                "latency",
                width=100,
                minwidth=85,
                stretch=False,
            )
        else:
            self.device_tree.configure(
                displaycolumns=(
                    "ip_address",
                    "hostname",
                    "status",
                    "latency",
                )
            )

            # Let the hostname column use the extra room for normal discovery.
            self.device_tree.column(
                "ip_address",
                width=155,
                minwidth=120,
                stretch=False,
            )
            self.device_tree.column(
                "hostname",
                width=500,
                minwidth=180,
                stretch=True,
            )
            self.device_tree.column(
                "status",
                width=100,
                minwidth=75,
                stretch=False,
            )
            self.device_tree.column(
                "latency",
                width=125,
                minwidth=95,
                stretch=False,
            )

        self.root.update_idletasks()

    def on_scan_type_changed(
        self,
        _event: tk.Event | None = None,
    ) -> None:
        self.update_scan_description()
        self.update_device_columns(
            self.scan_type_var.get()
        )

        if self.is_device_discovery(self.scan_type_var.get()):
            self.notebook.select(
                self.devices_tab
            )
        else:
            self.notebook.select(
                self.ports_tab
            )

    def detect_local_network(self) -> None:
        if self.process is not None:
            return

        self.interface_var.set(
            "Detecting local network..."
        )

        self.status_var.set(
            "Detecting network..."
        )

        self.detect_button.config(
            state=tk.DISABLED
        )

        thread = threading.Thread(
            target=self.run_network_detection,
            daemon=True,
        )
        thread.start()

    def run_network_detection(self) -> None:
        try:
            if shutil.which("ip") is None:
                raise RuntimeError(
                    "The Linux 'ip' command was not found."
                )

            route_result = subprocess.run(
                [
                    "ip",
                    "-j",
                    "route",
                    "show",
                    "default",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            routes = json.loads(
                route_result.stdout
            )

            if not routes:
                raise RuntimeError(
                    "No default network route was found."
                )

            interface = routes[0].get(
                "dev"
            )

            if not interface:
                raise RuntimeError(
                    "The active interface could not be determined."
                )

            address_result = subprocess.run(
                [
                    "ip",
                    "-j",
                    "-4",
                    "address",
                    "show",
                    "dev",
                    interface,
                    "scope",
                    "global",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            interface_data = json.loads(
                address_result.stdout
            )

            if not interface_data:
                raise RuntimeError(
                    f"No IPv4 address was found on {interface}."
                )

            addresses = interface_data[0].get(
                "addr_info",
                [],
            )

            ipv4_address = None
            prefix_length = None

            for address in addresses:
                if address.get("family") == "inet":
                    ipv4_address = address.get(
                        "local"
                    )
                    prefix_length = address.get(
                        "prefixlen"
                    )
                    break

            if (
                ipv4_address is None
                or prefix_length is None
            ):
                raise RuntimeError(
                    f"No usable IPv4 address was found on {interface}."
                )

            interface_network = ipaddress.ip_interface(
                f"{ipv4_address}/{prefix_length}"
            )

            network = str(
                interface_network.network
            )

            self.output_queue.put(
                (
                    "network_detected",
                    {
                        "interface": interface,
                        "address": ipv4_address,
                        "network": network,
                    },
                )
            )

        except (
            subprocess.CalledProcessError,
            json.JSONDecodeError,
            RuntimeError,
            ValueError,
            OSError,
        ) as error:
            self.output_queue.put(
                (
                    "network_detection_failed",
                    str(error),
                )
            )

    def validate_target(
        self,
        target: str,
    ) -> bool:
        if not target:
            return False

        if any(
            character.isspace()
            for character in target
        ):
            return False

        if target.startswith("-"):
            return False

        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        try:
            ipaddress.ip_network(
                target,
                strict=False,
            )
            return True
        except ValueError:
            pass

        allowed_characters = set(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            ".-_"
        )

        return all(
            character in allowed_characters
            for character in target
        )

    def start_scan(self) -> None:
        if self.process is not None:
            messagebox.showinfo(
                "Scan Running",
                "A scan is already running.",
            )
            return

        if shutil.which("nmap") is None:
            messagebox.showerror(
                "Nmap Not Found",
                "Nmap is not installed.\n\n"
                "Install it with:\n"
                "sudo apt install nmap",
            )
            return

        target = self.target_var.get().strip()

        if not self.validate_target(target):
            messagebox.showerror(
                "Invalid Target",
                "Enter a valid IP address, hostname, or subnet.\n\n"
                "Examples:\n"
                "192.168.1.10\n"
                "192.168.1.0/24\n"
                "server.local",
            )
            return

        scan_type = self.scan_type_var.get()

        options = self.scan_options.get(
            scan_type,
            ["-sn"],
        )

        self.current_temp_dir = tempfile.mkdtemp(
            prefix="simple-network-scanner-"
        )
        self.current_xml_path = os.path.join(
            self.current_temp_dir,
            "scan.xml",
        )

        nmap_path = shutil.which("nmap") or "/usr/bin/nmap"

        nmap_command = [
            nmap_path,
            *options,
            "--stats-every",
            "2s",
            "-oX",
            self.current_xml_path,
            target,
        ]

        if scan_type == "Device Discovery w/MAC":
            if os.geteuid() == 0:
                command = nmap_command
            elif shutil.which("pkexec") is not None:
                command = ["pkexec", *nmap_command]
            else:
                self.cleanup_temp_scan_files()
                messagebox.showerror(
                    "Administrator Access Required",
                    "Device Discovery w/MAC requires administrator access.\n\n"
                    "Install PolicyKit/pkexec or run the application with sudo.",
                )
                return
        else:
            command = nmap_command

        self.clear_results()

        self.append_raw_output(
            f"Target: {target}\n"
        )

        self.append_raw_output(
            f"Scan type: {scan_type}\n"
        )

        self.append_raw_output(
            f"Command: {' '.join(command)}\n"
        )

        if scan_type == "Device Discovery w/MAC" and os.geteuid() != 0:
            self.append_raw_output(
                "Administrator authorization will be requested through pkexec.\n"
            )

        self.append_raw_output(
            "-" * 75 + "\n"
        )

        self.scan_button.config(
            state=tk.DISABLED
        )

        self.stop_button.config(
            state=tk.NORMAL
        )

        self.scan_type_combo.config(
            state=tk.DISABLED
        )

        self.target_entry.config(
            state=tk.DISABLED
        )

        self.detect_button.config(
            state=tk.DISABLED
        )

        self.result_count_var.set(
            ""
        )

        if self.is_device_discovery(scan_type):
            self.notebook.select(
                self.devices_tab
            )
        else:
            self.notebook.select(
                self.ports_tab
            )

        self.start_activity_indicator(
            target
        )

        thread = threading.Thread(
            target=self.run_scan,
            args=(
                command,
                self.current_xml_path,
                scan_type,
            ),
            daemon=True,
        )
        thread.start()

    def start_activity_indicator(
        self,
        target: str,
    ) -> None:
        self.stop_activity_indicator()

        self.active_target = target
        self.scan_started_at = time.monotonic()
        self.activity_frame = 0
        self.latest_nmap_status = ""
        self.update_activity_indicator()

    def update_activity_indicator(self) -> None:
        if self.scan_started_at is None:
            return

        elapsed_seconds = int(
            time.monotonic() - self.scan_started_at
        )

        minutes, seconds = divmod(
            elapsed_seconds,
            60,
        )

        spinner = (
            "●○○",
            "○●○",
            "○○●",
            "○●○",
        )[self.activity_frame % 4]

        self.activity_frame += 1

        status = (
            f"{spinner} Scanning {self.active_target} "
            f"— {minutes:02d}:{seconds:02d}"
        )

        self.status_var.set(status)

        self.activity_job = self.root.after(
            500,
            self.update_activity_indicator,
        )

    def stop_activity_indicator(self) -> None:
        if self.activity_job is not None:
            try:
                self.root.after_cancel(
                    self.activity_job
                )
            except tk.TclError:
                pass

        self.activity_job = None
        self.scan_started_at = None
        self.active_target = ""
        self.latest_nmap_status = ""

    def run_scan(
        self,
        command: list[str],
        xml_path: str,
        scan_type: str,
    ) -> None:
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if self.process.stdout is not None:
                for line in iter(
                    self.process.stdout.readline,
                    "",
                ):
                    self.output_queue.put(
                        (
                            "raw_output",
                            line,
                        )
                    )

                    stripped_line = line.strip()

                    if (
                        stripped_line.startswith("Stats:")
                        or "Timing:" in stripped_line
                    ):
                        self.output_queue.put(
                            (
                                "scan_progress",
                                stripped_line,
                            )
                        )

            return_code = self.process.wait()

            results = self.parse_nmap_xml(
                xml_path
            )

            self.output_queue.put(
                (
                    "scan_complete",
                    {
                        "return_code": return_code,
                        "scan_type": scan_type,
                        "devices": results["devices"],
                        "ports": results["ports"],
                    },
                )
            )

        except FileNotFoundError:
            self.output_queue.put(
                (
                    "scan_error",
                    "Nmap could not be found.",
                )
            )

        except PermissionError:
            self.output_queue.put(
                (
                    "scan_error",
                    "Permission was denied while starting Nmap.",
                )
            )

        except Exception as error:
            self.output_queue.put(
                (
                    "scan_error",
                    f"Unexpected error: {error}",
                )
            )

        finally:
            self.process = None

            self.cleanup_temp_scan_files()

    def parse_nmap_xml(
        self,
        xml_path: str,
    ) -> dict[str, list[dict[str, str]]]:
        devices: list[dict[str, str]] = []
        ports: list[dict[str, str]] = []

        if not os.path.exists(xml_path):
            return {
                "devices": devices,
                "ports": ports,
            }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall("host"):
                status = self.get_host_status(host)
                ip_address = self.get_host_ip(host)

                if not ip_address:
                    continue

                hostname = self.get_hostname(host)
                mac_address, vendor = self.get_mac_and_vendor(host)
                latency = self.get_host_latency(host)

                devices.append(
                    {
                        "ip_address": ip_address,
                        "hostname": hostname,
                        "mac_address": mac_address,
                        "vendor": vendor,
                        "status": status,
                        "latency": latency,
                    }
                )

                ports_element = host.find("ports")

                if ports_element is None:
                    continue

                for port_element in ports_element.findall("port"):
                    port_number = port_element.get(
                        "portid",
                        "",
                    )

                    protocol = port_element.get(
                        "protocol",
                        "",
                    ).upper()

                    state_element = port_element.find("state")

                    port_state = "Unknown"

                    if state_element is not None:
                        port_state = state_element.get(
                            "state",
                            "unknown",
                        ).capitalize()

                    if port_state.lower() != "open":
                        continue

                    service_element = port_element.find("service")

                    service_name = "Unknown"
                    version = "Not detected"

                    if service_element is not None:
                        service_name = service_element.get(
                            "name",
                            "Unknown",
                        )

                        version_parts = []

                        product = service_element.get("product")
                        service_version = service_element.get("version")
                        extra_info = service_element.get("extrainfo")

                        if product:
                            version_parts.append(product)

                        if service_version:
                            version_parts.append(service_version)

                        if extra_info:
                            version_parts.append(
                                f"({extra_info})"
                            )

                        if version_parts:
                            version = " ".join(version_parts)

                    ports.append(
                        {
                            "ip_address": ip_address,
                            "hostname": hostname,
                            "port": port_number,
                            "protocol": protocol,
                            "state": port_state,
                            "service": service_name,
                            "version": version,
                        }
                    )

        except ET.ParseError as error:
            self.output_queue.put(
                (
                    "raw_output",
                    f"\nCould not parse Nmap XML: {error}\n",
                )
            )

        devices.sort(
            key=lambda device:
            self.ip_sort_key(
                device["ip_address"]
            )
        )

        ports.sort(
            key=lambda port: (
                self.ip_sort_key(
                    port["ip_address"]
                ),
                self.port_sort_key(
                    port["port"]
                ),
            )
        )

        return {
            "devices": devices,
            "ports": ports,
        }

    @staticmethod
    def get_host_status(
        host: ET.Element,
    ) -> str:
        status_element = host.find("status")

        if status_element is None:
            return "Unknown"

        return status_element.get(
            "state",
            "unknown",
        ).capitalize()

    @staticmethod
    def get_host_ip(
        host: ET.Element,
    ) -> str:
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                return address.get(
                    "addr",
                    "",
                )

        return ""

    @staticmethod
    def get_mac_and_vendor(
        host: ET.Element,
    ) -> tuple[str, str]:
        for address in host.findall("address"):
            if address.get("addrtype") == "mac":
                mac_address = address.get(
                    "addr",
                    "",
                ) or "Not available"

                vendor = address.get(
                    "vendor",
                    "",
                ) or "Unknown"

                return mac_address, vendor

        return "Not available", "Unknown"

    @staticmethod
    def get_hostname(
        host: ET.Element,
    ) -> str:
        hostname_element = host.find(
            "hostnames/hostname"
        )

        if hostname_element is None:
            return "Unknown"

        return hostname_element.get(
            "name",
            "",
        ) or "Unknown"

    @staticmethod
    def get_host_latency(
        host: ET.Element,
    ) -> str:
        times_element = host.find("times")

        if times_element is None:
            return "Not available"

        srtt_value = times_element.get("srtt")

        if not srtt_value:
            return "Not available"

        try:
            milliseconds = int(srtt_value) / 1000

            if milliseconds < 1:
                return f"{milliseconds:.3f} ms"

            if milliseconds < 10:
                return f"{milliseconds:.2f} ms"

            return f"{milliseconds:.1f} ms"

        except ValueError:
            return "Not available"

    def process_output_queue(self) -> None:
        try:
            while True:
                message_type, data = (
                    self.output_queue.get_nowait()
                )

                if message_type == "raw_output":
                    self.append_raw_output(
                        str(data)
                    )

                elif message_type == "scan_progress":
                    # Detailed Nmap progress remains in Raw Output only.
                    pass

                elif message_type == "network_detected":
                    self.network_detection_success(
                        data
                    )

                elif message_type == "network_detection_failed":
                    self.network_detection_failed(
                        str(data)
                    )

                elif message_type == "scan_complete":
                    self.scan_finished(
                        data
                    )

                elif message_type == "scan_error":
                    self.scan_failed(
                        str(data)
                    )

        except queue.Empty:
            pass

        self.root.after(
            100,
            self.process_output_queue,
        )

    @staticmethod
    def clean_nmap_progress(
        progress_line: str,
    ) -> str:
        text = progress_line.replace(
            "Stats:",
            "",
            1,
        ).strip()

        if len(text) > 85:
            return text[:82] + "..."

        return text

    def network_detection_success(
        self,
        network_data: dict[str, str],
    ) -> None:
        interface = network_data["interface"]
        address = network_data["address"]
        network = network_data["network"]

        self.target_var.set(network)

        self.interface_var.set(
            f"Interface: {interface}   "
            f"Host IP: {address}   "
            f"Network: {network}"
        )

        self.status_var.set(
            f"Detected {network}"
        )

        self.detect_button.config(
            state=tk.NORMAL
        )

    def network_detection_failed(
        self,
        error: str,
    ) -> None:
        self.interface_var.set(
            "Automatic network detection failed"
        )

        self.status_var.set(
            "Network detection failed"
        )

        self.detect_button.config(
            state=tk.NORMAL
        )

        messagebox.showwarning(
            "Network Detection Failed",
            "The local network could not be detected.\n\n"
            f"{error}\n\n"
            "Enter a network manually, such as:\n"
            "192.168.1.0/24",
        )

    def scan_finished(
        self,
        scan_data: dict[str, Any],
    ) -> None:
        self.stop_activity_indicator()

        return_code = scan_data["return_code"]
        scan_type = scan_data["scan_type"]
        devices = scan_data["devices"]
        ports = scan_data["ports"]

        self.last_completed_scan_type = scan_type
        self.update_device_columns(scan_type)
        self.populate_device_table(devices)
        self.populate_port_table(ports)
        self.restore_scan_controls()

        device_count = len(devices)
        port_count = len(ports)

        if return_code == 0:
            self.status_var.set(
                "Scan completed"
            )

            if self.is_device_discovery(scan_type):
                self.result_count_var.set(
                    f"{device_count} "
                    f"device{'s' if device_count != 1 else ''} found"
                )

                self.notebook.select(
                    self.devices_tab
                )

            else:
                self.result_count_var.set(
                    f"{device_count} "
                    f"device{'s' if device_count != 1 else ''}, "
                    f"{port_count} open "
                    f"port{'s' if port_count != 1 else ''}"
                )

                self.notebook.select(
                    self.ports_tab
                )

        elif return_code in (-15, -9):
            self.status_var.set(
                "Scan stopped"
            )

            self.result_count_var.set(
                f"{device_count} devices, "
                f"{port_count} open ports"
            )

        else:
            self.status_var.set(
                f"Nmap exited with code {return_code}"
            )

            self.result_count_var.set(
                f"{device_count} devices, "
                f"{port_count} open ports"
            )

    def scan_failed(
        self,
        error: str,
    ) -> None:
        self.stop_activity_indicator()

        self.append_raw_output(
            f"\n{error}\n"
        )

        self.restore_scan_controls()

        self.status_var.set(
            "Scan failed"
        )

        self.result_count_var.set(
            "0 results"
        )

        messagebox.showerror(
            "Scan Failed",
            error,
        )

    def restore_scan_controls(self) -> None:
        self.scan_button.config(
            state=tk.NORMAL
        )

        self.stop_button.config(
            state=tk.DISABLED
        )

        self.scan_type_combo.config(
            state="readonly"
        )

        self.target_entry.config(
            state=tk.NORMAL
        )

        self.detect_button.config(
            state=tk.NORMAL
        )

    def populate_device_table(
        self,
        devices: list[dict[str, str]],
    ) -> None:
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        for device in devices:
            self.device_tree.insert(
                "",
                tk.END,
                values=(
                    device["ip_address"],
                    device["hostname"],
                    device["mac_address"],
                    device["vendor"],
                    device["status"],
                    device["latency"],
                ),
            )

    def populate_port_table(
        self,
        ports: list[dict[str, str]],
    ) -> None:
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)

        for port in ports:
            self.port_tree.insert(
                "",
                tk.END,
                values=(
                    port["ip_address"],
                    port["hostname"],
                    port["port"],
                    port["protocol"],
                    port["state"],
                    port["service"],
                ),
            )

    def stop_scan(self) -> None:
        if self.process is None:
            return

        self.status_var.set(
            "Stopping scan..."
        )

        try:
            self.process.terminate()
        except ProcessLookupError:
            pass

    def on_device_double_click(
        self,
        event: tk.Event,
    ) -> None:
        item_id = self.device_tree.identify_row(
            event.y
        )

        if not item_id:
            return

        self.device_tree.selection_set(
            item_id
        )

        self.copy_selected_ip()

    def on_port_double_click(
        self,
        event: tk.Event,
    ) -> None:
        item_id = self.port_tree.identify_row(
            event.y
        )

        if not item_id:
            return

        self.port_tree.selection_set(
            item_id
        )

        self.copy_selected_ip()

    def copy_selected_ip(self) -> None:
        current_tab = self.notebook.select()

        if current_tab == str(self.ports_tab):
            tree = self.port_tree
        else:
            tree = self.device_tree

        selected_items = tree.selection()

        if not selected_items:
            self.status_var.set(
                "Select a result first"
            )
            return

        values = tree.item(
            selected_items[0],
            "values",
        )

        if not values:
            return

        ip_address = str(values[0])

        self.root.clipboard_clear()
        self.root.clipboard_append(
            ip_address
        )
        self.root.update_idletasks()

        self.status_var.set(
            f"Copied {ip_address}"
        )

    def sort_device_column(
        self,
        column: str,
        reverse: bool,
    ) -> None:
        rows = [
            (
                self.device_tree.set(
                    item_id,
                    column,
                ),
                item_id,
            )
            for item_id
            in self.device_tree.get_children("")
        ]

        if column == "ip_address":
            key_function = lambda row: self.ip_sort_key(row[0])
        elif column == "latency":
            key_function = lambda row: self.latency_sort_key(row[0])
        else:
            key_function = lambda row: row[0].lower()

        rows.sort(
            key=key_function,
            reverse=reverse,
        )

        for index, (_value, item_id) in enumerate(rows):
            self.device_tree.move(
                item_id,
                "",
                index,
            )

        self.device_tree.heading(
            column,
            command=lambda:
            self.sort_device_column(
                column,
                not reverse,
            ),
        )

    def sort_port_column(
        self,
        column: str,
        reverse: bool,
    ) -> None:
        rows = [
            (
                self.port_tree.set(
                    item_id,
                    column,
                ),
                item_id,
            )
            for item_id
            in self.port_tree.get_children("")
        ]

        if column == "ip_address":
            key_function = lambda row: self.ip_sort_key(row[0])
        elif column == "port":
            key_function = lambda row: self.port_sort_key(row[0])
        else:
            key_function = lambda row: row[0].lower()

        rows.sort(
            key=key_function,
            reverse=reverse,
        )

        for index, (_value, item_id) in enumerate(rows):
            self.port_tree.move(
                item_id,
                "",
                index,
            )

        self.port_tree.heading(
            column,
            command=lambda:
            self.sort_port_column(
                column,
                not reverse,
            ),
        )

    @staticmethod
    def ip_sort_key(
        value: str,
    ) -> tuple[int, ...]:
        try:
            return tuple(
                int(part)
                for part in value.split(".")
            )
        except ValueError:
            return (
                999,
                999,
                999,
                999,
            )

    @staticmethod
    def port_sort_key(
        value: str,
    ) -> int:
        try:
            return int(value)
        except ValueError:
            return 65536

    @staticmethod
    def latency_sort_key(
        value: str,
    ) -> float:
        try:
            return float(
                value.split()[0]
            )
        except (
            ValueError,
            IndexError,
        ):
            return float("inf")

    def append_raw_output(
        self,
        text: str,
    ) -> None:
        self.raw_output_text.insert(
            tk.END,
            text,
        )

        self.raw_output_text.see(
            tk.END
        )

    def clear_results(self) -> None:
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        for item in self.port_tree.get_children():
            self.port_tree.delete(item)

        self.raw_output_text.delete(
            "1.0",
            tk.END,
        )

        self.result_count_var.set(
            "0 results"
        )

    def save_results(self) -> None:
        current_tab = self.notebook.select()

        if current_tab == str(self.ports_tab):
            self.save_port_results()
        elif current_tab == str(self.raw_output_tab):
            self.save_raw_output()
        else:
            self.save_device_results()

    @staticmethod
    def generate_default_filename(extension: str) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %I-%M-%S %p")
        return f"Network Scan {timestamp}.{extension}"

    def save_device_results(self) -> None:
        all_rows = self.get_tree_rows(
            self.device_tree
        )

        if self.last_completed_scan_type == "Device Discovery w/MAC":
            headings = [
                "IP Address",
                "Hostname",
                "MAC Address",
                "Vendor",
                "Status",
                "Latency",
            ]
            rows = all_rows
        else:
            headings = [
                "IP Address",
                "Hostname",
                "Status",
                "Latency",
            ]
            rows = [
                (
                    row[0],
                    row[1],
                    row[4],
                    row[5],
                )
                for row in all_rows
            ]

        if not rows:
            messagebox.showinfo(
                "Nothing to Save",
                "There are no device results to save.",
            )
            return

        filename = filedialog.asksaveasfilename(
            title="Save Device Results",
            initialfile=self.generate_default_filename("csv"),
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )

        if filename:
            self.write_csv(
                filename,
                headings,
                rows,
            )

    def save_port_results(self) -> None:
        rows = self.get_tree_rows(
            self.port_tree
        )

        if not rows:
            messagebox.showinfo(
                "Nothing to Save",
                "There are no port results to save.",
            )
            return

        filename = filedialog.asksaveasfilename(
            title="Save Port Results",
            initialfile=self.generate_default_filename("csv"),
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )

        if filename:
            self.write_csv(
                filename,
                [
                    "IP Address",
                    "Hostname",
                    "Port",
                    "Protocol",
                    "State",
                    "Service",
                ],
                rows,
            )

    def save_raw_output(self) -> None:
        raw_output = self.raw_output_text.get(
            "1.0",
            tk.END,
        ).strip()

        if not raw_output:
            messagebox.showinfo(
                "Nothing to Save",
                "There is no raw output to save.",
            )
            return

        filename = filedialog.asksaveasfilename(
            title="Save Raw Output",
            initialfile=self.generate_default_filename("txt"),
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )

        if not filename:
            return

        try:
            with open(
                filename,
                "w",
                encoding="utf-8",
            ) as output_file:
                output_file.write(
                    raw_output + "\n"
                )

            self.status_var.set(
                f"Saved results to {filename}"
            )

        except OSError as error:
            messagebox.showerror(
                "Save Failed",
                f"Could not save the file:\n{error}",
            )

    @staticmethod
    def get_tree_rows(
        tree: ttk.Treeview,
    ) -> list[tuple[Any, ...]]:
        rows = []

        for item_id in tree.get_children():
            values = tree.item(
                item_id,
                "values",
            )

            if values:
                rows.append(
                    tuple(values)
                )

        return rows

    def write_csv(
        self,
        filename: str,
        headings: list[str],
        rows: list[tuple[Any, ...]],
    ) -> None:
        try:
            with open(
                filename,
                "w",
                encoding="utf-8",
                newline="",
            ) as output_file:
                writer = csv.writer(
                    output_file
                )

                writer.writerow(
                    headings
                )

                writer.writerows(
                    rows
                )

            self.status_var.set(
                f"Saved results to {filename}"
            )

        except OSError as error:
            messagebox.showerror(
                "Save Failed",
                f"Could not save the file:\n{error}",
            )

    def cleanup_temp_scan_files(self) -> None:
        if self.current_xml_path:
            try:
                if os.path.exists(self.current_xml_path):
                    os.remove(self.current_xml_path)
            except OSError:
                pass

        if self.current_temp_dir:
            try:
                os.rmdir(self.current_temp_dir)
            except OSError:
                pass

        self.current_xml_path = None
        self.current_temp_dir = None

    def close_application(self) -> None:
        if self.process is not None:
            should_close = messagebox.askyesno(
                "Scan Running",
                "A scan is currently running. Stop it and exit?",
            )

            if not should_close:
                return

            try:
                self.process.terminate()
            except ProcessLookupError:
                pass

        self.stop_activity_indicator()

        self.cleanup_temp_scan_files()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    NmapGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

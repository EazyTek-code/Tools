import os
import yara
import psutil
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from datetime import datetime
import webbrowser
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import binascii
import string
import logging
import subprocess
import sys

class YaraScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Yara Scanner (Windows)")
        self.root.geometry("600x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.yara_file_path = None
        self.rules = None
        self.scan_thread = None
        self.is_scanning = False
        self.results = []
        self.result_lock = threading.Lock()
        self.files_scanned = 0
        self.processes_scanned = 0
        self.max_threads = multiprocessing.cpu_count()
        self.selected_drive = "C:\\"
        self.selected_directory = None
        self.scan_scope = "suspend_immediate"
        self.total_files_est = 0
        self.current_path = ""

        self.excluded_processes = []
        self.excluded_paths = []

        self.log_file = "yara_scanner.log"
        logging.basicConfig(filename=self.log_file, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger()
        self.log_file_path = os.path.normcase(os.path.normpath(os.path.abspath(self.log_file)))

        self.target_exe_path = None
        self.delay_time = 5
        self.is_dll = False

        self.create_ui()

    def create_ui(self):
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.title_label = ctk.CTkLabel(
            self.main_frame, text="Yara Scanner", font=("Roboto", 24, "bold")
        )
        self.title_label.pack(pady=(10, 20))

        self.yara_frame = ctk.CTkFrame(self.main_frame, corner_radius=5)
        self.yara_frame.pack(fill="x", pady=5)
        self.yara_label = ctk.CTkLabel(
            self.yara_frame, text="No Yara rule file selected", font=("Roboto", 14)
        )
        self.yara_label.pack(pady=5)
        self.select_yara_button = ctk.CTkButton(
            self.yara_frame, text="Select Yara File", command=self.select_yara_file
        )
        self.select_yara_button.pack(pady=5)

        self.exclusions_frame = ctk.CTkFrame(self.main_frame, corner_radius=5)
        self.exclusions_frame.pack(fill="x", pady=5)
        
        self.exclusions_label = ctk.CTkLabel(
            self.exclusions_frame, text="Exclusions", font=("Roboto", 16, "bold")
        )
        self.exclusions_label.pack(pady=(10, 5))

        self.process_exclusions_label = ctk.CTkLabel(
            self.exclusions_frame, text="Exclude Processes (names or PIDs, comma-separated):", font=("Roboto", 14)
        )
        self.process_exclusions_label.pack(pady=(5, 2))
        self.process_exclusions_entry = ctk.CTkEntry(
            self.exclusions_frame, placeholder_text="e.g., notepad.exe,1234,chrome.exe"
        )
        self.process_exclusions_entry.pack(pady=2, fill="x", padx=10)

        self.file_exclusions_label = ctk.CTkLabel(
            self.exclusions_frame, text="Exclude Files/Directories:", font=("Roboto", 14)
        )
        self.file_exclusions_label.pack(pady=(10, 2))
        self.file_exclusions_entry = ctk.CTkEntry(
            self.exclusions_frame, placeholder_text="e.g., C:\\Temp,C:\\file.exe"
        )
        self.file_exclusions_entry.pack(pady=2, fill="x", padx=10)
        self.add_file_exclusion_button = ctk.CTkButton(
            self.exclusions_frame, text="Add File", command=self.add_file_exclusion
        )
        self.add_file_exclusion_button.pack(pady=2)
        self.add_dir_exclusion_button = ctk.CTkButton(
            self.exclusions_frame, text="Add Directory", command=self.add_dir_exclusion
        )
        self.add_dir_exclusion_button.pack(pady=2)

        self.scan_type_var = ctk.StringVar(value="File System")
        self.scan_type_segmented = ctk.CTkSegmentedButton(
            self.main_frame,
            values=["File System", "Live Memory", "Targeted Process", "Suspend Process"],
            variable=self.scan_type_var,
            command=self.update_scan_type
        )
        self.scan_type_segmented.pack(pady=20)

        self.options_frame = ctk.CTkFrame(self.main_frame, corner_radius=5)
        self.options_frame.pack(fill="both", expand=True, pady=10)

        self.fs_frame = ctk.CTkFrame(self.options_frame, corner_radius=5)
        self.scope_label = ctk.CTkLabel(
            self.fs_frame, text="Scan Scope:", font=("Roboto", 14)
        )
        self.scope_label.pack(pady=(10, 5))
        self.scope_var = ctk.StringVar(value="drive")
        self.scope_drive_radio = ctk.CTkRadioButton(
            self.fs_frame, text="Entire Drive", variable=self.scope_var, value="drive",
            command=self.update_scope
        )
        self.scope_drive_radio.pack(pady=2)
        self.scope_dir_radio = ctk.CTkRadioButton(
            self.fs_frame, text="Specific Directory", variable=self.scope_var, value="directory",
            command=self.update_scope
        )
        self.scope_dir_radio.pack(pady=2)

        self.drive_label = ctk.CTkLabel(
            self.fs_frame, text="Select Drive:", font=("Roboto", 14)
        )
        self.drive_label.pack(pady=(10, 5))
        self.drives = self.get_available_drives()
        self.drive_menu = ctk.CTkOptionMenu(
            self.fs_frame, values=self.drives, command=self.update_selected_drive
        )
        self.drive_menu.set("C:\\")
        self.drive_menu.pack(pady=5)

        self.dir_label = ctk.CTkLabel(
            self.fs_frame, text="No directory selected", font=("Roboto", 14)
        )
        self.dir_label.pack(pady=5)
        self.select_dir_button = ctk.CTkButton(
            self.fs_frame, text="Select Directory", command=self.select_directory
        )
        self.select_dir_button.pack(pady=5)
        self.select_dir_button.configure(state="disabled")

        self.lm_frame = ctk.CTkFrame(self.options_frame, corner_radius=5)
        self.lm_label = ctk.CTkLabel(
            self.lm_frame, text="Live Memory Scan: Scans all running processes.",
            font=("Roboto", 14)
        )
        self.lm_label.pack(pady=20)

        self.tp_frame = ctk.CTkFrame(self.options_frame, corner_radius=5)
        self.target_exe_label = ctk.CTkLabel(
            self.tp_frame, text="No target executable selected", font=("Roboto", 14)
        )
        self.target_exe_label.pack(pady=5)
        self.select_target_exe_button = ctk.CTkButton(
            self.tp_frame, text="Select Target (EXE/DLL)", command=self.select_target_exe
        )
        self.select_target_exe_button.pack(pady=5)

        self.delay_label = ctk.CTkLabel(
            self.tp_frame, text="Delay before suspend (seconds):", font=("Roboto", 14)
        )
        self.delay_label.pack(pady=(10, 5))
        self.delay_entry = ctk.CTkEntry(self.tp_frame, placeholder_text="5")
        self.delay_entry.insert(0, "5")
        self.delay_entry.pack(pady=5)

        self.sp_frame = ctk.CTkFrame(self.options_frame, corner_radius=5)
        self.sp_target_exe_label = ctk.CTkLabel(
            self.sp_frame, text="No target executable selected", font=("Roboto", 14)
        )
        self.sp_target_exe_label.pack(pady=5)
        self.sp_select_target_exe_button = ctk.CTkButton(
            self.sp_frame, text="Select Target (EXE/DLL)", command=self.select_target_exe_sp
        )
        self.sp_select_target_exe_button.pack(pady=5)

        self.sp_scope_label = ctk.CTkLabel(
            self.sp_frame, text="Suspend Timing:", font=("Roboto", 14)
        )
        self.sp_scope_label.pack(pady=(10, 5))
        self.sp_scope_var = ctk.StringVar(value="suspend_immediate")
        self.sp_immediate_radio = ctk.CTkRadioButton(
            self.sp_frame, text="Suspend Immediately", variable=self.sp_scope_var, value="suspend_immediate",
            command=self.update_sp_scope
        )
        self.sp_immediate_radio.pack(pady=2)
        self.sp_delayed_radio = ctk.CTkRadioButton(
            self.sp_frame, text="Suspend After Delay", variable=self.sp_scope_var, value="suspend_delayed",
            command=self.update_sp_scope
        )
        self.sp_delayed_radio.pack(pady=2)

        self.sp_delay_label = ctk.CTkLabel(
            self.sp_frame, text="Delay before suspend (seconds):", font=("Roboto", 14)
        )
        self.sp_delay_label.pack(pady=(10, 5))
        self.sp_delay_entry = ctk.CTkEntry(self.sp_frame, placeholder_text="5")
        self.sp_delay_entry.insert(0, "5")
        self.sp_delay_entry.pack(pady=5)
        self.sp_delay_entry.configure(state="disabled")

        self.scan_button = ctk.CTkButton(
            self.main_frame, text="Start Scan", command=self.start_scan,
            fg_color="#1f538d", font=("Roboto", 16), height=40
        )
        self.scan_button.pack(pady=20, fill="x")

        self.progress = ctk.CTkProgressBar(self.main_frame, mode="determinate")
        self.progress.set(0)
        self.progress.pack(pady=10)
        self.progress.pack_forget()

        self.current_path_label = ctk.CTkLabel(
            self.main_frame, text="", font=("Roboto", 12), wraplength=550
        )
        self.current_path_label.pack(pady=5)
        self.current_path_label.pack_forget()

        self.status_label = ctk.CTkLabel(
            self.main_frame, text="Ready", font=("Roboto", 12)
        )
        self.status_label.pack(pady=5)

        self.update_scan_type("File System")

    def add_file_exclusion(self):
        file_path = filedialog.askopenfilename(
            title="Select File to Exclude",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            current = self.file_exclusions_entry.get()
            new_value = f"{current},{file_path}" if current else file_path
            self.file_exclusions_entry.delete(0, tk.END)
            self.file_exclusions_entry.insert(0, new_value)
            self.logger.info(f"Added file exclusion: {file_path}")

    def add_dir_exclusion(self):
        dir_path = filedialog.askdirectory(
            title="Select Directory to Exclude",
            mustexist=True
        )
        if dir_path:
            current = self.file_exclusions_entry.get()
            new_value = f"{current},{dir_path}" if current else dir_path
            self.file_exclusions_entry.delete(0, tk.END)
            self.file_exclusions_entry.insert(0, new_value)
            self.logger.info(f"Added directory exclusion: {dir_path}")

    def parse_exclusions(self):
        self.excluded_processes = []
        process_input = self.process_exclusions_entry.get().strip()
        if process_input:
            items = [item.strip() for item in process_input.split(",")]
            for item in items:
                if not item:
                    continue
                try:
                    pid = int(item)
                    self.excluded_processes.append(pid)
                except ValueError:
                    self.excluded_processes.append(item.lower())
                self.logger.info(f"Excluding process: {item}")

        self.excluded_paths = []
        file_input = self.file_exclusions_entry.get().strip()
        if file_input:
            paths = [path.strip() for path in file_input.split(",")]
            for path in paths:
                if not path:
                    continue
                norm_path = os.path.normcase(os.path.normpath(path))
                self.excluded_paths.append(norm_path)
                self.logger.info(f"Excluding path: {path}")

    def get_available_drives(self):
        drives = []
        for partition in psutil.disk_partitions():
            if partition.fstype and partition.mountpoint.startswith(tuple('ABCDEFGHIJKLMNOPQRSTUVWXYZ')):
                drives.append(partition.mountpoint)
        self.logger.info(f"Found available drives: {drives}")
        return drives if drives else ["C:\\"]

    def update_selected_drive(self, drive):
        self.selected_drive = drive

    def update_scope(self):
        self.scan_scope = self.scope_var.get()
        if self.scan_scope == "drive":
            self.drive_menu.configure(state="normal")
            self.select_dir_button.configure(state="disabled")
            self.dir_label.configure(text="No directory selected")
            self.selected_directory = None
        else:
            self.drive_menu.configure(state="disabled")
            self.select_dir_button.configure(state="normal")

    def update_sp_scope(self):
        self.scan_scope = self.sp_scope_var.get()
        if self.scan_scope == "suspend_immediate":
            self.sp_delay_entry.configure(state="disabled")
        else:
            self.sp_delay_entry.configure(state="normal")

    def update_scan_type(self, scan_type):
        for widget in self.options_frame.winfo_children():
            widget.pack_forget()
        if scan_type == "File System":
            self.fs_frame.pack(fill="both", expand=True, padx=10, pady=10)
            self.update_scope()
        elif scan_type == "Live Memory":
            self.lm_frame.pack(fill="both", expand=True, padx=10, pady=10)
        elif scan_type == "Targeted Process":
            self.tp_frame.pack(fill="both", expand=True, padx=10, pady=10)
        else:
            self.sp_frame.pack(fill="both", expand=True, padx=10, pady=10)
            self.update_sp_scope()

    def select_yara_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Yara Rules", "*.yar *.yara")]
        )
        if file_path:
            try:
                self.rules = yara.compile(filepath=file_path)
                self.yara_file_path = os.path.normcase(os.path.normpath(file_path))
                self.yara_label.configure(text=f"Selected: {os.path.basename(file_path)}")
                self.status_label.configure(text="Yara rules compiled successfully")
                self.logger.info(f"Yara rules compiled from {file_path}")
                # Log the compiled rules for debugging
                rule_names = [rule.identifier for rule in self.rules]
                self.logger.info(f"Compiled rules: {rule_names}")
            except yara.Error as e:
                messagebox.showerror("Error", f"Failed to compile Yara rules: {e}")
                self.yara_label.configure(text="No Yara rule file selected")
                self.rules = None
                self.yara_file_path = None
                self.logger.error(f"Failed to compile Yara rules: {e}")

    def select_directory(self):
        directory = filedialog.askdirectory(mustexist=True)
        if directory:
            self.selected_directory = directory
            self.dir_label.configure(text=f"Selected: {directory}")
            self.logger.info(f"Selected directory: {directory}")

    def select_target_exe(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Executables and DLLs", "*.exe *.dll")]
        )
        if file_path:
            self.target_exe_path = file_path
            self.is_dll = file_path.lower().endswith('.dll')
            label_text = f"Selected: {os.path.basename(file_path)}"
            if self.is_dll:
                label_text += " (will be run with rundll32.exe)"
            self.target_exe_label.configure(text=label_text)
            self.logger.info(f"Selected target: {file_path} (DLL: {self.is_dll})")

    def select_target_exe_sp(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Executables and DLLs", "*.exe *.dll")]
        )
        if file_path:
            self.target_exe_path = file_path
            self.is_dll = file_path.lower().endswith('.dll')
            label_text = f"Selected: {os.path.basename(file_path)}"
            if self.is_dll:
                label_text += " (will be run with rundll32.exe)"
            self.sp_target_exe_label.configure(text=label_text)
            self.logger.info(f"Selected target for suspend process: {file_path} (DLL: {self.is_dll})")

    def start_scan(self):
        if self.scan_type_var.get() in ["File System", "Live Memory", "Targeted Process"]:
            if not self.yara_file_path or not self.rules:
                messagebox.showwarning("Warning", "Please select a valid Yara rule file")
                return
        if self.is_scanning:
            messagebox.showwarning("Warning", "A scan is already in progress")
            return
        if self.scan_type_var.get() == "File System" and self.scan_scope == "directory" and not self.selected_directory:
            messagebox.showwarning("Warning", "Please select a directory to scan")
            return
        if self.scan_type_var.get() in ["Targeted Process", "Suspend Process"] and not self.target_exe_path:
            messagebox.showwarning("Warning", "Please select a target executable")
            return
        if self.scan_type_var.get() == "Targeted Process":
            try:
                self.delay_time = int(self.delay_entry.get())
                if self.delay_time <= 0:
                    messagebox.showwarning("Warning", "Delay time must be a positive integer")
                    return
            except ValueError:
                messagebox.showwarning("Warning", "Delay time must be a valid integer")
                return
        if self.scan_type_var.get() == "Suspend Process":
            if self.scan_scope == "suspend_delayed":
                try:
                    self.delay_time = int(self.sp_delay_entry.get())
                    if self.delay_time <= 0:
                        messagebox.showwarning("Warning", "Delay time must be a positive integer")
                        return
                except ValueError:
                    messagebox.showwarning("Warning", "Delay time must be a valid integer")
                    return

        self.parse_exclusions()

        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.progress.pack()
        self.current_path_label.pack()
        self.status_label.configure(text="Processing...")
        self.results = []
        self.files_scanned = 0
        self.processes_scanned = 0
        self.total_files_est = 0
        self.current_path = ""
        self.logger.info(f"Starting {self.scan_type_var.get()} operation")

        scan_type = self.scan_type_var.get()
        self.scan_thread = threading.Thread(
            target=self.run_scan, args=(scan_type,)
        )
        self.scan_thread.start()
        self.root.after(100, self.check_scan_thread)

    def estimate_total_files(self, root_dir):
        total = 0
        try:
            for root, _, files in os.walk(root_dir, onerror=lambda err: self.logger.warning(f"Walk error: {err}")):
                norm_root = os.path.normcase(os.path.normpath(root))
                skip_dir = False
                for excluded_path in self.excluded_paths:
                    if norm_root == excluded_path or norm_root.startswith(excluded_path + os.sep):
                        skip_dir = True
                        break
                if skip_dir:
                    continue
                total += len(files)
            self.logger.info(f"Estimated {total} files in {root_dir}")
        except Exception as e:
            self.logger.error(f"Error estimating files: {e}")
        return max(total, 1)

    def format_matched_string(self, identifier, instances):
        if not instances:
            self.logger.debug(f"No instances for {identifier}")
            return None

        formatted_strings = []
        for instance in instances:
            try:
                data = instance.matched_data
                self.logger.debug(f"Matched data for {identifier}: {data}")
                try:
                    decoded = data.decode('utf-8')
                    formatted_strings.append(decoded)
                    self.logger.debug(f"Decoded {identifier} as: {decoded}")
                except UnicodeDecodeError:
                    hex_str = binascii.hexlify(data).decode('ascii')
                    formatted_strings.append(f"0x{hex_str[:32]}{'...' if len(hex_str) > 32 else ''}")
                    self.logger.debug(f"Hex for {identifier}: {hex_str}")
            except Exception as e:
                self.logger.warning(f"Error formatting string {identifier}: {e}")
                formatted_strings.append("<error processing data>")

        result = f"{identifier}: {formatted_strings[0] if len(formatted_strings) == 1 else '[' + ', '.join(formatted_strings) + ']'}"
        self.logger.debug(f"Formatted {identifier} as: {result}")
        return result

    def run_scan(self, scan_type):
        start_time = time.time()

        if scan_type == "File System":
            self.scan_file_system()
        elif scan_type == "Live Memory":
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self.scan_memory()
        elif scan_type == "Targeted Process":
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self.scan_targeted_process()
        else:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self.suspend_process()

        elapsed_time = time.time() - start_time
        if scan_type in ["File System", "Live Memory", "Targeted Process"]:
            self.logger.info(f"Scan completed in {elapsed_time:.2f} seconds with {len(self.results)} matches")
            self.generate_report(self.results, scan_type, elapsed_time)
        else:
            self.logger.info(f"Suspend process operation completed in {elapsed_time:.2f} seconds")
            self.root.after(
                0,
                lambda: self.finalize_scan("Process suspended successfully.")
            )

    def scan_file_system(self):
        root_dir = self.selected_directory if self.scan_scope == "directory" else self.selected_drive
        self.status_label.configure(text=f"Scanning file system on {root_dir}...")
        self.total_files_est = self.estimate_total_files(root_dir)
        self.progress.configure(mode="determinate")
        self.progress.set(0)
        
        top_dirs = []
        try:
            for item in os.listdir(root_dir):
                item_path = os.path.join(root_dir, item)
                if os.path.isdir(item_path):
                    top_dirs.append(item_path)
            self.logger.info(f"Found {len(top_dirs)} top-level directories in {root_dir}")

            def scan_directory(directory):
                local_count = 0
                try:
                    for root, _, files in os.walk(directory, onerror=lambda err: self.logger.warning(f"Walk error: {err}")):
                        norm_root = os.path.normcase(os.path.normpath(root))
                        skip_dir = False
                        for excluded_path in self.excluded_paths:
                            if norm_root == excluded_path or norm_root.startswith(excluded_path + os.sep):
                                self.logger.info(f"Skipping directory {root} due to exclusion")
                                skip_dir = True
                                break
                        if skip_dir:
                            continue

                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            norm_file_path = os.path.normcase(os.path.normpath(file_path))
                            if norm_file_path == self.yara_file_path:
                                self.logger.info(f"Skipping Yara rule file: {file_path}")
                                continue
                            if norm_file_path == self.log_file_path:
                                self.logger.info(f"Skipping logfile: {file_path}")
                                continue
                            if file_name.startswith("yara_scan_report_") and file_name.endswith(".html"):
                                self.logger.info(f"Skipping report file: {file_path}")
                                continue
                            if norm_file_path in self.excluded_paths:
                                self.logger.info(f"Skipping file {file_path} due to exclusion")
                                continue

                            self.root.after(
                                0,
                                lambda p=file_path: self.current_path_label.configure(text=f"Scanning: {p}")
                            )
                            try:
                                self.logger.info(f"Scanning file: {file_path}")
                                matches = self.rules.match(file_path)
                                self.logger.debug(f"Matches for {file_path}: {matches}")
                                if matches:
                                    self.logger.info(f"Match found in {file_path}: {len(matches)} rules matched")
                                    for m in matches:
                                        matched_strings = []
                                        for s in m.strings:
                                            formatted = self.format_matched_string(s.identifier, s.instances)
                                            if formatted:
                                                matched_strings.append(formatted)
                                            else:
                                                matched_strings.append(s.identifier)
                                        if matched_strings:
                                            with self.result_lock:
                                                self.results.append({
                                                    "path": file_path,
                                                    "matches": [
                                                        {
                                                            "rule": m.rule,
                                                            "strings": matched_strings
                                                        }
                                                    ]
                                                })
                                                self.logger.info(f"Added match to results: {file_path} with strings: {matched_strings}")
                                else:
                                    self.logger.debug(f"No match in {file_path}")
                                local_count += 1
                                with self.result_lock:
                                    self.files_scanned += 1
                                    self.root.after(
                                        0,
                                        lambda: self.progress.set(min(self.files_scanned / self.total_files_est, 1.0))
                                    )
                            except (OSError, yara.Error) as e:
                                self.logger.warning(f"Error scanning {file_path}: {e}")
                                continue
                    self.logger.info(f"Scanned {local_count} files in {directory}")
                except Exception as e:
                    self.logger.error(f"Error in directory {directory}: {e}")
                return local_count

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                executor.map(scan_directory, top_dirs)

            self.root.after(
                0,
                lambda: self.status_label.configure(
                    text=f"Scanned {self.files_scanned} files"
                )
            )

        except Exception as e:
            self.logger.error(f"File system scan failed: {e}")
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", f"File system scan failed: {e}")
            )

    def scan_memory(self):
        self.status_label.configure(text="Scanning live memory...")
        total_processes = len(list(psutil.process_iter()))
        self.processes_scanned = 0
        current_pid = os.getpid()
        self.logger.info(f"Current process PID (yara_scanner.exe): {current_pid}")

        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            proc_name = proc.info['name']
            if pid == current_pid:
                self.logger.info(f"Skipping current process: {proc_name} (PID: {pid})")
                total_processes -= 1
                continue

            if proc_name.lower() in self.excluded_processes or pid in self.excluded_processes:
                self.logger.info(f"Skipping process {proc_name} (PID: {pid}) due to exclusion")
                total_processes -= 1
                continue

            self.processes_scanned += 1
            try:
                self.root.after(
                    0,
                    lambda p=proc_name: self.current_path_label.configure(text=f"Scanning process: {p} (PID: {pid})")
                )
                self.logger.debug(f"Scanning process: {proc_name} (PID: {pid})")
                matches = self.rules.match(pid=pid)
                if matches:
                    self.logger.info(f"Match found in process {proc_name} (PID: {pid}): {len(matches)} rules matched")
                    for m in matches:
                        matched_strings = []
                        for s in m.strings:
                            formatted = self.format_matched_string(s.identifier, s.instances)
                            if formatted:
                                matched_strings.append(formatted)
                            else:
                                matched_strings.append(s.identifier)
                        if matched_strings:
                            with self.result_lock:
                                self.results.append({
                                    "process": f"{proc_name} (PID: {pid})",
                                    "matches": [
                                        {
                                            "rule": m.rule,
                                            "strings": matched_strings
                                        }
                                    ]
                                })
                                self.logger.debug(f"Added match to results: {proc_name} (PID: {pid}) with strings: {matched_strings}")
                else:
                    self.logger.debug(f"No match in process {proc_name} (PID: {pid})")
                self.root.after(
                    0,
                    lambda: self.progress.set(self.processes_scanned / total_processes)
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, yara.Error) as e:
                self.logger.warning(f"Error scanning process {proc_name} (PID: {pid}): {e}")
                continue

        self.root.after(
            0,
            lambda: self.status_label.configure(text=f"Scanned {self.processes_scanned} processes")
        )

    def scan_targeted_process(self):
        target_name = os.path.basename(self.target_exe_path)
        proc_name_to_check = "rundll32.exe" if self.is_dll else target_name.lower()
        if proc_name_to_check in self.excluded_processes:
            self.logger.info(f"Target process {proc_name_to_check} is excluded")
            self.root.after(
                0,
                lambda: messagebox.showwarning("Warning", f"Target process {proc_name_to_check} is in the exclusion list")
            )
            self.root.after(
                0,
                lambda: self.finalize_scan("Scan aborted due to exclusion.")
            )
            return

        if self.is_dll:
            self.status_label.configure(text=f"Launching DLL {target_name} with rundll32.exe...")
            self.logger.info(f"Launching DLL: {self.target_exe_path} with rundll32.exe")
        else:
            self.status_label.configure(text=f"Launching target: {target_name}...")
            self.logger.info(f"Launching target executable: {self.target_exe_path}")

        try:
            if self.is_dll:
                dll_command = f'rundll32.exe "{self.target_exe_path}",DllMain'
                process = psutil.Popen(dll_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                proc_name = "rundll32.exe"
            else:
                process = psutil.Popen(self.target_exe_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc_name = target_name
            pid = process.pid
            self.logger.info(f"Target process started: {proc_name} (PID: {pid})")

            self.root.after(
                0,
                lambda: self.current_path_label.configure(text=f"Running: {proc_name} (PID: {pid})")
            )

            start_time = time.time()
            child_pids = set()
            while time.time() - start_time < self.delay_time:
                try:
                    children = process.children(recursive=True)
                    for child in children:
                        child_pid = child.pid
                        if child_pid not in child_pids:
                            child_pids.add(child_pid)
                            self.logger.info(f"Detected child process: {child.name()} (PID: {child_pid})")
                            self.root.after(
                                0,
                                lambda c=child: self.current_path_label.configure(
                                    text=f"Detected child: {c.name()} (PID: {c.pid})"
                                )
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Error tracking child processes: {e}")
                time.sleep(0.5)

            all_processes = [(process, proc_name, pid)]
            for child_pid in child_pids:
                try:
                    child = psutil.Process(child_pid)
                    if child.name().lower() in self.excluded_processes or child_pid in self.excluded_processes:
                        self.logger.info(f"Skipping child process {child.name()} (PID: {child_pid}) due to exclusion")
                        continue
                    all_processes.append((child, child.name(), child_pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Error accessing child process {child_pid}: {e}")
                    continue

            for proc, proc_name, proc_pid in all_processes:
                try:
                    self.status_label.configure(text=f"Suspending process: {proc_name} (PID: {proc_pid})...")
                    proc.suspend()
                    self.logger.info(f"Process suspended: {proc_name} (PID: {proc_pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Error suspending process {proc_name} (PID: {proc_pid}): {e}")
                    continue

            self.processes_scanned = 0
            for proc, proc_name, proc_pid in all_processes:
                try:
                    self.status_label.configure(text=f"Scanning process: {proc_name} (PID: {proc_pid})...")
                    matches = self.rules.match(pid=proc_pid)
                    if matches:
                        self.logger.info(f"Match found in process {proc_name} (PID: {proc_pid}): {len(matches)} rules matched")
                        for m in matches:
                            matched_strings = []
                            for s in m.strings:
                                formatted = self.format_matched_string(s.identifier, s.instances)
                                if formatted:
                                    matched_strings.append(formatted)
                                else:
                                    matched_strings.append(s.identifier)
                            if matched_strings:
                                with self.result_lock:
                                    self.results.append({
                                        "process": f"{proc_name} (PID: {proc_pid})",
                                        "matches": [
                                            {
                                                "rule": m.rule,
                                                "strings": matched_strings
                                            }
                                        ]
                                    })
                                    self.logger.debug(f"Added match to results: {proc_name} (PID: {proc_pid}) with strings: {matched_strings}")
                    else:
                        self.logger.debug(f"No match in process {proc_name} (PID: {proc_pid})")
                    self.processes_scanned += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, yara.Error) as e:
                    self.logger.warning(f"Error scanning process {proc_name} (PID: {proc_pid}): {e}")
                    continue

            self.status_label.configure(text=f"Processes remain suspended: {proc_name} (PID: {pid}) and {len(child_pids)} children")
            self.logger.info(f"Processes remain suspended: {proc_name} (PID: {pid}) and {len(child_pids)} children")

            self.root.after(
                0,
                lambda: self.status_label.configure(text=f"Scanned {self.processes_scanned} processes (remain suspended)")
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied, yara.Error, OSError) as e:
            self.logger.error(f"Error in targeted process scan: {e}")
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", f"Targeted process scan failed: {e}")
            )

    def suspend_process(self):
        target_name = os.path.basename(self.target_exe_path)
        proc_name_to_check = "rundll32.exe" if self.is_dll else target_name.lower()
        if proc_name_to_check in self.excluded_processes:
            self.logger.info(f"Target process {proc_name_to_check} is excluded")
            self.root.after(
                0,
                lambda: messagebox.showwarning("Warning", f"Target process {proc_name_to_check} is in the exclusion list")
            )
            self.root.after(
                0,
                lambda: self.finalize_scan("Operation aborted due to exclusion.")
            )
            return

        if self.is_dll:
            self.status_label.configure(text=f"Launching DLL {target_name} with rundll32.exe...")
            self.logger.info(f"Launching DLL: {self.target_exe_path} with rundll32.exe")
        else:
            self.status_label.configure(text=f"Launching target: {target_name}...")
            self.logger.info(f"Launching target executable: {self.target_exe_path}")

        try:
            if self.is_dll:
                dll_command = f'rundll32.exe "{self.target_exe_path}",DllMain'
                process = psutil.Popen(dll_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                proc_name = "rundll32.exe"
            else:
                process = psutil.Popen(self.target_exe_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc_name = target_name
            pid = process.pid
            self.logger.info(f"Target process started: {proc_name} (PID: {pid})")

            self.root.after(
                0,
                lambda: self.current_path_label.configure(text=f"Running: {proc_name} (PID: {pid})")
            )

            start_time = time.time()
            child_pids = set()
            if self.scan_scope == "suspend_delayed":
                while time.time() - start_time < self.delay_time:
                    try:
                        if not process.is_running():
                            self.logger.warning(f"Main process {proc_name} (PID: {pid}) terminated early")
                            break
                        children = process.children(recursive=True)
                        for child in children:
                            child_pid = child.pid
                            if child_pid not in child_pids:
                                child_pids.add(child_pid)
                                self.logger.info(f"Detected child process: {child.name()} (PID: {child_pid})")
                                self.root.after(
                                    0,
                                    lambda c=child: self.current_path_label.configure(
                                        text=f"Detected child: {c.name()} (PID: {c.pid})"
                                    )
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        self.logger.warning(f"Error tracking child processes: {e}")
                    time.sleep(0.5)

            all_processes = []
            try:
                if process.is_running():
                    all_processes.append((process, proc_name, pid))
                else:
                    self.logger.warning(f"Main process {proc_name} (PID: {pid}) is no longer running")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.warning(f"Error accessing main process {proc_name} (PID: {pid}): {e}")

            for child_pid in child_pids:
                try:
                    child = psutil.Process(child_pid)
                    if child.name().lower() in self.excluded_processes or child_pid in self.excluded_processes:
                        self.logger.info(f"Skipping child process {child.name()} (PID: {child_pid}) due to exclusion")
                        continue
                    if child.is_running():
                        all_processes.append((child, child.name(), child_pid))
                    else:
                        self.logger.warning(f"Child process PID {child_pid} is no longer running")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Error accessing child process {child_pid}: {e}")
                    continue

            if not all_processes:
                self.logger.error("No processes available to suspend")
                self.root.after(
                    0,
                    lambda: messagebox.showwarning("Warning", "No processes available to suspend")
                )
                return

            self.processes_scanned = 0
            for proc, proc_name, proc_pid in all_processes:
                try:
                    self.status_label.configure(text=f"Suspending process: {proc_name} (PID: {proc_pid})...")
                    proc.suspend()
                    self.logger.info(f"Process suspended: {proc_name} (PID: {proc_pid})")
                    self.processes_scanned += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Error suspending process {proc_name} (PID: {proc_pid}): {e}")
                    continue

            self.root.after(
                0,
                lambda: self.status_label.configure(
                    text=f"Suspended {self.processes_scanned} processes: {proc_name} (PID: {pid}) and {len(child_pids)} children"
                )
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            self.logger.error(f"Error in suspend process operation: {e}")
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", f"Suspend process operation failed: {e}")
            )

    def generate_report(self, results, scan_type, elapsed_time):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"yara_scan_report_{timestamp}.html"
        self.logger.debug(f"Generating report with results: {results}")

        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        css_path = os.path.join(base_path, "tailwind.css")
        self.logger.debug(f"Attempting to load CSS from: {css_path}")

        try:
            with open(css_path, "r", encoding="utf-8") as css_file:
                tailwind_css = css_file.read()
            self.logger.debug("Successfully loaded Tailwind CSS")
        except Exception as e:
            self.logger.error(f"Failed to load Tailwind CSS: {e}")
            tailwind_css = """
            body { background-color: #1f2937; color: #f3f4f6; font-family: sans-serif; }
            div { margin: 0 auto; max-width: 1200px; padding: 1.5rem; }
            h1 { font-size: 1.875rem; font-weight: 700; margin-bottom: 1rem; color: #60a5fa; }
            p { margin-bottom: 0.5rem; }
            h2 { font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem; }
            .no-matches { color: #4ade80; }
            .result { background-color: #374151; padding: 1rem; margin-bottom: 1rem; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1); }
            .result p { font-weight: 700; }
            ul { list-style: disc; padding-left: 1.25rem; }
            ul ul { list-style: circle; padding-left: 1.25rem; }
            """
            self.logger.warning("Using fallback CSS styles")

        report_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Yara Scan Report</title>
    <style>
        {tailwind_css}
    </style>
</head>
<body class="bg-gray-900 text-gray-100 font-sans">
    <div class="container mx-auto p-6">
        <h1 class="text-3xl font-bold mb-4 text-blue-400">Yara Scan Report</h1>
        <p class="mb-2"><strong>Scan Type:</strong> {scan_type}</p>
        <p class="mb-2"><strong>Yara Rules:</strong> {os.path.basename(self.yara_file_path)}</p>
        <p class="mb-2"><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p class="mb-2"><strong>Elapsed Time:</strong> {elapsed_time:.2f} seconds</p>
        <p class="mb-6"><strong>Items Scanned:</strong> {self.files_scanned if scan_type == "File System" else self.processes_scanned}</p>
        <h2 class="text-2xl font-semibold mb-4">Results</h2>
        {'<p class="text-green-400">No matches found.</p>' if not results else ''}
        {''.join([
            f'<div class="bg-gray-800 p-4 mb-4 rounded-lg shadow">'
            f'<p class="font-bold">{"File" if scan_type == "File System" else "Process"}: {res["path" if scan_type == "File System" else "process"]}</p>'
            f'<p><strong>Matched Rules:</strong></p>'
            f'<ul class="list-disc pl-5">'
            f'{''.join([
                f'<li>{match["rule"]}: <ul class="list-circle pl-5">'
                f'{''.join([f"<li>{s}</li>" for s in match["strings"]])}'
                f'</ul></li>'
                for match in res["matches"]
            ])}'
            f'</ul>'
            f'</div>'
            for res in results
        ])}
    </div>
</body>
</html>"""

        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        self.logger.info(f"Generated report: {report_file} with {len(results)} matches")
        self.root.after(
            0,
            lambda: self.finalize_scan(report_file)
        )

    def finalize_scan(self, message):
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.progress.stop()
        self.progress.pack_forget()
        self.current_path_label.pack_forget()
        self.status_label.configure(text=f"Operation complete. {message}")
        if self.scan_type_var.get() != "Suspend Process" and message.endswith(".html"):
            if messagebox.askyesno("Report Generated", "Open report in browser?"):
                webbrowser.open(f"file://{os.path.abspath(message)}")

    def check_scan_thread(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(100, self.check_scan_thread)
        else:
            self.scan_thread = None

if __name__ == "__main__":
    root = ctk.CTk()
    app = YaraScannerApp(root)
    root.mainloop()